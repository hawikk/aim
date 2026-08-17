"""Bounded repo-graph context for the AI reviewer (Greptile parity).

the bundle is the PR's added hunks plus a ±N line window — enough for
many defects, useless for the ones where safety lives in a *caller* three
files away. Greptile's differentiator is whole-repo awareness; we take the
narrow slice of that that is still data-minimizing: for each symbol the PR
touched, include **caller and callee signatures only** (no bodies), within a
strict byte budget, still inside the same hard total cap as the rest of the
bundle.

No tree-sitter, no language server, no durable index. A pure-Python AST walk
over the checkout at review time is enough for the languages that dominate
our dogfood (Python), and the same module is the extension point for more
later. Every skip is recorded so a missing edge is visible, not silent.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field

from .context import _read_text, _skip_reason

# Graph is a minority of the bundle: primary signal is still the diff hunks.
DEFAULT_MAX_GRAPH_BYTES = 16 * 1024
DEFAULT_MAX_SYMBOLS = 24
DEFAULT_MAX_EDGES_PER_SYMBOL = 6
DEFAULT_MAX_INDEX_FILES = 400
DEFAULT_MAX_FILE_BYTES_FOR_INDEX = 256 * 1024

_PY_EXTS = {".py"}


@dataclass
class Symbol:
    """A named definition at a path:line, with a one-line signature."""
    qualname: str
    name: str
    path: str
    line: int
    end_line: int
    signature: str
    kind: str  # "function" | "method" | "class"


@dataclass
class Index:
    """In-memory call graph over one checkout. Built once per review."""
    symbols: list[Symbol] = field(default_factory=list)
    # simple_name -> [Symbol] (unqualified; last-write wins on collisions
    # for resolution, but we keep all for "who defines X")
    by_name: dict[str, list[Symbol]] = field(default_factory=dict)
    # path -> symbols defined in that file
    by_path: dict[str, list[Symbol]] = field(default_factory=dict)
    # callee simple name -> list of (caller Symbol, call_line)
    callers_of: dict[str, list[tuple[Symbol, int]]] = field(default_factory=dict)
    # caller qualname -> list of (callee simple name, call_line)
    callees_of: dict[str, list[tuple[str, int]]] = field(default_factory=dict)
    files_indexed: int = 0
    files_skipped: list[dict] = field(default_factory=list)
    truncated: bool = False


def _signature_for(node: ast.AST, kind: str, class_name: str | None = None) -> str:
    """One-line signature. Bodies never leave the box via this path."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = node.args
        parts: list[str] = []
        for a in args.posonlyargs + args.args:
            parts.append(a.arg)
        if args.vararg:
            parts.append("*" + args.vararg.arg)
        for a in args.kwonlyargs:
            parts.append(a.arg)
        if args.kwarg:
            parts.append("**" + args.kwarg.arg)
        name = f"{class_name}.{node.name}" if class_name else node.name
        prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
        ret = ""
        if node.returns is not None:
            try:
                ret = " -> " + ast.unparse(node.returns)
            except Exception:
                ret = ""
        return f"{prefix} {name}({', '.join(parts)}){ret}"
    if isinstance(node, ast.ClassDef):
        bases = []
        for b in node.bases:
            try:
                bases.append(ast.unparse(b))
            except Exception:
                bases.append("...")
        suffix = f"({', '.join(bases)})" if bases else ""
        return f"class {node.name}{suffix}"
    return f"{kind} {getattr(node, 'name', '?')}"


def _walk_python(path: str, source: str, index: Index) -> None:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        index.files_skipped.append({"path": path, "reason": "python syntax error"})
        return

    # Stack of enclosing function/method Symbols for call attribution.
    enclosing: list[Symbol] = []

    class Visitor(ast.NodeVisitor):
        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            sym = Symbol(
                qualname=node.name, name=node.name, path=path,
                line=node.lineno, end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                signature=_signature_for(node, "class"), kind="class",
            )
            _add_symbol(index, sym)
            # Methods only — nested classes are rare enough to skip for v1.
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    m = Symbol(
                        qualname=f"{node.name}.{child.name}", name=child.name,
                        path=path,
                        line=child.lineno,
                        end_line=getattr(child, "end_lineno", child.lineno) or child.lineno,
                        signature=_signature_for(child, "method", class_name=node.name),
                        kind="method",
                    )
                    _add_symbol(index, m)
                    enclosing.append(m)
                    self.generic_visit(child)
                    enclosing.pop()
                elif isinstance(child, ast.ClassDef):
                    self.visit_ClassDef(child)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._function(node)

        def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            # Top-level or nested function. Nested functions get a dotted
            # qualname under the outer function so they stay unique.
            parent = enclosing[-1].qualname if enclosing else ""
            qn = f"{parent}.{node.name}" if parent else node.name
            sym = Symbol(
                qualname=qn, name=node.name, path=path,
                line=node.lineno,
                end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                signature=_signature_for(node, "function"),
                kind="function",
            )
            _add_symbol(index, sym)
            enclosing.append(sym)
            self.generic_visit(node)
            enclosing.pop()

        def visit_Call(self, node: ast.Call) -> None:
            callee = _callee_name(node.func)
            if callee and enclosing:
                caller = enclosing[-1]
                index.callers_of.setdefault(callee, []).append((caller, node.lineno))
                index.callees_of.setdefault(caller.qualname, []).append(
                    (callee, node.lineno))
            self.generic_visit(node)

    Visitor().visit(tree)


def _callee_name(func: ast.AST) -> str | None:
    """Best-effort simple name for a call target. Attribute chains keep the
    final attribute (`obj.method` -> `method`); that over-matches but never
    under-informs for signature lookup."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _add_symbol(index: Index, sym: Symbol) -> None:
    index.symbols.append(sym)
    index.by_name.setdefault(sym.name, []).append(sym)
    index.by_path.setdefault(sym.path, []).append(sym)


def _list_source_files(repo_dir: str, *, max_files: int,
                       max_file_bytes: int) -> tuple[list[str], list[dict], bool]:
    """Walk the checkout for indexable sources. Same skip heuristics as the
    bundle so vendored trees never enter the graph either."""
    found: list[str] = []
    skipped: list[dict] = []
    truncated = False
    for root, dirs, files in os.walk(repo_dir):
        # Prune skip dirs in-place so os.walk does not descend.
        dirs[:] = [d for d in dirs
                   if d not in {"vendor", "vendors", "node_modules", "third_party",
                                "dist", "build", "generated", ".venv", ".git",
                                "__pycache__"}]
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, repo_dir).replace(os.sep, "/")
            reason = _skip_reason(rel)
            if reason:
                continue  # not worth recording every lockfile under node_modules
            ext = os.path.splitext(name)[1].lower()
            if ext not in _PY_EXTS:
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                skipped.append({"path": rel, "reason": "unreadable"})
                continue
            if size > max_file_bytes:
                skipped.append({"path": rel, "reason": "file too large for index"})
                continue
            found.append(rel)
            if len(found) >= max_files:
                truncated = True
                return found, skipped, truncated
    return found, skipped, truncated


def build_index(repo_dir: str, *,
                max_files: int = DEFAULT_MAX_INDEX_FILES,
                max_file_bytes: int = DEFAULT_MAX_FILE_BYTES_FOR_INDEX,
                ) -> Index:
    """Index definitions and calls across the checkout. Pure CPU, no I/O
    beyond reading source files; result lives only in process memory."""
    index = Index()
    paths, skipped, truncated = _list_source_files(
        repo_dir, max_files=max_files, max_file_bytes=max_file_bytes)
    index.files_skipped.extend(skipped)
    index.truncated = truncated
    for rel in paths:
        text = _read_text(repo_dir, rel)
        if text is None:
            index.files_skipped.append({"path": rel, "reason": "binary or unreadable"})
            continue
        _walk_python(rel, text, index)
        index.files_indexed += 1
    return index


def symbols_touching(index: Index, path: str,
                     ranges: list[tuple[int, int]]) -> list[Symbol]:
    """Symbols in `path` whose body intersects any added line range."""
    out: list[Symbol] = []
    for sym in index.by_path.get(path, []):
        for start, end in ranges:
            if sym.line <= end and sym.end_line >= start:
                out.append(sym)
                break
    # Prefer smaller (more specific) symbols first — methods over the class
    # that contains them, nested functions over the outer — by span length.
    out.sort(key=lambda s: (s.end_line - s.line, s.line))
    return out


def _resolve_defs(index: Index, name: str, *, exclude_path: str | None = None
                  ) -> list[Symbol]:
    """Definitions of `name`, optionally excluding the changed file itself
    so we prefer cross-file edges (the whole point of the graph)."""
    hits = index.by_name.get(name) or []
    cross = [s for s in hits if s.path != exclude_path]
    return cross or hits


def _call_site_line(repo_dir: str | None, path: str, line: int) -> str:
    """One source line at a call site (stripped). Empty when unavailable.

    This is still not a function body — it is the single invocation line that
    proves the edge exists, so the model can see *how* a symbol is called.
    """
    if not repo_dir:
        return ""
    text = _read_text(repo_dir, path)
    if not text:
        return ""
    lines = text.splitlines()
    if line < 1 or line > len(lines):
        return ""
    return lines[line - 1].strip()


def format_graph_section(index: Index, changed: list[tuple[str, list[tuple[int, int]]]],
                         *, max_bytes: int = DEFAULT_MAX_GRAPH_BYTES,
                         max_symbols: int = DEFAULT_MAX_SYMBOLS,
                         max_edges: int = DEFAULT_MAX_EDGES_PER_SYMBOL,
                         repo_dir: str | None = None,
                         ) -> tuple[str, dict]:
    """Render the graph slice for the changed symbols. Returns (text, stats).

    Stats always include a zeroed shape so callers can merge without key
    checks, even when the section is empty.
    """
    stats: dict = {
        "graph_bytes": 0,
        "graph_symbols": 0,
        "graph_edges": 0,
        "graph_files_indexed": index.files_indexed,
        "graph_index_truncated": index.truncated,
        "graph_skipped": list(index.files_skipped),
        "graph_cap_hit": False,
        "graph_enabled": True,
    }
    if max_bytes <= 0:
        stats["graph_enabled"] = False
        return "", stats

    blocks: list[str] = []
    used = 0
    symbols_used = 0
    edges_used = 0
    seen_qual: set[str] = set()

    header = ("## Repo graph (signatures only)\n"
              "# Callers/callees of symbols this PR touched. Function bodies "
              "are not included — only signatures and the single call-site "
              "line. Use these as evidence; findings still must anchor to "
              "'+' lines in the diff sections above.\n")
    header_size = len(header.encode())
    if header_size > max_bytes:
        stats["graph_cap_hit"] = True
        return "", stats
    used = header_size

    for path, ranges in changed:
        for sym in symbols_touching(index, path, ranges):
            if symbols_used >= max_symbols:
                stats["graph_cap_hit"] = True
                break
            if sym.qualname in seen_qual:
                continue
            seen_qual.add(sym.qualname)

            lines = [
                f"### Symbol: {sym.qualname} ({sym.path}:{sym.line})",
                f"signature: {sym.signature}",
            ]

            # Callers of this symbol (by simple name), cross-file preferred.
            caller_lines: list[str] = []
            seen_c: set[str] = set()
            for caller, call_line in index.callers_of.get(sym.name, []):
                if caller.qualname == sym.qualname:
                    continue
                key = f"{caller.path}:{call_line}:{caller.qualname}"
                if key in seen_c:
                    continue
                seen_c.add(key)
                site = _call_site_line(repo_dir, caller.path, call_line)
                entry = f"- {caller.path}:{call_line}  {caller.signature}"
                if site:
                    entry += f"\n  call: {site}"
                caller_lines.append(entry)
                if len(caller_lines) >= max_edges:
                    break
            if caller_lines:
                lines.append("callers:")
                lines.extend(caller_lines)
            else:
                lines.append("callers: (none indexed)")

            # Callees this symbol invokes, resolved to a signature when known.
            callee_lines: list[str] = []
            seen_cal: set[str] = set()
            for callee_name, _call_line in index.callees_of.get(sym.qualname, []):
                if callee_name in seen_cal or callee_name == sym.name:
                    continue
                seen_cal.add(callee_name)
                defs = _resolve_defs(index, callee_name, exclude_path=sym.path)
                if defs:
                    d = defs[0]
                    callee_lines.append(f"- {d.path}:{d.line}  {d.signature}")
                else:
                    callee_lines.append(f"- (unresolved) {callee_name}()")
                if len(callee_lines) >= max_edges:
                    break
            if callee_lines:
                lines.append("callees:")
                lines.extend(callee_lines)
            else:
                lines.append("callees: (none indexed)")

            block = "\n".join(lines) + "\n"
            size = len(block.encode()) + 1
            if used + size > max_bytes:
                stats["graph_cap_hit"] = True
                break
            blocks.append(block)
            used += size
            symbols_used += 1
            edges_used += len(caller_lines) + len(callee_lines)
        if stats["graph_cap_hit"]:
            break

    if not blocks:
        stats["graph_bytes"] = 0
        return "", stats

    text = header + "\n".join(blocks)
    stats["graph_bytes"] = len(text.encode())
    stats["graph_symbols"] = symbols_used
    stats["graph_edges"] = edges_used
    return text, stats
