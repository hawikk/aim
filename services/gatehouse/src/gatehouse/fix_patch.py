"""Apply a reviewed catalogue patch to file content for one-click suggestions.

Port of the security-critical path in sentinel's `patch.py` (AIM-185). Gatehouse
and sentinel deliberately do not share a package — they run in separate
containers with different blast radii — so the transformation logic is mirrored
here and kept intentionally small.

Only `set_attribute` exists. Every ambiguity is a refusal, not a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_FILE_BYTES = 256 * 1024
FORBIDDEN_PREFIXES = (".github/", ".git/", ".circleci/", ".gitlab/")
FORBIDDEN_NAMES = ("CODEOWNERS", ".gitmodules", ".gitattributes", ".npmrc",
                   ".pre-commit-config.yaml")

_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")
_HEREDOC = re.compile(r"<<[-~]?\s*([A-Za-z_][A-Za-z0-9_]*)")
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_HEADER = re.compile(r'^\s*([a-z][a-z0-9_]*)\s*((?:"(?:[^"\\]|\\.)*"\s*)*)\{\s*$')
_BLOCK_KEYWORDS = ("resource", "data", "module", "provider", "variable",
                   "output", "locals", "terraform")


class PatchRefused(Exception):
    """This finding cannot become a suggested fix. Expected for most findings."""


@dataclass(frozen=True)
class PatchSpec:
    kind: str
    attribute: str
    value: str
    block_types: tuple[str, ...]
    path_suffixes: tuple[str, ...] = (".tf",)
    summary: str = ""

    @classmethod
    def parse(cls, raw: dict, *, entry_id: str) -> "PatchSpec":
        kind = str(raw.get("kind") or "")
        if kind != "set_attribute":
            raise ValueError(f"fix entry {entry_id}: unknown patch kind {kind!r}")
        attribute = str(raw.get("attribute") or "")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", attribute):
            raise ValueError(f"fix entry {entry_id}: bad patch.attribute {attribute!r}")
        value = str(raw.get("value", ""))
        if not value or "\n" in value:
            raise ValueError(f"fix entry {entry_id}: patch.value must be a single-line literal")
        block_types = tuple(str(b) for b in (raw.get("block_types") or []))
        if not block_types:
            raise ValueError(f"fix entry {entry_id}: patch.block_types is required")
        return cls(
            kind=kind, attribute=attribute, value=value, block_types=block_types,
            path_suffixes=tuple(str(s) for s in (raw.get("path_suffixes") or [".tf"])),
            summary=str(raw.get("summary") or ""),
        )


@dataclass(frozen=True)
class PatchResult:
    content: str
    changed: bool
    note: str
    # 1-based inclusive line range in the *original* content that the suggestion
    # replaces. Insertion-only patches still name the line the attribute was
    # added after (the header), so GitHub has something to anchor to.
    start_line: int
    end_line: int
    replacement_lines: tuple[str, ...]


def safe_repo_path(path: str) -> str:
    raw = (path or "").strip()
    if not raw:
        raise PatchRefused("finding has no file path")
    if len(raw) > 400:
        raise PatchRefused("finding path is implausibly long")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        raise PatchRefused("finding path contains control characters")
    if "\\" in raw or raw.startswith("/") or re.match(r"^[A-Za-z]:", raw):
        raise PatchRefused(f"finding path is not a relative POSIX path: {raw!r}")
    segments = raw.split("/")
    for segment in segments:
        if segment in ("", ".", "..") or not _SAFE_SEGMENT.match(segment):
            raise PatchRefused(f"finding path has an unusable segment: {raw!r}")
    clean = "/".join(segments)
    if any(clean.startswith(p) for p in FORBIDDEN_PREFIXES) or segments[-1] in FORBIDDEN_NAMES:
        raise PatchRefused(f"{clean} is in the never-write set")
    return clean


def check_path_allowed(path: str, spec: PatchSpec) -> None:
    if not any(path.endswith(suffix) for suffix in spec.path_suffixes):
        raise PatchRefused(
            f"{path} is not a file type this fix knows how to edit "
            f"({', '.join(spec.path_suffixes)})")


def apply(spec: PatchSpec, content: str, line: int, *, path: str) -> PatchResult:
    """Apply `spec` at 1-based `line`. Raises PatchRefused on any ambiguity."""
    check_path_allowed(path, spec)
    if len(content.encode()) > MAX_FILE_BYTES:
        raise PatchRefused(f"{path} is larger than {MAX_FILE_BYTES // 1024} KiB")
    lines = content.split("\n")
    if not 1 <= line <= len(lines):
        raise PatchRefused(
            f"finding points at line {line} of {path}, which has {len(lines)} lines")

    header_index, block_type, close_index = _enclosing_block(lines, line)
    if block_type not in spec.block_types:
        raise PatchRefused(
            f"line {line} of {path} is inside a `{block_type}` block, but this fix "
            f"only applies to {', '.join(spec.block_types)}")
    return _set_attribute(lines, header_index, close_index, spec)


def _set_attribute(lines: list[str], header_index: int, close_index: int,
                   spec: PatchSpec) -> PatchResult:
    body = list(range(header_index + 1, close_index))
    direct = _direct_children(lines, body)
    assign = re.compile(rf"^(\s*){re.escape(spec.attribute)}\s*=\s*(.*)$")

    for index in direct:
        match = assign.match(lines[index])
        if not match:
            continue
        indent, rhs = match.group(1), match.group(2)
        value, comment = _split_comment(rhs)
        if not value:
            raise PatchRefused(f"`{spec.attribute}` is assigned across several lines")
        if value.rstrip().endswith(("[", "{", "(")) or "<<" in value:
            raise PatchRefused(f"`{spec.attribute}` is a multi-line expression")
        if value.strip() == spec.value:
            return PatchResult(
                content="\n".join(lines), changed=False,
                note=f"`{spec.attribute}` is already `{spec.value}`",
                start_line=index + 1, end_line=index + 1,
                replacement_lines=(lines[index],))
        was = value.strip()
        new_line = f"{indent}{spec.attribute} = {spec.value}" + (f"  {comment}" if comment else "")
        original = list(lines)
        original[index] = new_line
        return PatchResult(
            content="\n".join(original), changed=True,
            note=f"changed `{spec.attribute}` from `{was}` to `{spec.value}`",
            start_line=index + 1, end_line=index + 1,
            replacement_lines=(new_line,))

    indent = _body_indent(lines, direct, header_index)
    new_line = f"{indent}{spec.attribute} = {spec.value}"
    # GitHub suggestions replace a contiguous range. For an insertion we
    # replace the header line with header + new attribute so the author sees
    # the attribute appear in context rather than as a free-floating line.
    header = lines[header_index]
    original = list(lines)
    original.insert(header_index + 1, new_line)
    return PatchResult(
        content="\n".join(original), changed=True,
        note=f"added `{spec.attribute} = {spec.value}`",
        start_line=header_index + 1, end_line=header_index + 1,
        replacement_lines=(header, new_line))


def _direct_children(lines: list[str], body: list[int]) -> list[int]:
    out, depth, heredoc = [], 0, ""
    for index in body:
        stripped, heredoc = _strip(lines[index], heredoc)
        if depth == 0:
            out.append(index)
        depth += stripped.count("{") - stripped.count("}")
        depth = max(depth, 0)
    return out


def _body_indent(lines: list[str], direct: list[int], header_index: int) -> str:
    for index in direct:
        if lines[index].strip():
            return lines[index][:len(lines[index]) - len(lines[index].lstrip())]
    header = lines[header_index]
    return header[:len(header) - len(header.lstrip())] + "  "


def _split_comment(rhs: str) -> tuple[str, str]:
    masked = _STRING.sub(lambda m: "\0" * len(m.group(0)), rhs)
    positions = [p for p in (masked.find("#"), masked.find("//")) if p != -1]
    if not positions:
        return rhs.strip(), ""
    cut = min(positions)
    return rhs[:cut].strip(), rhs[cut:].strip()


def _strip(line: str, heredoc: str) -> tuple[str, str]:
    if heredoc:
        return ("", "" if line.strip() == heredoc else heredoc)
    masked = _STRING.sub("", line)
    for marker in ("#", "//"):
        cut = masked.find(marker)
        if cut != -1:
            masked = masked[:cut]
    opened = _HEREDOC.search(masked)
    if opened:
        return masked[:opened.start()], opened.group(1)
    return masked, ""


def _enclosing_block(lines: list[str], line: int) -> tuple[int, str, int]:
    target = line - 1
    depth, heredoc = 0, ""
    header_index, block_type = -1, ""
    for index, raw in enumerate(lines):
        stripped, heredoc = _strip(raw, heredoc)
        opens = stripped.count("{")
        closes = stripped.count("}")
        if depth == 0 and opens:
            match = _HEADER.match(raw)
            if match and match.group(1) in _BLOCK_KEYWORDS:
                header_index, block_type = index, _block_type(match)
            else:
                header_index, block_type = index, ""
        depth += opens - closes
        if depth <= 0:
            depth = 0
            if header_index != -1 and header_index <= target <= index:
                if not block_type:
                    raise PatchRefused(
                        f"line {line} is not inside a recognisable Terraform block")
                return header_index, block_type, index
            header_index, block_type = -1, ""
    raise PatchRefused(
        f"line {line} is not inside a closed Terraform block")


def _block_type(match: re.Match) -> str:
    keyword = match.group(1)
    labels = re.findall(r'"((?:[^"\\]|\\.)*)"', match.group(2) or "")
    if keyword in ("resource", "data") and labels:
        return f"{'data.' if keyword == 'data' else ''}{labels[0]}"
    return keyword
