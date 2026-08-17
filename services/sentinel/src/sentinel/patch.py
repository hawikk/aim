"""The diff. Written by this file, from a reviewed catalogue entry — never by a model.

The rule the whole remediation path is built on: *a model writes prose, a human
writes commands.* A draft PR is a command with a merge button on it, so the
same rule applies with more force. The LLM may select nothing here and author
nothing here. What it can do is what it already does in `triage.py`: explain.

So a patch is a **parameterised application of a reviewed transformation**:

    catalogue entry  ->  patch spec (kind, target block types, attribute, value)
    alert            ->  which file, which line
    this module      ->  the exact bytes

Two transformation kinds exist:

* ``set_attribute`` — set a named HCL attribute to a literal on the block that
  encloses the flagged line (IaC one-liners).
* ``bump_dep_version`` — replace a package's declared version in a manifest
  (``package.json``, ``requirements*.txt``, ``pyproject.toml``) with the
  scanner's fixed version (dep-bump autofix).

Everything else — lockfile regeneration, multi-file rewrites, appending
blocks, rewriting expressions — is left to a human, because a wrong answer
there is a plausible-looking PR that changes infrastructure or a dependency
graph in a way nobody reads closely.

Every ambiguity is a refusal, not a guess. `PatchRefused` carries a reason that
goes verbatim into the ping, so "no PR was opened" is always accompanied by
*why*, in one sentence, in the channel — never as silence.

Two inputs here are publisher-controlled and therefore hostile until proven
otherwise: the file path (`labels.path`) and the line number. `safe_repo_path`
is the control on the first — a compromised or buggy pillar must not be able to
aim a write at `.github/workflows/`, where a merged file is code execution on
the org's runners. The second is bounded by the file's own length and by the
`block_types` check: a line pointed at the wrong block refuses instead of
editing whatever happens to be there.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Beyond this a "config file" is a data file, a vendored bundle or a generated
# artefact, and a machine-authored edit to it is not reviewable in a PR diff.
MAX_FILE_BYTES = 256 * 1024

# Paths this service will not write to under any configuration, on any repo in
# the allowlist. `.github/` is code execution on merge (workflows, actions) and
# CODEOWNERS decides who may approve the very PRs this feature opens — a write
# there would let a bus publisher edit the review controls that are supposed to
# contain it. The auto-merge gate in this repo refuses `.github` paths for the
# same reason; this is the same rule enforced one step earlier.
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
    """This finding cannot be turned into a diff we are willing to open a PR for.

    Not an error state — the expected outcome for most findings. The caller
    falls back to the copy-paste proposal and says so.
    """


# Manifest basenames (and suffixes) that bump_dep_version may edit. Lockfiles
# are intentionally absent: regenerating integrity hashes is a human/tool step
# (npm install / poetry lock), not a one-line catalogue transform.
DEP_MANIFEST_SUFFIXES = (
    "package.json",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "pyproject.toml",
)
_PKG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-/@]*$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]*$")


@dataclass(frozen=True)
class PatchSpec:
    """The `patch:` block of a catalogue entry, validated at load time."""

    kind: str
    attribute: str = ""
    value: str = ""
    block_types: tuple[str, ...] = ()
    path_suffixes: tuple[str, ...] = (".tf",)
    summary: str = ""

    @classmethod
    def parse(cls, raw: dict, *, entry_id: str) -> "PatchSpec":
        kind = str(raw.get("kind") or "")
        if kind == "bump_dep_version":
            suffixes = tuple(str(s) for s in (raw.get("path_suffixes") or DEP_MANIFEST_SUFFIXES))
            if not suffixes:
                raise ValueError(f"catalogue entry {entry_id}: bump_dep_version needs "
                                 f"path_suffixes")
            for s in suffixes:
                lower = s.lower()
                if any(tok in lower for tok in ("lock", "yarn.lock", "pnpm-lock",
                                                "poetry.lock", "pipfile.lock", "cargo.lock")):
                    raise ValueError(
                        f"catalogue entry {entry_id}: bump_dep_version must not target "
                        f"lockfiles ({s!r}); regenerate those with the package manager")
            return cls(kind=kind, path_suffixes=suffixes,
                       summary=str(raw.get("summary") or "bump dependency to fixed version"))
        if kind != "set_attribute":
            raise ValueError(f"catalogue entry {entry_id}: unknown patch kind {kind!r} "
                             f"(only 'set_attribute' and 'bump_dep_version' exist)")
        attribute = str(raw.get("attribute") or "")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", attribute):
            raise ValueError(f"catalogue entry {entry_id}: patch.attribute {attribute!r} "
                             f"is not an HCL identifier")
        value = str(raw.get("value", ""))
        if not value or "\n" in value:
            raise ValueError(f"catalogue entry {entry_id}: patch.value must be a "
                             f"single-line literal")
        block_types = tuple(str(b) for b in (raw.get("block_types") or []))
        if not block_types:
            raise ValueError(f"catalogue entry {entry_id}: patch.block_types is required")
        return cls(kind=kind, attribute=attribute, value=value, block_types=block_types,
                   path_suffixes=tuple(str(s) for s in (raw.get("path_suffixes") or [".tf"])),
                   summary=str(raw.get("summary") or ""))


@dataclass(frozen=True)
class PatchResult:
    content: str
    changed: bool
    note: str


def safe_repo_path(path: str) -> str:
    """Normalise a publisher-supplied repo path, or refuse it.

    Rejects: absolute paths, traversal, backslashes, control characters, empty
    or dot segments, and the forbidden prefixes above. Returns the cleaned
    relative path.
    """
    raw = (path or "").strip()
    if not raw:
        raise PatchRefused("the alert carries no file path (labels.path), so there is "
                           "nothing to patch")
    if len(raw) > 400:
        raise PatchRefused("the alert's file path is implausibly long; refusing it")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        raise PatchRefused("the alert's file path contains control characters")
    if "\\" in raw or raw.startswith("/") or re.match(r"^[A-Za-z]:", raw):
        raise PatchRefused(f"the alert's file path is not a relative POSIX path: {raw!r}")
    segments = [s for s in raw.split("/")]
    for segment in segments:
        if segment in ("", ".", "..") or not _SAFE_SEGMENT.match(segment):
            raise PatchRefused(f"the alert's file path has an unusable segment: {raw!r}")
    clean = "/".join(segments)
    if any(clean.startswith(p) for p in FORBIDDEN_PREFIXES) or segments[-1] in FORBIDDEN_NAMES:
        raise PatchRefused(
            f"{clean} is in the never-write set (CI, git and review configuration); "
            f"remediate this one by hand")
    return clean


def check_path_allowed(path: str, spec: PatchSpec) -> None:
    if not any(path.endswith(suffix) for suffix in spec.path_suffixes):
        raise PatchRefused(
            f"{path} is not one of the file types this remediation knows how to edit "
            f"({', '.join(spec.path_suffixes)})")


def apply(spec: PatchSpec, content: str, line: int, *, path: str,
          labels: dict | None = None) -> PatchResult:
    """Apply `spec` at `line` of `content`. Raises PatchRefused on any ambiguity.

    ``labels`` are publisher-controlled (gatehouse/trivy). They may select a
    package and fixed version for ``bump_dep_version``; they never invent a
    transformation kind — that lives only in the reviewed catalogue.
    """
    check_path_allowed(path, spec)
    if len(content.encode()) > MAX_FILE_BYTES:
        raise PatchRefused(f"{path} is larger than {MAX_FILE_BYTES // 1024} KiB; a "
                           f"machine-authored edit to it would not be reviewable")
    if spec.kind == "bump_dep_version":
        return _bump_dep_version(content, path=path, labels=labels or {})

    lines = content.split("\n")
    if not 1 <= line <= len(lines):
        raise PatchRefused(
            f"the alert points at line {line} of {path}, which has {len(lines)} lines — "
            f"the file has changed since it was scanned")

    header_index, block_type, close_index = _enclosing_block(lines, line)
    if block_type not in spec.block_types:
        raise PatchRefused(
            f"line {line} of {path} is inside a `{block_type}` block, but this remediation "
            f"only applies to {', '.join(spec.block_types)}")
    return _set_attribute(lines, header_index, close_index, spec)


def _bump_dep_version(content: str, *, path: str, labels: dict) -> PatchResult:
    """Replace one declared dependency version with the scanner's fixed version."""
    package = str(labels.get("pkg") or labels.get("package") or "").strip()
    fixed = str(labels.get("fixed_version") or "").strip()
    installed = str(labels.get("installed_version") or "").strip()
    if not package or not _PKG_NAME.fullmatch(package):
        raise PatchRefused("dep-bump refused: alert labels.pkg is missing or not a package name")
    if not fixed or fixed.lower() in ("none", "null", "n/a", "-"):
        raise PatchRefused(
            f"dep-bump refused: no fixed version published for {package}; "
            f"a human must choose a pin or alternative")
    if not _VERSION.fullmatch(fixed):
        raise PatchRefused(f"dep-bump refused: fixed_version {fixed!r} is not a safe version token")
    if installed and installed == fixed:
        return PatchResult(content=content, changed=False,
                           note=f"`{package}` is already at fixed version `{fixed}`")

    base = path.rsplit("/", 1)[-1].lower()
    if base == "package.json":
        return _bump_package_json(content, package=package, fixed=fixed, installed=installed)
    if base.startswith("requirements") and base.endswith(".txt"):
        return _bump_requirements_txt(content, package=package, fixed=fixed, installed=installed)
    if base == "pyproject.toml":
        return _bump_pyproject_toml(content, package=package, fixed=fixed, installed=installed)
    raise PatchRefused(
        f"dep-bump does not know how to edit {path}; regenerate the lockfile by hand "
        f"or add a catalogue path_suffix for this manifest kind")


def _bump_package_json(content: str, *, package: str, fixed: str,
                       installed: str) -> PatchResult:
    pattern = re.compile(
        rf'^(\s*)"{re.escape(package)}"\s*:\s*"([^"]*)"(\s*,?\s*)$', re.MULTILINE)
    hits = list(pattern.finditer(content))
    if not hits:
        raise PatchRefused(
            f"`{package}` is not declared in package.json dependencies; "
            f"the lockfile entry may be transitive — bump the parent by hand")
    if len(hits) > 3:
        raise PatchRefused(
            f"`{package}` appears {len(hits)} times in package.json; refusing an ambiguous bump")

    new_content = content
    changed_from = None
    for match in reversed(hits):
        old_ver = match.group(2).strip()
        prefix = ""
        body = old_ver
        for op in (">=", "<=", "~=", "^", "~", ">", "<", "="):
            if body.startswith(op):
                prefix, body = op, body[len(op):]
                break
        if body == fixed or old_ver == fixed:
            continue
        if installed and body and body != installed and old_ver != installed:
            continue
        replacement = f'{match.group(1)}"{package}": "{prefix}{fixed}"{match.group(3)}'
        new_content = new_content[:match.start()] + replacement + new_content[match.end():]
        changed_from = old_ver

    if new_content == content:
        if any(m.group(2).endswith(fixed) or m.group(2) == fixed for m in hits):
            return PatchResult(content=content, changed=False,
                               note=f"`{package}` already declares fixed version `{fixed}`")
        raise PatchRefused(
            f"could not reconcile `{package}` declaration with installed={installed!r} "
            f"fixed={fixed!r}; edit package.json by hand")
    return PatchResult(
        content=new_content, changed=True,
        note=f"bumped `{package}` from `{changed_from}` to `{fixed}` in package.json "
             f"(re-run `npm install` / `pnpm install` to refresh the lockfile)")


def _bump_requirements_txt(content: str, *, package: str, fixed: str,
                           installed: str) -> PatchResult:
    lines = content.split("\n")

    def _norm(name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).lower()

    target = _norm(package)
    changed_from = None
    out = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            out.append(line)
            continue
        match = re.match(
            r'^(\s*)([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?'
            r'(\s*(?:===|==|>=|<=|~=|!=|>|<)\s*)([^;#\s]+)(.*)$',
            line)
        if not match or _norm(match.group(2)) != target:
            out.append(line)
            continue
        old_ver = match.group(5).strip()
        if old_ver == fixed:
            out.append(line)
            continue
        if installed and old_ver != installed and old_ver.lstrip("=v") != installed.lstrip("=v"):
            out.append(line)
            continue
        indent = match.group(1)
        extras = match.group(3) or ""
        rest = match.group(6) or ""
        out.append(f"{indent}{match.group(2)}{extras}=={fixed}{rest}")
        changed_from = old_ver
    if changed_from is None:
        for i, line in enumerate(out):
            match = re.match(rf'^(\s*)({re.escape(package)})(\[[^\]]*\])?(\s*)([;#].*)?$',
                             line, re.IGNORECASE)
            if match:
                out[i] = (f"{match.group(1)}{match.group(2)}{match.group(3) or ''}"
                          f"=={fixed}{match.group(4) or ''}{match.group(5) or ''}")
                changed_from = "(unpinned)"
                break
    if changed_from is None:
        raise PatchRefused(
            f"`{package}` is not a direct requirement in this file; "
            f"it may be transitive — pin it explicitly or upgrade the parent")
    if "\n".join(out) == content:
        return PatchResult(content=content, changed=False,
                           note=f"`{package}` is already pinned to `{fixed}`")
    return PatchResult(
        content="\n".join(out), changed=True,
        note=f"bumped `{package}` from `{changed_from}` to `{fixed}`")


def _bump_pyproject_toml(content: str, *, package: str, fixed: str,
                         installed: str) -> PatchResult:
    pattern = re.compile(
        rf'^(\s*){re.escape(package)}\s*=\s*("|\')([^"\']*)(\2)(.*)$', re.MULTILINE | re.IGNORECASE)
    hits = list(pattern.finditer(content))
    if not hits:
        raise PatchRefused(
            f"`{package}` is not a simple string pin in pyproject.toml; "
            f"multi-line version tables must be edited by hand")
    new_content = content
    changed_from = None
    for match in reversed(hits):
        old_ver = match.group(3).strip()
        prefix = ""
        body = old_ver
        for op in ("^", "~", ">=", "<=", "==", "~=", ">", "<", "="):
            if body.startswith(op):
                prefix, body = op, body[len(op):]
                break
        if body == fixed or old_ver == fixed:
            continue
        if installed and body and body != installed and old_ver != installed:
            continue
        quote = match.group(2)
        replacement = (f"{match.group(1)}{package} = {quote}{prefix}{fixed}{quote}"
                       f"{match.group(5)}")
        new_content = new_content[:match.start()] + replacement + new_content[match.end():]
        changed_from = old_ver
    if new_content == content:
        return PatchResult(content=content, changed=False,
                           note=f"`{package}` already declares fixed version `{fixed}`")
    return PatchResult(
        content=new_content, changed=True,
        note=f"bumped `{package}` from `{changed_from}` to `{fixed}` in pyproject.toml "
             f"(re-run the lock tool if this project uses one)")


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
            raise PatchRefused(
                f"`{spec.attribute}` is assigned across several lines; refusing to rewrite "
                f"a multi-line expression")
        if value.rstrip().endswith(("[", "{", "(")) or "<<" in value:
            raise PatchRefused(
                f"`{spec.attribute}` is assigned a multi-line expression; a human should "
                f"make this change")
        if value.strip() == spec.value:
            return PatchResult(content="\n".join(lines), changed=False,
                               note=f"`{spec.attribute}` is already `{spec.value}` in the "
                                    f"default branch")
        was = value.strip()
        lines[index] = f"{indent}{spec.attribute} = {spec.value}" + (f"  {comment}" if comment else "")
        return PatchResult(content="\n".join(lines), changed=True,
                           note=f"changed `{spec.attribute}` from `{was}` to `{spec.value}`")

    indent = _body_indent(lines, direct, header_index)
    lines.insert(header_index + 1, f"{indent}{spec.attribute} = {spec.value}")
    return PatchResult(content="\n".join(lines), changed=True,
                       note=f"added `{spec.attribute} = {spec.value}`")


def _direct_children(lines: list[str], body: list[int]) -> list[int]:
    """Indices in `body` that sit at the block's top level, not in a nested block."""
    out, depth = [], 0
    heredoc = ""
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
    """Split `false  # why` into ("false", "# why"), respecting quoted strings."""
    masked = _STRING.sub(lambda m: "\0" * len(m.group(0)), rhs)
    positions = [p for p in (masked.find("#"), masked.find("//")) if p != -1]
    if not positions:
        return rhs.strip(), ""
    cut = min(positions)
    return rhs[:cut].strip(), rhs[cut:].strip()


def _strip(line: str, heredoc: str) -> tuple[str, str]:
    """Return (brace-significant text, heredoc terminator still open).

    Strings, comments and heredoc bodies are removed before braces are counted;
    `"${var.tags}"` and `# {` must not move the depth counter, and neither must
    a policy document embedded in a heredoc.
    """
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
    """(header index, block type, closing-brace index) for the top-level block
    containing 1-indexed `line`. Raises PatchRefused if there isn't exactly one."""
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
        f"line {line} is not inside a closed Terraform block — the file may have moved "
        f"since it was scanned, or it is not the file the finding refers to")


def _block_type(match: re.Match) -> str:
    keyword = match.group(1)
    labels = re.findall(r'"((?:[^"\\]|\\.)*)"', match.group(2) or "")
    if keyword in ("resource", "data") and labels:
        return f"{'data.' if keyword == 'data' else ''}{labels[0]}"
    return keyword
