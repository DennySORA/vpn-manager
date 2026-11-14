#!/usr/bin/env python3
"""Export this checkout as a public repository with a history of its own.

    scripts/public_export.py OUT [--markers FILE] [--message TEXT]

OUT must not exist or must be empty. The export is HEAD as `git archive` writes it: what
`.gitattributes` marks `export-ignore` (the maintainer's work log, the instructions for coding
agents) is left out, and so is everything untracked or ignored; a note stands where the work log
was. Before anything is committed the export is checked:

- none of the private markers appears in it. FILE (default `.local/private-markers.txt`, which is
  never part of the repository) holds one marker per line: a literal, matched without regard to
  case, or `re:` and a regular expression; `#` starts a comment. A hit is reported by file, line
  and marker number, never by its text. The list finds only what somebody wrote into it: a
  private value that is not listed (a new server, port, profile id or account) passes. So new
  ones are added to FILE before an export, and what changed since the last export is read for
  private data; the export says so each time.
- every relative link of its Markdown files leads to a file of the export, and a link with an
  anchor to a heading of that file.

Then OUT becomes a Git repository with one commit, made with the identity Git is configured with.
Nothing is pushed, and this repository is not changed.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
WORK_LOG = Path("docs") / "process" / "README.md"
WORK_LOG_NOTE = (
    "# Work log\n\nThe maintainer's work log and its evidence are not part of the public "
    "repository. Design and trade-offs: [architecture.md](../architecture.md).\n"
)
LINK = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)\)")
HEADING = re.compile(r"(?m)^#{1,6}[ \t]+(.+?)[ \t]*$")


def git(args: list[str], cwd: Path) -> str:
    """Run git with a fixed argument list and return its output."""
    done = subprocess.run(  # noqa: S603 - fixed argv built in this file, never a shell
        ["git", *args],  # noqa: S607 - the user's own git
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
    if done.returncode != 0:
        sys.stderr.write(done.stderr)
        msg = f"git {' '.join(args)} failed ({done.returncode})"
        raise SystemExit(msg)
    return done.stdout.strip()


def archive(out: Path) -> None:
    """Unpack HEAD, as `git archive` writes it, into `out`."""
    packed = subprocess.Popen(
        ["git", "archive", "--format=tar", "HEAD"],  # noqa: S607 - the user's own git
        cwd=ROOT,
        stdout=subprocess.PIPE,
    )
    unpacked = subprocess.run(  # noqa: S603 - fixed argv, never a shell
        ["tar", "-x", "-C", str(out)],  # noqa: S607 - the system's tar
        stdin=packed.stdout,
        check=False,
    )
    if packed.wait() != 0 or unpacked.returncode != 0:
        msg = "git archive HEAD could not be unpacked"
        raise SystemExit(msg)


def markers_of(path: Path) -> list[re.Pattern[str]]:
    """Read the private markers: literals without regard to case, or `re:` expressions."""
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("re:"):
            out.append(re.compile(line[len("re:") :]))
        else:
            out.append(re.compile(re.escape(line), re.IGNORECASE))
    return out


def text_of(path: Path) -> str | None:
    """Return the text of a file, or None when it is not UTF-8 text."""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def text_files(out: Path) -> list[tuple[Path, str]]:
    """Every file of the export that is text, with its content."""
    paths = sorted(p for p in out.rglob("*") if p.is_file())
    return [(path, text) for path in paths for text in [text_of(path)] if text is not None]


def marker_hits(out: Path, files: list[tuple[Path, str]], markers: list[re.Pattern[str]]) -> int:
    """Report every private marker in the export; return how many were found."""
    hits = 0
    for path, text in files:
        for number, marker in enumerate(markers, start=1):
            for found in marker.finditer(text):
                line = text.count("\n", 0, found.start()) + 1
                sys.stdout.write(f"{path.relative_to(out)}:{line}: private marker {number}\n")
                hits += 1
    return hits


def anchors_of(text: str) -> set[str]:
    """Return the anchors GitHub gives the headings of a Markdown text.

    A heading's anchor is its text in lower case without punctuation, spaces as hyphens; a
    repeated one gets `-1`, `-2`. Inline code marks and emphasis marks are not part of the text.
    """
    seen: dict[str, int] = {}
    out = set()
    for found in HEADING.finditer(text):
        title = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", found.group(1))
        slug = re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        out.add(slug if count == 0 else f"{slug}-{count}")
    return out


def broken_links(out: Path, files: list[tuple[Path, str]]) -> int:
    """Report every relative Markdown link that leads nowhere in the export; return how many.

    A link leads nowhere when its file is not in the export, or when it names an anchor that no
    heading of that Markdown file has. Vendored third-party sources keep the links of their own
    repository and are not checked.
    """
    texts = dict(files)
    broken = 0
    for path, text in files:
        if path.suffix != ".md" or path.relative_to(out).parts[0] == "vendor":
            continue
        for found in LINK.finditer(text):
            target, _, anchor = found.group(1).partition("#")
            if "://" in target or target.startswith("mailto:"):
                continue
            # A link that starts with a slash counts from the top of the repository.
            base = out if target.startswith("/") else path.parent
            file = (base / target.lstrip("/")).resolve() if target else path
            line = text.count("\n", 0, found.start()) + 1
            if not file.exists():
                sys.stdout.write(
                    f"{path.relative_to(out)}:{line}: link to {target} leads nowhere\n"
                )
                broken += 1
            elif (
                anchor
                and file.suffix == ".md"
                and file in texts
                and unquote(anchor) not in anchors_of(texts[file])
            ):
                sys.stdout.write(
                    f"{path.relative_to(out)}:{line}: {target or 'this file'} has no "
                    f"heading for #{anchor}\n"
                )
                broken += 1
    return broken


def main() -> int:
    """Export HEAD into the directory given, check it and commit it there."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("out", type=Path, help="the directory of the new repository")
    parser.add_argument("--markers", type=Path, default=ROOT / ".local" / "private-markers.txt")
    parser.add_argument("--message", help="the message of the one commit")
    args = parser.parse_args()
    out: Path = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        sys.stderr.write(f"{out} is not empty\n")
        return 2
    if not args.markers.is_file():
        sys.stderr.write(f"no private markers at {args.markers}: nothing would be checked\n")
        return 2
    head = git(["rev-parse", "--short", "HEAD"], ROOT)
    if git(["status", "--porcelain"], ROOT):
        sys.stdout.write("note: uncommitted changes are not part of the export (HEAD is)\n")
    out.mkdir(parents=True, exist_ok=True)
    archive(out)
    (out / WORK_LOG).parent.mkdir(parents=True, exist_ok=True)
    (out / WORK_LOG).write_text(WORK_LOG_NOTE, encoding="utf-8")
    files = text_files(out)
    markers = markers_of(args.markers)
    sys.stdout.write(
        f"note: {len(markers)} private markers are checked, and nothing that is not listed in "
        f"{args.markers}: add new private values there first, and read what changed since the "
        "last export\n"
    )
    problems = marker_hits(out, files, markers) + broken_links(out, files)
    if problems:
        sys.stdout.write(f"{problems} problem(s): {out} is left as it is, not committed\n")
        return 1
    git(["init", "-q", "-b", "main"], out)
    git(["add", "-A"], out)
    git(["commit", "-q", "-m", args.message or "Initial public release"], out)
    commit = git(["rev-parse", "--short", "HEAD"], out)
    count = len(git(["ls-files"], out).splitlines())
    sys.stdout.write(f"{out}: {count} files of {head} in one commit, {commit}; nothing pushed\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
