#!/usr/bin/env python3
"""Text a person reads is written in three languages (Rust side of the interface languages).

Server-written text is a `vpn_domain::Text`, built with `tr!(English, Traditional Chinese,
Japanese)`. This check fails when a Rust string literal holds CJK script anywhere else in
product code, and when the English argument of a `tr!` holds it. Not checked: comments, test
items (`#[cfg(test)]`, `#[test]`, `#[tokio::test]`), test modules (`tests.rs`), `tests/`
directories, and the command-line crates that stay Traditional Chinese (vpnctl, installer).

    scripts/text_guard.py [REPO]      (exit status 1 when something is found)
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

CJK = re.compile("[　-ヿ㐀-鿿＀-￯]")
# Command-line tools that keep Traditional Chinese for now (README "介面語言").
UNCHECKED_CRATES = {"vpnctl", "installer"}
OPEN = {"(": ")", "[": "]", "{": "}"}
OUTSIDE_TR = "CJK text outside tr!: write it as tr!(English, Traditional Chinese, Japanese)"
# Items that exist only in tests.
TEST_ATTRIBUTES = {"cfg(test)", "test", "tokio::test"}
# A module file that is a test module by convention (`#[cfg(test)] mod tests;`).
TEST_FILES = {"tests.rs", "test.rs"}


@dataclass
class Token:
    """One lexical token: a string literal, a word, or a punctuation character."""

    kind: str  # "str", "word" or "punct"
    text: str
    line: int


def _skip_block_comment(src: str, i: int) -> int:
    depth = 0
    while i < len(src):
        if src.startswith("/*", i):
            depth += 1
            i += 2
        elif src.startswith("*/", i):
            depth -= 1
            i += 2
            if depth == 0:
                return i
        else:
            i += 1
    return i


def _raw_string_end(src: str, i: int) -> int | None:
    """End of a raw string starting at `i` (at `r`), or None when `r` starts no raw string."""
    j = i + 1
    hashes = 0
    while j < len(src) and src[j] == "#":
        hashes += 1
        j += 1
    if j >= len(src) or src[j] != '"':
        return None
    close = '"' + "#" * hashes
    end = src.find(close, j + 1)
    return len(src) if end < 0 else end + len(close)


def _string_end(src: str, i: int) -> int:
    """End of a quoted string whose opening quote is at `i`."""
    j = i + 1
    while j < len(src):
        if src[j] == "\\":
            j += 2
        elif src[j] == '"':
            return j + 1
        else:
            j += 1
    return j


def _char_end(src: str, i: int) -> int | None:
    """End of a character literal at `i`, or None for a lifetime or label."""
    if src.startswith("'\\", i):
        end = src.find("'", i + 2)
        return None if end < 0 else end + 1
    if i + 2 < len(src) and src[i + 2] == "'":
        return i + 3
    return None


def tokenize(src: str) -> list[Token]:  # noqa: C901 - one pass, one branch per token kind
    """Split Rust source into tokens; comments are dropped."""
    tokens: list[Token] = []
    i = 0
    line = 1
    while i < len(src):
        c = src[i]
        start = i
        if c == "\n":
            line += 1
            i += 1
            continue
        if c.isspace():
            i += 1
            continue
        if src.startswith("//", i):
            end = src.find("\n", i)
            i = len(src) if end < 0 else end
            continue
        if src.startswith("/*", i):
            i = _skip_block_comment(src, i)
        elif c in "rbc" and (
            raw := _raw_string_end(src, i + (1 if src[i : i + 2] in ("br", "cr") else 0))
        ):
            tokens.append(Token("str", src[start:raw], line))
            i = raw
        elif c in "bc" and i + 1 < len(src) and src[i + 1] == '"':
            i = _string_end(src, i + 1)
            tokens.append(Token("str", src[start:i], line))
        elif c == '"':
            i = _string_end(src, i)
            tokens.append(Token("str", src[start:i], line))
        elif c == "'" and (char_end := _char_end(src, i)) is not None:
            tokens.append(Token("str", src[start:char_end], line))
            i = char_end
        elif c.isalnum() or c in {"_", "'"}:
            i += 1
            while i < len(src) and (src[i].isalnum() or src[i] == "_"):
                i += 1
            tokens.append(Token("word", src[start:i], line))
        else:
            tokens.append(Token("punct", c, line))
            i += 1
        line += src.count("\n", start, i)
    return tokens


def _matching(tokens: list[Token], k: int) -> int:
    """Index of the bracket closing the one at `k`."""
    depth = 0
    for j in range(k, len(tokens)):
        t = tokens[j]
        if t.kind == "punct" and t.text in OPEN:
            depth += 1
        elif t.kind == "punct" and t.text in OPEN.values():
            depth -= 1
            if depth == 0:
                return j
    return len(tokens) - 1


def _item_end(tokens: list[Token], k: int) -> int:
    """Index of the last token of the item that starts at `k` (after its attributes)."""
    j = k
    while j < len(tokens):
        t = tokens[j]
        if t.kind == "punct" and t.text == ";":
            return j
        if t.kind == "punct" and t.text == "{":
            return _matching(tokens, j)
        if t.kind == "punct" and t.text in "([":
            j = _matching(tokens, j)
        j += 1
    return len(tokens) - 1


def _attribute(tokens: list[Token], k: int) -> tuple[str, int] | None:
    """Return the text and last index of an outer attribute starting at `k`."""
    if tokens[k].text != "#" or k + 1 >= len(tokens) or tokens[k + 1].text != "[":
        return None
    end = _matching(tokens, k + 1)
    return "".join(t.text for t in tokens[k + 2 : end]), end


def findings(src: str) -> list[tuple[int, str]]:
    """(line, reason) for every CJK string that is not where it may be."""
    tokens = tokenize(src)
    out: list[tuple[int, str]] = []
    k = 0
    while k < len(tokens):
        attr = _attribute(tokens, k)
        if attr is not None and attr[0] in TEST_ATTRIBUTES:
            j = attr[1] + 1
            while (more := _attribute(tokens, j)) is not None:
                j = more[1] + 1
            k = _item_end(tokens, j) + 1
            continue
        t = tokens[k]
        is_tr = t.kind == "word" and t.text == "tr"
        if is_tr and k + 2 < len(tokens) and tokens[k + 1].text == "!":
            end = _matching(tokens, k + 2)
            strings = [s for s in tokens[k + 3 : end] if s.kind == "str"]
            if strings and CJK.search(strings[0].text):
                out.append((strings[0].line, "the English text of tr! holds CJK script"))
            k = end + 1
            continue
        if t.kind == "str" and CJK.search(t.text):
            out.append((t.line, OUTSIDE_TR))
        k += 1
    return out


def checked_files(repo: Path) -> list[Path]:
    """List the product sources under crates/*/src of the checked crates."""
    files: list[Path] = []
    for crate in sorted((repo / "crates").iterdir()):
        if crate.name in UNCHECKED_CRATES or not (crate / "src").is_dir():
            continue
        files.extend(p for p in sorted((crate / "src").rglob("*.rs")) if p.name not in TEST_FILES)
    return files


def main() -> int:
    """Check the repository given (default: the one holding this script)."""
    repo = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    count = 0
    for path in checked_files(repo):
        for line, reason in findings(path.read_text(encoding="utf-8")):
            sys.stdout.write(f"{path.relative_to(repo)}:{line}: {reason}\n")
            count += 1
    if count:
        sys.stdout.write(f"text_guard: {count} finding(s)\n")
        return 1
    sys.stdout.write("text_guard: every server-written text is in three languages\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
