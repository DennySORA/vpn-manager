#!/usr/bin/env python3
"""Third-party notices of the programs VPN Manager ships.

The programs are `vpnd` (with the web UI inside), `vpnctl` and `vpn-installer`. This writes one
text file for them: VPN Manager's own licences (its AirVPN adapter is GPL-3.0-or-later, so the
file says what `vpnd` is distributed under and carries that licence's text), every third-party
package they contain with its version, licence and source, where the source of the weak-copyleft
ones is, what was modified or adapted, and the licence texts the packages ship (an identical text
once). scripts/package.sh puts the file into the installer (`vpn-installer licenses` prints it)
and next to it in dist/.

    scripts/third_party_notices.py OUT [--target TRIPLE]

Rust packages: what Cargo.lock resolves for TRIPLE (default: this machine's) from the three
programs, without development-only dependencies. npm packages: the production dependencies of
web/ (`pnpm licenses list --prod`). Needs cargo, and pnpm with web/node_modules installed; nothing
is downloaded (`cargo metadata --offline`) and nothing is built. The output is the same for the
same lock files: sorted, no dates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROGRAMS = ("vpnd", "vpnctl", "vpn-installer")
# Top-level files of a package that hold its licence or notices.
LICENCE_FILE = re.compile(r"(?i)^(licen[cs]e|copying|notice|unlicense|copyright)")
# A package that ships no licence file: the standard text of what its expression names.
STANDARD_TEXTS = {
    "Apache-2.0": ROOT / "LICENSE-APACHE",
    "MIT": ROOT / "scripts" / "licenses" / "MIT.txt",
    "MPL-2.0": ROOT / "scripts" / "licenses" / "MPL-2.0.txt",
}
RULE = "=" * 100
# VPN Manager's AirVPN adapter is GPL-3.0-or-later (NOTICE says why) and `vpnd` contains it.
OWN_GPL = ROOT / "LICENSE-GPL-3.0"
SOURCE = "https://github.com/DennySORA/vpn-manager"


@dataclass
class Package:
    """One third-party package of the programs."""

    ecosystem: str  # "Rust crate" or "npm package"
    name: str
    version: str
    licence: str
    source: str
    directory: Path | None
    modified: bool = False
    texts: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        """Name and version, as the lists show it."""
        return f"{self.name} {self.version}"


def run(argv: list[str], cwd: Path) -> str:
    """Run a fixed command of this repository's toolchain and return its output."""
    done = subprocess.run(  # noqa: S603 - fixed argv built in this file, never a shell
        argv, cwd=cwd, check=False, capture_output=True, text=True
    )
    if done.returncode != 0:
        sys.stderr.write(done.stderr)
        msg = f"{' '.join(argv)} failed ({done.returncode})"
        raise SystemExit(msg)
    return done.stdout


def host_triple() -> str:
    """Return the target triple of this machine's Rust toolchain."""
    for line in run(["rustc", "-vV"], ROOT).splitlines():
        if line.startswith("host: "):
            return line[len("host: ") :]
    msg = "rustc -vV names no host"
    raise SystemExit(msg)


def rust_packages(triple: str) -> list[Package]:
    """Third-party crates the three programs are built from for `triple`."""
    argv = ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"]
    meta = json.loads(run([*argv, "--filter-platform", triple], ROOT))
    by_id = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    members = set(meta["workspace_members"])
    todo = [p["id"] for p in meta["packages"] if p["id"] in members and p["name"] in PROGRAMS]
    if len(todo) != len(PROGRAMS):
        msg = f"the workspace does not hold all of {', '.join(PROGRAMS)}"
        raise SystemExit(msg)
    seen: set[str] = set()
    while todo:
        package = todo.pop()
        if package in seen:
            continue
        seen.add(package)
        # A dependency used only by tests and examples is not in the programs.
        todo.extend(
            dep["pkg"]
            for dep in nodes[package]["deps"]
            if any(kind["kind"] != "dev" for kind in dep["dep_kinds"])
        )
    vendored = str(ROOT / "vendor") + "/"
    out = []
    for package in sorted(seen - members):
        p = by_id[package]
        manifest = Path(p["manifest_path"])
        crate = f"https://crates.io/crates/{p['name']}/{p['version']}"
        out.append(
            Package(
                ecosystem="Rust crate",
                name=p["name"],
                version=p["version"],
                licence=p.get("license") or "see the package",
                source=p.get("repository") or crate,
                directory=manifest.parent,
                modified=str(manifest).startswith(vendored),
            )
        )
    return out


def npm_packages() -> list[Package]:
    """Production npm packages of the web UI."""
    listed = json.loads(run(["pnpm", "licenses", "list", "--prod", "--json"], ROOT / "web"))
    out = []
    for licence, packages in listed.items():
        for p in packages:
            paths = p.get("paths") or [None]
            for version, path in zip(p["versions"], paths):
                out.append(
                    Package(
                        ecosystem="npm package",
                        name=p["name"],
                        version=version,
                        licence=p.get("license") or licence,
                        source=p.get("homepage")
                        or f"https://www.npmjs.com/package/{p['name']}/v/{version}",
                        directory=Path(path) if path else None,
                    )
                )
    return out


def licence_texts(directory: Path | None) -> list[str]:
    """Licence and notice files at the top of a package (and in its `LICENSES` folder)."""
    if directory is None or not directory.is_dir():
        return []
    files = [f for f in directory.iterdir() if f.is_file() and LICENCE_FILE.match(f.name)]
    for folder in directory.iterdir():
        if folder.is_dir() and folder.name.lower() in {"licenses", "license"}:
            files.extend(f for f in folder.iterdir() if f.is_file())
    return [f.read_text(encoding="utf-8", errors="replace").strip() for f in sorted(files)]


def standard_texts(licence: str) -> list[str]:
    """Return the standard texts of the licences an expression names (no licence file shipped)."""
    named = set(re.findall(r"[A-Za-z0-9.+-]+", licence)) - {"OR", "AND", "WITH"}
    return [
        path.read_text(encoding="utf-8").strip()
        for name, path in sorted(STANDARD_TEXTS.items())
        if name in named
    ]


def summary(packages: list[Package]) -> list[str]:
    """One line per package: what it is, its licence and where it comes from."""
    lines = []
    for ecosystem in ("Rust crate", "npm package"):
        mine = [p for p in packages if p.ecosystem == ecosystem]
        lines += ["", f"{ecosystem}s ({len(mine)})", ""]
        lines += [f"  {p.label} - {p.licence} - {p.source}" for p in mine]
    return lines


def source_offers(packages: list[Package]) -> list[str]:
    """Where the source of the MPL-licensed packages is (MPL-2.0 section 3.2)."""
    lines = []
    for p in packages:
        if "MPL" not in p.licence:
            continue
        how = "with the changes in the source repository's vendor/" if p.modified else "unmodified"
        lines.append(f"  {p.label} ({p.licence}) is used {how}. Its source code: {p.source}")
        if p.ecosystem == "Rust crate":
            archive = f"https://crates.io/api/v1/crates/{p.name}/{p.version}/download"
            lines.append(f"    this version's source archive: {archive}")
    return lines


def texts_section(packages: list[Package]) -> list[str]:
    """Every distinct licence text once, under the packages it belongs to."""
    users: dict[str, list[str]] = {}
    body: dict[str, str] = {}
    for p in packages:
        for text in p.texts:
            key = hashlib.sha256(" ".join(text.split()).encode()).hexdigest()
            users.setdefault(key, []).append(p.label)
            body.setdefault(key, text)
    lines = []
    for key in sorted(users, key=lambda k: (min(users[k]).lower(), k)):
        lines += ["", RULE, "Applies to: " + ", ".join(sorted(set(users[key]))), RULE, ""]
        lines.append(body[key])
    return lines


def own_texts() -> list[str]:
    """Return the licence `vpnd` is distributed under, the first of the licence texts."""
    applies = "Applies to: VPN Manager's AirVPN adapter, and vpnd and the installers that carry it"
    return ["", RULE, applies, RULE, "", OWN_GPL.read_text(encoding="utf-8").rstrip()]


def render(packages: list[Package], triple: str) -> str:
    """Build the whole notice text."""
    modified = [p for p in packages if p.modified]
    without = [p for p in packages if not p.texts]
    for p in without:
        p.texts = standard_texts(p.licence)
    lines = [
        "VPN Manager - third-party notices",
        "",
        "VPN Manager is licensed under MIT OR Apache-2.0 (LICENSE-MIT and LICENSE-APACHE in its",
        "source repository), except its AirVPN adapter (crates/providers/src/airvpn), which is",
        "licensed under GPL-3.0-or-later (LICENSE-GPL-3.0; NOTICE in the repository says why).",
        "vpnd contains that adapter: vpnd, and an installer that carries it, are distributed under",
        "the GNU General Public License, version 3 or (at your option) any later version, without",
        "any warranty. That licence's text is the first of the licence texts below, and the source",
        f"code of a release is the source repository at the release's tag: {SOURCE}",
        "",
        "The programs - vpnd with the web UI, vpnctl and vpn-installer - contain the third-party",
        "software listed here, each under its own licence. This list is for",
        f"{triple}, made from Cargo.lock and web/pnpm-lock.yaml.",
        *summary(packages),
        "",
        "Source code of the weak-copyleft packages",
        "",
        *source_offers(packages),
        "",
        "Modified packages",
        "",
        *[
            f"  {p.label} ({p.licence}): patched, as vendor/README.md in the source repository says"
            for p in modified
        ],
        "",
        "Packages that ship no licence file (the standard text of their licence is below)",
        "",
        *[f"  {p.label} - {p.licence} - {p.source}" for p in without],
        "",
        "Source code adapted into the web UI",
        "",
        (ROOT / "web" / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8").strip(),
        "",
        "Licence texts",
        *own_texts(),
        *texts_section(packages),
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    """Write the notices of this checkout's lock files to the file given."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("out", type=Path, help="the text file to write")
    parser.add_argument("--target", help="Rust target triple (default: this machine's)")
    args = parser.parse_args()
    triple = args.target or host_triple()
    packages = rust_packages(triple) + npm_packages()
    for p in packages:
        p.texts = licence_texts(p.directory)
    packages.sort(key=lambda p: (p.ecosystem != "Rust crate", p.name.lower(), p.version))
    text = render(packages, triple)
    args.out.write_text(text, encoding="utf-8")
    sys.stdout.write(f"{args.out}: {len(packages)} packages, {len(text.encode())} bytes\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
