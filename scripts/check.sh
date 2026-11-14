#!/usr/bin/env bash
# Static gates of the scripts/ owner, with the dev tools locked in scripts/uv.lock (project-local
# .venv): ruff format and lint, strict mypy, shellcheck at every optional check. Then the one gate
# that is a script itself: text_guard.py, which reads the Rust sources (the text a person reads is
# in three languages). It runs no other script.
#
#   scripts/check.sh
set -euo pipefail
umask 022
cd "$(dirname "$0")"

uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy --strict leak_capture.py leak_scenarios.py public_export.py text_guard.py \
  third_party_notices.py
uv run --frozen shellcheck --severity=style --enable=all ./*.sh
python3 -I text_guard.py
echo "scripts: all static gates passed"
