#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
exec "$repo_root/scripts/check-reported-library-corpus.sh" klauspost-compress
