#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
suite=${1:-all}
if [[ $# -gt 1 ]]; then
  echo "usage: $0 [suite-id|all]" >&2
  exit 2
fi

# Resolved relative to the checked-out repository.
# shellcheck disable=SC1091
source "$repo_root/scripts/llvm22.sh"
if ! llc_cmd=$(find_llvm22_llc); then
  exit 1
fi

tmp_root=$(mktemp -d)
trap 'rm -rf "$tmp_root"' EXIT
translator="$tmp_root/plan9asmll"
runner="$tmp_root/plan9asmcorpus"
source "$repo_root/scripts/translator-source.sh"
prepare_translator_source "$repo_root"
go build -C "$translator_root/cmd/plan9asmll" -o "$translator" .
go build -C "$repo_root" -o "$runner" ./cmd/plan9asmcorpus

check_latest=${PLAN9ASM_CORPUS_CHECK_LATEST:-true}
"$runner" \
  -manifest="$repo_root/testdata/corpus/reported-libraries.json" \
  -corpus-dir="$repo_root/testdata/corpus" \
  -repo-root="$repo_root" \
  -translator-root="$translator_root" \
  -translator="$translator" \
  -llc="$llc_cmd" \
  -suite="$suite" \
  -check-latest="$check_latest"
