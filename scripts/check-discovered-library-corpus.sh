#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
shard_index=${1:-}
shard_count=${2:-}
report_path=${3:-}
phase_events=${PLAN9ASM_DISCOVERY_EVENTS:-0}
if [[ "$phase_events" != 0 && "$phase_events" != 1 ]]; then
  echo "invalid PLAN9ASM_DISCOVERY_EVENTS: expected 0 or 1" >&2
  exit 2
fi
if [[ "$shard_index" == "all" ]]; then
  if (( $# > 2 )); then
    echo "usage: $0 all [shard-count]" >&2
    exit 2
  fi
  shard_count=${2:-128}
  parallelism=${PLAN9ASM_DISCOVERY_PARALLELISM:-4}
  if ! [[ "$shard_count" =~ ^[1-9][0-9]*$ && "$parallelism" =~ ^[1-9][0-9]*$ ]]; then
    echo "invalid shard count or PLAN9ASM_DISCOVERY_PARALLELISM" >&2
    exit 2
  fi
  shard_order=()
  selected_shards=()
  priority=${PLAN9ASM_DISCOVERY_PRIORITY_SHARDS:-}
  if [[ -n "$priority" ]]; then
    if ! [[ "$priority" =~ ^(0|[1-9][0-9]*)(,(0|[1-9][0-9]*))*$ ]]; then
      echo "invalid PLAN9ASM_DISCOVERY_PRIORITY_SHARDS: expected comma-separated indices" >&2
      exit 2
    fi
    IFS=',' read -r -a shard_order <<< "$priority"
    for index in "${shard_order[@]}"; do
      if (( ${#index} > ${#shard_count} || index >= shard_count )) ||
         [[ -n "${selected_shards[index]:-}" ]]; then
        echo "invalid priority shard $index: out of range or repeated" >&2
        exit 2
      fi
      selected_shards[index]=1
    done
  fi
  for (( index=0; index<shard_count; index++ )); do
    if [[ -z "${selected_shards[index]:-}" ]]; then
      shard_order+=("$index")
    fi
  done
  report_dir="$repo_root/_out/discovered-library-corpus"
  mkdir -p "$report_dir"
  find "$report_dir" -maxdepth 1 -type f -name 'shard-*.json' -delete
  status=0
  # Refill a vacant worker immediately instead of waiting for a slow batch
  # neighbor. Each corpus process owns its default shard cache and closes it
  # before returning; the queue never deletes another live writer's cache.
  # An explicitly supplied cache belongs only to a single-shard invocation.
  unset PLAN9ASM_DISCOVERY_BUILD_CACHE
  if ! printf '%s\n' "${shard_order[@]}" |
    xargs -P "$parallelism" -I '{}' "$0" '{}' "$shard_count" "$report_dir/shard-{}.json"; then
    status=1
  fi
  if ! "$repo_root/scripts/verify-discovered-library-corpus.sh" "$report_dir" "$shard_count"; then
    status=1
  fi
  exit "$status"
fi
if [[ -z "$shard_index" || -z "$shard_count" || $# -gt 3 ]]; then
  echo "usage: $0 <zero-based-shard-index> <shard-count> [report.json]" >&2
  echo "       $0 all [shard-count]" >&2
  exit 2
fi
if ! [[ "$shard_index" =~ ^[0-9]+$ && "$shard_count" =~ ^[1-9][0-9]*$ ]] || (( shard_index >= shard_count )); then
  echo "invalid shard $shard_index/$shard_count" >&2
  exit 2
fi

go_version=$(go env GOVERSION)
if [[ ! "$go_version" =~ ^go1[.]27([.]|$) ]]; then
  echo "discovered third-party corpus requires Go 1.27, got $go_version" >&2
  exit 1
fi
go_root=$(go env GOROOT)
if [[ ! -f "$go_root/pkg/include/funcdata.h" ]]; then
  echo "active Go toolchain is missing pkg/include/funcdata.h" >&2
  exit 1
fi
# Keep every child process on the same Go binary, tools and headers. Resolving
# GOROOT alone is insufficient when the invoking go binary auto-switched
# toolchains: a child with GOTOOLCHAIN=local may otherwise use the older go on
# PATH and classify its version-mismatch build error as source-inapplicable.
export GOROOT="$go_root"
export PATH="$go_root/bin:$PATH"
export GOTOOLCHAIN=local
if [[ "$(go env GOVERSION)" != "$go_version" ||
      "$(go tool compile -V)" != "compile version $go_version" ||
      "$(go tool asm -V)" != "asm version $go_version" ]]; then
  echo "Go command, compiler, assembler and GOROOT versions do not match" >&2
  exit 1
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
# Reports from separate shard worktrees must identify the same source build
# with the same binary hash, without embedding absolute checkout paths.
go build -C "$translator_root/cmd/plan9asmll" -trimpath -o "$translator" .
go build -C "$repo_root" -trimpath -o "$runner" ./cmd/plan9asmcorpus

if [[ -z "$report_path" ]]; then
  report_path="$repo_root/_out/discovered-library-corpus/shard-$shard_index.json"
fi

runner_args=(
  -manifest="$repo_root/testdata/corpus/reported-libraries.json"
  -discovery-ledger="$repo_root/testdata/discovery/ledger"
  -repo-root="$repo_root"
  -translator-root="$translator_root"
  -translator="$translator"
  -llc="$llc_cmd"
  -discovery-shard-index="$shard_index"
  -discovery-shard-count="$shard_count"
  -discovery-report="$report_path"
)
if [[ -n "${PLAN9ASM_DISCOVERY_CANDIDATE_TIMEOUT:-}" ]]; then
  runner_args+=("-candidate-timeout=$PLAN9ASM_DISCOVERY_CANDIDATE_TIMEOUT")
fi
if [[ -n "${PLAN9ASM_DISCOVERY_TARGETS:-}" ]]; then
  runner_args+=("-discovery-targets=$PLAN9ASM_DISCOVERY_TARGETS")
fi
if [[ -n "${PLAN9ASM_DISCOVERY_BUILD_CACHE:-}" ]]; then
  runner_args+=("-discovery-build-cache=$PLAN9ASM_DISCOVERY_BUILD_CACHE")
fi
if [[ "$phase_events" == 1 ]]; then
  # New diagnostic files are exclusive: never overwrite a previous journal.
  # The report reader, not phase timing, certifies candidate completion.
  mkdir -p "$(dirname "$report_path")"
  runner_args+=("-discovery-events=${report_path%.json}.events.jsonl")
fi
"$runner" "${runner_args[@]}"
