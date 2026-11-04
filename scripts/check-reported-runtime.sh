#!/usr/bin/env bash
# Known issue reproductions are ordinary failures, never xfail/skip receipts.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
llgo=$(command -v "${LLGO:-llgo}")
llgo=$(realpath "$llgo")
export GOWORK=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local
export GOSUMDB=sum.golang.org GOPRIVATE= GONOSUMDB= GONOPROXY= GOINSECURE=

if [[ $(go env GOHOSTOS)/$(go env GOHOSTARCH) != linux/amd64 ]]; then
  echo 'reported runtime probes require linux/amd64' >&2
  exit 1
fi
if [[ $("$llgo" env LLGO_LLVM_VERSION) != 22.* ]]; then
  echo 'reported runtime probes require LLVM 22' >&2
  exit 1
fi
if [[ $(go env GOVERSION) != go1.27.3 ]]; then
  echo 'reported runtime probes require Go 1.27.3' >&2
  exit 1
fi
if [[ $(go env CGO_ENABLED) != 1 ]]; then
  echo 'reported runtime probes require CGO_ENABLED=1' >&2
  exit 1
fi
if [[ $(llvm-nm-22 --version) != *'version 22.'* ]]; then
  echo 'reported runtime probes require llvm-nm-22' >&2
  exit 1
fi

mkdir -p "$repo/_out/reported-runtime"
report=$(mktemp -d "$repo/_out/reported-runtime/run.XXXXXX")
sha256sum "$llgo" > "$report/compiler.sha256"
go version -m "$llgo" > "$report/compiler-build.txt"
go version > "$report/go-version.txt"
failed=0

names=("$@")
if [[ ${#names[@]} == 0 ]]; then
  names=(funcval purego sqlite gohex s2 purego-latest turso crc32 libcabi0)
fi
for name in "${names[@]}"; do
  case "$name" in
    funcval|purego|sqlite|gohex|s2|purego-latest|turso|crc32|libcabi0) ;;
    *) echo "Unknown reported case: $name" >&2; exit 1 ;;
  esac
done

assembly="$repo/scripts/check-reported-assembly.py"
shared="$report/lib-purego-abi-probe.so"
turso_cache="$report/turso-library-cache"
cleanup() {
  rm -f -- "$shared"
  rm -rf -- "$turso_cache"
}
trap cleanup EXIT

for name in "${names[@]}"; do
  dir="$repo/testdata/reported/$name"
  source_ready=1
  modes=(default)
  run_environment=()
  if [[ $name == turso ]]; then
    run_environment=(env "TURSO_GO_CACHE_DIR=$turso_cache")
  fi
  case "$name" in
    gohex|s2|purego-latest|turso|crc32|libcabi0)
      if ! (cd "$dir" && python3 "$assembly" source "$name" "$report/$name-source.json") \
          > "$report/$name-source.log" 2>&1; then
        source_ready=0
        failed=1
      fi
      ;;
  esac
  if [[ $name == purego-latest ]]; then
    modes=(strlen ints15 floats15 mixed15 qsort)
    if [[ $(clang-22 --version) != *'version 22.'* ]]; then
      echo 'purego native oracle requires clang-22' >&2
      exit 1
    fi
    if ! timeout -k 10s 60s clang-22 -std=c11 -O2 -fPIC -shared -Wl,-z,defs \
        "$dir/native/abi.c" -o "$shared" > "$report/purego-native-build.log" 2>&1; then
      source_ready=0
      failed=1
    fi
  fi

  for compiler in go llgo; do
    tool=go
    if [[ $compiler == llgo ]]; then
      tool="$llgo"
    fi
    binary="$report/$name-$compiler"
    status=passed
    phase=source
    if [[ $source_ready != 1 ]]; then
      status=failed
    else
      phase=build
      if ! (cd "$dir" && timeout -k 10s 20m "$tool" build -mod=readonly -o "$binary" .) \
          > "$binary.build.log" 2>&1; then
        status=failed
      fi
    fi
    if [[ $status == passed && -f $report/$name-source.json ]]; then
      phase=symbols
      if ! python3 "$assembly" linked "$name" "$report/$name-source.json" \
          --compiler "$compiler" --binary "$binary" > "$binary.symbols.log" 2>&1; then
        status=failed
      fi
    fi
    if [[ $status == passed ]]; then
      phase=run
      for mode in "${modes[@]}"; do
        args=()
        if [[ $mode != default ]]; then args=("$mode" "$shared"); fi
        log="$binary.$mode.run.log"
        if ! timeout -k 10s 120s "${run_environment[@]}" "$binary" "${args[@]}" > "$log" 2>&1; then
          status=failed
        elif [[ $compiler == llgo ]]; then
          reference="$report/$name-go.$mode.run.log"
          if [[ ! -f $reference ]] || ! cmp -s "$reference" "$log"; then
            status=failed
          fi
        fi
      done
    fi
    printf '{"case":"%s","compiler":"%s","phase":"%s","status":"%s"}\n' \
      "$name" "$compiler" "$phase" "$status" >> "$report/results.jsonl"
    printf '%s %s: %s (%s)\n' "$name" "$compiler" "$status" "$phase"
    if [[ $status == failed ]]; then
      failed=1
    fi
    if [[ -f $binary ]]; then
      sha256sum "$binary" > "$binary.sha256"
      rm -- "$binary"
    fi
  done
  if [[ -f $report/$name-source.json ]]; then
    source_status=passed
    if ! python3 "$assembly" unchanged "$name" "$report/$name-source.json" \
        > "$report/$name-source-final.log" 2>&1; then
      failed=1
      source_status=failed
    fi
    printf '{"case":"%s","compiler":"source","phase":"source-final","status":"%s"}\n' \
      "$name" "$source_status" >> "$report/results.jsonl"
  fi
done

echo "Reports: $report"
exit "$failed"
