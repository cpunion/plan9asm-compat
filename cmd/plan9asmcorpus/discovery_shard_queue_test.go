package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the actual all/single-shard shell entry points with inert local
// tools. No module is downloaded and no external package is executed.
func TestDiscoveryAllRefillsVacantWorkerWithoutBatchBarrier(t *testing.T) {
	root, env := discoveryQueueScriptFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", filepath.Join(root, "scripts", "check-discovered-library-corpus.sh"), "all", "4")
	command.Env = append(env, "PLAN9ASM_DISCOVERY_PARALLELISM=2", "QUEUE_FAIL_SHARD=3")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("a failed shard became all-success: %s", output)
	}
	if ctx.Err() != nil {
		t.Fatalf("scheduler did not drain: %v\n%s", ctx.Err(), output)
	}
	for _, marker := range []string{"starved", "shared-cache", "excess-workers"} {
		if _, err := os.Stat(filepath.Join(root, "events", marker)); !os.IsNotExist(err) {
			t.Fatalf("scheduler violated %s: %v\n%s", marker, err, output)
		}
	}
	for _, marker := range []string{"start-0", "start-1", "start-2", "start-3", "done-0", "done-1", "done-2", "done-3", "aggregate-4"} {
		if _, err := os.Stat(filepath.Join(root, "events", marker)); err != nil {
			t.Fatalf("missing %s after sticky shard failure: %v\n%s", marker, err, output)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "caller-cache", "keep")); err != nil {
		t.Fatalf("scheduler removed caller-owned cache: %v", err)
	}
}

func TestDiscoveryAllQueueKeepsPriorityAndAggregateFailures(t *testing.T) {
	root, env := discoveryQueueScriptFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", filepath.Join(root, "scripts", "check-discovered-library-corpus.sh"), "all", "4")
	command.Env = append(env,
		"PLAN9ASM_DISCOVERY_PARALLELISM=1", "PLAN9ASM_DISCOVERY_PRIORITY_SHARDS=3,1",
		"QUEUE_SERIAL=1", "QUEUE_AGGREGATE_FAIL=1",
	)
	output, err := command.CombinedOutput()
	if err == nil || ctx.Err() != nil {
		t.Fatalf("aggregate failure lost or scheduler stalled: %v\n%s", err, output)
	}
	order, err := os.ReadFile(filepath.Join(root, "events", "order"))
	if err != nil || string(order) != "3\n1\n0\n2\n" {
		t.Fatalf("priority/exhaustive order = %q, %v\n%s", order, err, output)
	}
	if _, err := os.Stat(filepath.Join(root, "events", "aggregate-4")); err != nil {
		t.Fatalf("final strict aggregate did not receive the actual shard count: %v\n%s", err, output)
	}
}

func TestDiscoveryAllQueueSuccessfulDrain(t *testing.T) {
	root, env := discoveryQueueScriptFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", filepath.Join(root, "scripts", "check-discovered-library-corpus.sh"), "all", "4")
	command.Env = append(env, "PLAN9ASM_DISCOVERY_PARALLELISM=2")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("complete successful queue failed: %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(root, "events", "aggregate-4")); err != nil {
		t.Fatalf("success omitted the strict aggregate: %v", err)
	}
}

func discoveryQueueScriptFixture(t *testing.T) (string, []string) {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"scripts", "tools/bin", "tools/pkg/include", "events", "caller-cache"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"check-discovered-library-corpus.sh", "llvm22.sh"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		writeDiscoveryQueueExecutable(t, filepath.Join(root, "scripts", name), string(data))
	}
	writeTestFile(t, filepath.Join(root, "tools", "pkg", "include", "funcdata.h"), "fixture")
	writeTestFile(t, filepath.Join(root, "caller-cache", "keep"), "caller-owned")
	writeDiscoveryQueueExecutable(t, filepath.Join(root, "tools", "bin", "go"), discoveryQueueFakeGo)
	writeDiscoveryQueueExecutable(t, filepath.Join(root, "tools", "bin", "llc-22"), "#!/usr/bin/env bash\nprintf 'LLVM version 22.1.8\\n'\n")
	writeDiscoveryQueueExecutable(t, filepath.Join(root, "runner"), discoveryQueueFakeRunner)
	writeDiscoveryQueueExecutable(t, filepath.Join(root, "scripts", "verify-discovered-library-corpus.sh"), discoveryQueueFakeAggregate)
	env := append([]string(nil), os.Environ()...)
	for index := len(env) - 1; index >= 0; index-- {
		if strings.HasPrefix(env[index], "PLAN9ASM_DISCOVERY_") || strings.HasPrefix(env[index], "LLVM_CONFIG=") ||
			strings.HasPrefix(env[index], "PATH=") || strings.HasPrefix(env[index], "QUEUE_") {
			env = append(env[:index], env[index+1:]...)
		}
	}
	env = append(env,
		"PATH="+filepath.Join(root, "tools", "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"QUEUE_ROOT="+root,
		"PLAN9ASM_DISCOVERY_BUILD_CACHE="+filepath.Join(root, "caller-cache"),
	)
	return root, env
}

func writeDiscoveryQueueExecutable(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0700); err != nil {
		t.Fatal(err)
	}
}

const discoveryQueueFakeGo = `#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  env)
    case "$2" in
      GOVERSION) printf 'go1.27.1\n' ;;
      GOROOT) printf '%s/tools\n' "$QUEUE_ROOT" ;;
      *) exit 91 ;;
    esac
    ;;
  tool) printf '%s version go1.27.1\n' "$2" ;;
  build)
    while (( $# )); do
      if [[ "$1" == -o ]]; then
        cp "$QUEUE_ROOT/runner" "$2"
        exit 0
      fi
      shift
    done
    exit 92
    ;;
  *) exit 93 ;;
esac
`

const discoveryQueueFakeRunner = `#!/usr/bin/env bash
set -euo pipefail
events="$QUEUE_ROOT/events"
index=
for argument in "$@"; do
  case "$argument" in
    -discovery-shard-index=*) index=${argument#*=} ;;
    -discovery-build-cache=*) touch "$events/shared-cache" ;;
  esac
done
test -n "$index"
# mkdir is an exclusive, per-shard witness: a duplicate cannot succeed.
mkdir "$events/start-$index"
if [[ "${QUEUE_SERIAL:-0}" == 1 ]]; then
  printf '%s\n' "$index" >> "$events/order"
else
  if [[ "$index" == 0 ]]; then
    for (( attempt=0; attempt<100; attempt++ )); do
      [[ ! -d "$events/start-2" ]] || break
      sleep 0.05
    done
    [[ -d "$events/start-2" ]] || touch "$events/starved"
  elif [[ "$index" == 1 ]]; then
    for (( attempt=0; attempt<100; attempt++ )); do
      [[ ! -d "$events/start-0" ]] || break
      sleep 0.05
    done
    test -d "$events/start-0"
  elif [[ "$index" == 2 && ! -f "$events/done-1" ]]; then
    touch "$events/excess-workers"
  fi
fi
touch "$events/done-$index"
[[ "$index" != "${QUEUE_FAIL_SHARD:-}" ]]
`

const discoveryQueueFakeAggregate = `#!/usr/bin/env bash
set -euo pipefail
events="$QUEUE_ROOT/events"
count=${2:?missing expected shard count}
touch "$events/aggregate-$count"
for (( index=0; index<count; index++ )); do
  test -f "$events/done-$index"
done
[[ "${QUEUE_AGGREGATE_FAIL:-0}" != 1 ]]
`
