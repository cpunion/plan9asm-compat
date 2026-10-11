//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/llgo-compat/plan9asm/internal/ownedprocess"
)

func TestDiscoveryCollectionTransferActualCLILowDescriptorLimit(t *testing.T) {
	const childKey = "PLAN9ASM_COLLECTION_LOW_FD_ARGS"
	if encoded := os.Getenv(childKey); encoded != "" {
		var args []string
		if err := json.Unmarshal([]byte(encoded), &args); err != nil {
			t.Fatal(err)
		}
		var limit syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
			t.Fatal(err)
		}
		if limit.Max < 64 {
			t.Fatalf("required descriptor fixture needs hard limit >=64, got %d", limit.Max)
		}
		limit.Cur = 64
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil || limit.Cur != 64 {
			t.Fatalf("child did not establish soft descriptor limit64: %+v %v", limit, err)
		}
		bad := filepath.Join(t.TempDir(), "ff.jsonl")
		if err := os.WriteFile(bad, []byte("invalid tail\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 200; i++ {
			if _, err := newTransferModuleCursor(bad); err == nil || !strings.Contains(err.Error(), "decode record shard "+bad+":1") {
				t.Fatalf("cursor decoder-error leaked descriptors/lost concrete failure at iteration%d: %v", i, err)
			}
		}
		flag.CommandLine = flag.NewFlagSet("plan9asmdiscover", flag.ExitOnError)
		os.Args = append([]string{"plan9asmdiscover"}, args...)
		main()
		t.Log("actual CLI imported80 members with RLIMIT_NOFILE soft64")
		return
	}
	var modules []string
	for i := 0; len(modules) < 3; i++ {
		module := fmt.Sprintf("example.com/low-fd/%08d", i)
		if sha256.Sum256([]byte(module))[0] == 0x80 {
			modules = append(modules, module)
		}
	}
	reports := make([]discoveryReport, 80)
	for i := range reports {
		version := fmt.Sprintf("v1.0.%d", i)
		reports[i].Scanned = []moduleVersion{{Path: modules[0], Version: version}, {Path: modules[1], Version: version}, {Path: modules[2], Version: version}}
		reports[i].Failures = []scanFailure{{Module: modules[0], Version: "@latest", Error: fmt.Sprintf("unresolved-%d", i)}}
	}
	source := writeTransferCollection(t, reports)
	destination := filepath.Join(t.TempDir(), "destination")
	change, err := readShardedReports(source)
	if err != nil {
		t.Fatal(err)
	}
	want, err := mergeDiscoveryReports(discoveryReport{}, change)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal([]string{"-convert-report", source, "-out-dir", destination,
		"-index-url", "http://127.0.0.1:1", "-proxy-url", "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDiscoveryCollectionTransferActualCLILowDescriptorLimit$", "-test.v")
	command.Env = append(os.Environ(), childKey+"="+string(encoded))
	command.WaitDelay = time.Second
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	err = ownedprocess.Run(command)
	t.Logf("actual low-FD CLI child: %s", output.String())
	if err != nil || ctx.Err() != nil || errors.Is(err, ownedprocess.ErrCleanup) {
		t.Fatalf("bounded collection descriptor conversion failed: %v context=%v", err, ctx.Err())
	}
	reference := filepath.Join(t.TempDir(), "reference")
	if err := writeShardedReport(reference, want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(readDirectoryFiles(t, destination), readDirectoryFiles(t, reference)) {
		t.Fatal("low-FD collection differs from complete canonical ordered reference")
	}
}

func TestDiscoveryCollectionTransferActualCLIHeap(t *testing.T) {
	const childKey = "PLAN9ASM_COLLECTION_TRANSFER_ARGS"
	if encoded := os.Getenv(childKey); encoded != "" {
		var args []string
		if err := json.Unmarshal([]byte(encoded), &args); err != nil {
			t.Fatal(err)
		}
		flag.CommandLine = flag.NewFlagSet("plan9asmdiscover", flag.ExitOnError)
		os.Args = append([]string{"plan9asmdiscover"}, args...)
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		stop, peak := make(chan struct{}), make(chan uint64, 1)
		go func() {
			maximum := before.HeapAlloc
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for {
				var stats runtime.MemStats
				runtime.ReadMemStats(&stats)
				if stats.HeapAlloc > maximum {
					maximum = stats.HeapAlloc
				}
				select {
				case <-stop:
					peak <- maximum
					return
				case <-ticker.C:
				}
			}
		}()
		main()
		close(stop)
		maximum := <-peak
		var growth uint64
		if maximum > before.HeapAlloc {
			growth = maximum - before.HeapAlloc
		}
		t.Logf("actual collection CLI sampled HeapAlloc growth=%d bytes; source=2x4096x8192, destination=4096x8192 payload bytes", growth)
		if growth > 24<<20 {
			t.Errorf("collection CLI retains complete ledger payloads: growth=%d exceeds %d", growth, 24<<20)
		}
		return
	}

	root := t.TempDir()
	source, destination := filepath.Join(root, "collection"), filepath.Join(root, "destination")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a-first", "z-last"} {
		if err := os.Rename(writeSummaryPayloadFixture(t, 4096), filepath.Join(source, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(writeSummaryPayloadFixture(t, 4096), destination); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal([]string{
		"-convert-report", source, "-out-dir", destination,
		"-index-url", "http://127.0.0.1:1", "-proxy-url", "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDiscoveryCollectionTransferActualCLIHeap$", "-test.v")
	command.Env = append(os.Environ(), childKey+"="+string(encoded))
	command.WaitDelay = time.Second
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	err = ownedprocess.Run(command)
	t.Logf("actual CLI child: %s", output.String())
	if err != nil || ctx.Err() != nil || errors.Is(err, ownedprocess.ErrCleanup) {
		t.Fatalf("bounded collection conversion failed: %v context=%v", err, ctx.Err())
	}
	summary, err := readShardedSummary(destination)
	if err != nil || summary.FailureRecords != 4096 || summary.UniqueModules != 4096 {
		t.Fatalf("actual collection conversion summary=%+v: %v", summary, err)
	}
}
