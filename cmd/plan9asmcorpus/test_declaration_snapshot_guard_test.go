package main

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/mod/sumdb/dirhash"
)

func testSnapshotGuardCapture(t testing.TB, payloadBytes int) (*discoveryTestModuleCapture, gotoolprofile.TestModuleSource) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	module, version := "example.invalid/snapshot-guard", "v1.0.0"
	files := map[string]string{
		"go.mod":     "module " + module + "\n\ngo 1.20\n",
		"source.go":  "//go:build !race\n\npackage dependency\n",
		"source.bin": strings.Repeat("snapshot fixture bytes\n", payloadBytes/23+1),
	}
	archive := filepath.Join(t.TempDir(), "module.zip")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	t.Cleanup(func() {
		// Fatal setup paths must finalize the ZIP before releasing its file.
		_ = writer.Close()
		_ = file.Close()
	})
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		member, err := writer.Create(module + "@" + version + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(member, contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	sum, err := dirhash.HashZip(archive, dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	modSum, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(files["go.mod"])), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(root, "go.mod")
	capture := &discoveryTestModuleCapture{
		Root: root,
		Download: moduleDownloadInfo{
			Path: module, Version: version, Dir: root, GoMod: metadata,
			Zip: archive, Sum: sum, GoModSum: modSum,
		},
		Plan:     &discoveryOrdinarySelectionPlan{Module: module, Version: version},
		Exports:  make(map[string]string),
		Metadata: map[string]string{metadata: discoveryFeatureBytesSHA256([]byte(files["go.mod"]))},
	}
	if err := captureDiscoveryTestSourceDirectory(capture.Plan, root, root); err != nil {
		t.Fatal(err)
	}
	source, err := discoveryTestModuleSnapshot(capture)
	if err != nil {
		t.Fatal(err)
	}
	if err := gotoolprofile.VerifyTestModuleSource(context.Background(), source, root, archive); err != nil {
		t.Fatal(err)
	}
	return capture, source
}

func testSnapshotGuardPlan(capture *discoveryTestModuleCapture, source gotoolprofile.TestModuleSource, count int) *discoveryOrdinarySelectionPlan {
	plan := &discoveryOrdinarySelectionPlan{
		testDependencyContext:        context.Background(),
		testDependencyModuleCaptures: make(map[*gotoolprofile.TestDependencyProof]map[string]*discoveryTestModuleCapture),
	}
	for i := 0; i < count; i++ {
		dependency := &gotoolprofile.TestDependencyProof{SourceModules: []gotoolprofile.TestModuleSource{source}}
		copyCapture := *capture // Distinct actual profile captures share the same original bytes.
		plan.testDependencyModuleCaptures[dependency] = map[string]*discoveryTestModuleCapture{source.ID(): &copyCapture}
	}
	return plan
}

func TestTestDependencySnapshotGuardDeduplicatesSameInvocation(t *testing.T) {
	capture, source := testSnapshotGuardCapture(t, 1<<20)
	plan := testSnapshotGuardPlan(capture, source, 8)
	guard := newDiscoveryTestSnapshotGuard()
	rootCalls, zipHashCalls := 0, 0
	guard.verifySource = func(ctx context.Context, source gotoolprofile.TestModuleSource, root, archive string) error {
		rootCalls++
		return gotoolprofile.VerifyTestModuleSource(ctx, source, root, archive)
	}
	guard.zipHash = func(archive string) (string, error) {
		zipHashCalls++
		return discoveryFeatureFileSHA256(archive)
	}
	if err := verifyDiscoveryTestDependencySnapshotWithGuard(plan, capture.Root, guard); err != nil {
		t.Fatal(err)
	}
	if rootCalls != 1 || zipHashCalls != 1 {
		t.Fatalf("eight exact source snapshots in one guard: real complete-root verification calls=%d, snapshot ZIP SHA calls=%d; want 1 each", rootCalls, zipHashCalls)
	}
	t.Logf("eight identical snapshots: actual complete-root checks=%d; actual snapshot ZIP SHA reads=%d", rootCalls, zipHashCalls)
}

func TestTestDependencySnapshotGuardDoesNotSurvivePhase(t *testing.T) {
	capture, source := testSnapshotGuardCapture(t, 4096)
	plan := testSnapshotGuardPlan(capture, source, 8)
	rootCalls := 0
	check := func() error {
		guard := newDiscoveryTestSnapshotGuard()
		guard.verifySource = func(ctx context.Context, source gotoolprofile.TestModuleSource, root, archive string) error {
			rootCalls++
			return gotoolprofile.VerifyTestModuleSource(ctx, source, root, archive)
		}
		return verifyDiscoveryTestDependencySnapshotWithGuard(plan, capture.Root, guard)
	}
	for phase := 0; phase < 2; phase++ {
		if err := check(); err != nil {
			t.Fatal(err)
		}
	}
	if rootCalls != 2 {
		t.Fatalf("independent pre/post phases verified the real root %d times, want 2", rootCalls)
	}
	if err := os.WriteFile(filepath.Join(capture.Root, "source.bin"), []byte("changed asset"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("changed original bytes survived a new guard phase")
	}
}

func TestTestDependencySnapshotGuardChecksEveryMetadataAndExport(t *testing.T) {
	for _, kind := range []string{"export", "original metadata copy"} {
		t.Run(kind, func(t *testing.T) {
			capture, source := testSnapshotGuardCapture(t, 4096)
			dependency := &gotoolprofile.TestDependencyProof{SourceModules: []gotoolprofile.TestModuleSource{source}}
			captures := map[string]*discoveryTestModuleCapture{source.ID(): capture}
			guard := newDiscoveryTestSnapshotGuard()
			rootCalls := 0
			guard.verifySource = func(ctx context.Context, source gotoolprofile.TestModuleSource, root, archive string) error {
				rootCalls++
				return gotoolprofile.VerifyTestModuleSource(ctx, source, root, archive)
			}
			if err := verifyDiscoveryForeignTestSnapshotsWithGuard(context.Background(), dependency, captures, guard); err != nil {
				t.Fatal(err)
			}
			copyPath := filepath.Join(t.TempDir(), "actual-copy")
			bytes := []byte("actual export")
			if kind == "original metadata copy" {
				var err error
				bytes, err = os.ReadFile(capture.Download.GoMod)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(copyPath, bytes, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "export" {
				capture.Exports[copyPath] = discoveryFeatureBytesSHA256(bytes)
			} else {
				capture.Metadata[copyPath] = discoveryFeatureBytesSHA256(bytes)
			}
			if err := verifyDiscoveryForeignTestSnapshotsWithGuard(context.Background(), dependency, captures, guard); err != nil {
				t.Fatalf("same source with an independently guarded actual copy: %v", err)
			}
			if rootCalls != 1 {
				t.Fatalf("copy paths incorrectly changed the original root verification count: %d", rootCalls)
			}
			if err := os.WriteFile(copyPath, []byte("mutated current copy"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := verifyDiscoveryForeignTestSnapshotsWithGuard(context.Background(), dependency, captures, guard); err == nil {
				t.Fatal("a cached original root hid changed per-proof metadata/export bytes")
			}
		})
	}
}

func TestTestDependencySnapshotGuardKeepsPhysicalOriginsSeparate(t *testing.T) {
	for _, kind := range []string{"different root", "different archive"} {
		t.Run(kind, func(t *testing.T) {
			first, source := testSnapshotGuardCapture(t, 4096)
			second := *first
			if kind == "different root" {
				second.Root = t.TempDir()
				var err error
				second.Root, err = filepath.EvalSymlinks(second.Root)
				if err != nil {
					t.Fatal(err)
				}
				for name := range source.Sources {
					bytes, err := os.ReadFile(filepath.Join(first.Root, name))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(second.Root, name), bytes, 0600); err != nil {
						t.Fatal(err)
					}
				}
				second.Download.Dir, second.Download.GoMod = second.Root, filepath.Join(second.Root, "go.mod")
				second.Metadata = map[string]string{second.Download.GoMod: source.GoModSHA256}
			} else {
				second.Download.Zip = filepath.Join(t.TempDir(), "independent-copy.zip")
				bytes, err := os.ReadFile(first.Download.Zip)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(second.Download.Zip, bytes, 0600); err != nil {
					t.Fatal(err)
				}
			}
			guard := newDiscoveryTestSnapshotGuard()
			calls := 0
			guard.verifySource = func(ctx context.Context, source gotoolprofile.TestModuleSource, root, archive string) error {
				calls++
				return gotoolprofile.VerifyTestModuleSource(ctx, source, root, archive)
			}
			dependency := &gotoolprofile.TestDependencyProof{SourceModules: []gotoolprofile.TestModuleSource{source}}
			for _, capture := range []*discoveryTestModuleCapture{first, &second} {
				if err := verifyDiscoveryForeignTestSnapshotsWithGuard(context.Background(), dependency,
					map[string]*discoveryTestModuleCapture{source.ID(): capture}, guard); err != nil {
					t.Fatal(err)
				}
			}
			if calls != 2 {
				t.Fatalf("different physical origins shared a whole-root guard: actual checks=%d", calls)
			}
		})
	}
}

func TestTestDependencySnapshotGuardRejectsChangedTokens(t *testing.T) {
	for _, kind := range []string{"module h1", "ZIP SHA", "header", "directory", "source hash"} {
		t.Run(kind, func(t *testing.T) {
			capture, source := testSnapshotGuardCapture(t, 4096)
			guard := newDiscoveryTestSnapshotGuard()
			dependency := &gotoolprofile.TestDependencyProof{SourceModules: []gotoolprofile.TestModuleSource{source}}
			captures := map[string]*discoveryTestModuleCapture{source.ID(): capture}
			if err := verifyDiscoveryForeignTestSnapshotsWithGuard(context.Background(), dependency, captures, guard); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "module h1":
				capture.Download.Sum = "h1:" + strings.Repeat("A", 43) + "="
			case "ZIP SHA":
				dependency.SourceModules[0].ZipSHA256 = strings.Repeat("a", 64)
			case "header":
				capture.Plan.TestDeclarationSources[0].Header = "package different\n"
			case "directory":
				capture.Plan.TestDeclarationDirectories[0].Entries = capture.Plan.TestDeclarationDirectories[0].Entries[1:]
			case "source hash":
				capture.Plan.TestDeclarationDirectories[0].Entries[0].SHA256 = strings.Repeat("a", 64)
			}
			if kind != "ZIP SHA" {
				current, err := discoveryTestModuleSnapshot(capture)
				if err != nil {
					t.Fatal(err)
				}
				dependency.SourceModules[0] = current // Even consistent altered capture tokens cannot borrow prior checks.
			}
			if err := verifyDiscoveryForeignTestSnapshotsWithGuard(context.Background(), dependency, captures, guard); err == nil {
				t.Fatal("changed same-path tokens acquired an old original-byte verification")
			}
		})
	}
}

func TestTestDependencySnapshotGuardRejectsCanceledAndRedirectedOrigins(t *testing.T) {
	capture, source := testSnapshotGuardCapture(t, 4096)
	dependency := &gotoolprofile.TestDependencyProof{SourceModules: []gotoolprofile.TestModuleSource{source}}
	captures := map[string]*discoveryTestModuleCapture{source.ID(): capture}
	guard := newDiscoveryTestSnapshotGuard()
	if err := verifyDiscoveryForeignTestSnapshotsWithGuard(context.Background(), dependency, captures, guard); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyDiscoveryForeignTestSnapshotsWithGuard(ctx, dependency, captures, guard); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cached source ignored cancellation: %v", err)
	}
	if err := verifyDiscoveryForeignTestSnapshotsWithGuard(nil, dependency, captures, guard); err == nil {
		t.Fatal("a cached source accepted a missing bounded context")
	}
	original := filepath.Join(t.TempDir(), "moved-original-root")
	if err := os.Rename(capture.Root, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(original, capture.Root); err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryForeignTestSnapshotsWithGuard(context.Background(), dependency, captures, guard); err == nil {
		t.Fatal("a cached source authorized a newly redirected physical root")
	}
}

func TestTestDependencySnapshotGuardDoesNotRecordCanceledVerification(t *testing.T) {
	capture, source := testSnapshotGuardCapture(t, 4096)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := newDiscoveryTestSnapshotGuard()
	guard.verifySource = func(ctx context.Context, source gotoolprofile.TestModuleSource, root, archive string) error {
		if err := gotoolprofile.VerifyTestModuleSource(ctx, source, root, archive); err != nil {
			return err
		}
		cancel()
		return nil
	}
	if err := guard.verify(ctx, source, capture); !errors.Is(err, context.Canceled) || len(guard.verified) != 0 {
		t.Fatalf("cancellation recorded a reusable verification: err=%v, cached=%d", err, len(guard.verified))
	}
}

func BenchmarkTestDependencySnapshotGuard(b *testing.B) {
	capture, source := testSnapshotGuardCapture(b, 4<<20)
	plan := testSnapshotGuardPlan(capture, source, 8)
	for _, reuse := range []bool{false, true} {
		name := "same_input_no_reuse"
		if reuse {
			name = "same_input_local_guard"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if reuse {
					if err := verifyDiscoveryTestDependencySnapshot(plan, capture.Root); err != nil {
						b.Fatal(err)
					}
				} else {
					for dependency, captures := range plan.testDependencyModuleCaptures {
						if err := verifyDiscoveryForeignTestSnapshots(context.Background(), dependency, captures); err != nil {
							b.Fatal(err)
						}
					}
				}
			}
		})
	}
}
