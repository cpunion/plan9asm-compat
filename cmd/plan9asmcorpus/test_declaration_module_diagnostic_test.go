package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestTestDependencySourceRootFailureIncludesExactIdentity(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(t.TempDir(), "unverified-fixture.zip")
	if err := os.WriteFile(archive, []byte("not authenticated library code"), 0600); err != nil {
		t.Fatal(err)
	}
	file := "package dependency\n"
	digest := strings.Repeat("a", 64)
	capture := &discoveryTestModuleCapture{
		Root: root,
		Download: moduleDownloadInfo{
			Zip: archive, Sum: "h1:" + strings.Repeat("A", 43) + "=",
			GoModSum: "h1:" + strings.Repeat("B", 43) + "=",
		},
		Plan: &discoveryOrdinarySelectionPlan{
			Module: "example.invalid/dependency", Version: "v1.0.0",
			TestDeclarationDirectories: []ordinarySelectionDirectory{{
				Directory: ".", Entries: []ordinarySelectionEntry{{Name: "source.go", Kind: "file", SHA256: digest}},
			}},
			TestDeclarationSources: []ordinarySelectionSource{{File: "source.go", Header: file}},
		},
	}
	// This is intentionally not an authenticated module. The shape rejection
	// must retain its exact public identity without leaking its private path.
	source, err := discoveryTestModuleSnapshot(capture)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyDiscoveryForeignTestSnapshots(context.Background(),
		&gotoolprofile.TestDependencyProof{SourceModules: []gotoolprofile.TestModuleSource{source}},
		map[string]*discoveryTestModuleCapture{source.ID(): capture})
	if err == nil || !strings.Contains(err.Error(), source.ID()) ||
		!strings.Contains(err.Error(), "external dependency lacks exact ZIP/module/mod source identity") ||
		strings.Contains(err.Error(), root) || strings.Contains(err.Error(), archive) {
		t.Fatalf("source-boundary failure lost its identity/cause or exposed private paths: %v", err)
	}
}
