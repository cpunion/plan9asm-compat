package main

import (
	"archive/zip"
	"context"

	"os"

	"path/filepath"

	"strings"
	"testing"
	"time"
)

func TestOrdinaryProducerProfilesKeepFeatureOnlyAssemblyAndCPPBranches(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.invalid/profile", Version: "v1.0.0", AsmFiles: []string{"probe_amd64.s"}}
	sources := map[string]string{
		"go.mod":        "module example.invalid/profile\n\ngo 1.20\n",
		"probe.go":      "//go:build amd64.v3\n\npackage profile\nfunc probe()\n",
		"probe_amd64.s": "//go:build amd64.v3\n\n#ifdef GOAMD64_v4\nTEXT ·probe(SB),$0-0\nNOP\nRET\n#else\nTEXT ·probe(SB),$0-0\nRET\n#endif\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	plan, profiles, configs, rejected, root, err := captureDiscoveryOrdinaryProfiles(ctx, candidate, download, []string{"linux/amd64"}, t.TempDir(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if root == "" || plan.CPPInputs == nil || len(plan.CPPInputs.Units) != 1 || len(rejected) != 0 {
		t.Fatalf("feature-only source/CPP union was lost: root=%q plan=%#v rejected=%#v", root, plan, rejected)
	}
	levels := make(map[string]bool)
	for _, profile := range profiles {
		levels[profile.Observed.Environment["GOAMD64"]] = true
	}
	if len(profiles) != 3 || !levels["v1"] || !levels["v3"] || !levels["v4"] {
		t.Fatalf("source + CPP-required profiles = %#v", levels)
	}
	_, scopes, err := replayOrdinarySelectionForProfiles(plan, candidate.AsmFiles, profiles)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ordinaryProfileConfigurationKeys(configs, scopes)
	if err != nil || len(keys) != 2 {
		t.Fatalf("production configurations collapsed v3/v4 scopes: %#v %v", configs, err)
	}
	if err := verifyDiscoveryOrdinaryCPP(plan, download.Dir, root, candidate); err != nil {
		t.Fatal(err)
	}
	// The producer still compares original bytes, not self-reported headers.
	writeTestFile(t, filepath.Join(download.Dir, "probe.go"), strings.ReplaceAll(sources["probe.go"], "amd64.v3", "amd64.v1"))
	if err := verifyDiscoveryOrdinaryCPP(plan, download.Dir, root, candidate); err == nil {
		t.Fatal("changed source header retained the original selection proof")
	}
}

func fixtureProfileModuleDownload(t *testing.T, candidate discoveryCandidate, sources map[string]string) moduleDownloadInfo {
	t.Helper()
	dir := t.TempDir()
	archivePath := filepath.Join(t.TempDir(), "source.zip")
	archive, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(archive)
	for file, data := range sources {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, file)), 0755); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(dir, file), data)
		entry, err := writer.Create(candidate.Module + "@" + candidate.Version + "/" + file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return moduleDownloadInfo{Path: candidate.Module, Version: candidate.Version, Dir: dir, GoMod: filepath.Join(dir, "go.mod"), Zip: archivePath}
}
