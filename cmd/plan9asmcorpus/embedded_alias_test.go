package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryEmbeddedAliasManifestRequiresExactInspectedModule(t *testing.T) {
	repoRoot := t.TempDir()
	manifestDir := filepath.Join(repoRoot, "testdata", "corpus")
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		t.Fatal(err)
	}
	alias := discoveryEmbeddedModuleAlias{
		Module:       "example.com/fork",
		Version:      "v1.2.3",
		ModuleSum:    "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		SourceDir:    "nested",
		ImportModule: "example.com/original",
		EvidenceURL:  "https://example.com/fork/tree/v1.2.3/nested",
	}
	writeManifest := func(aliases []discoveryEmbeddedModuleAlias) {
		t.Helper()
		data, err := json.Marshal(discoveryEmbeddedModuleManifest{
			SchemaVersion: 1, Aliases: aliases,
		})
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(manifestDir, "embedded-modules.json"), string(data))
	}
	known := []discoveryCandidate{{Module: alias.Module, Version: alias.Version}}
	writeManifest([]discoveryEmbeddedModuleAlias{alias})
	got, err := loadDiscoveryEmbeddedModuleAliases(repoRoot, known)
	if err != nil || got[alias.Module+"@"+alias.Version] != alias {
		t.Fatalf("valid embedded alias = %#v, %v", got, err)
	}

	for _, change := range []struct {
		name string
		edit func(*discoveryEmbeddedModuleAlias)
	}{
		{"unknown version", func(a *discoveryEmbeddedModuleAlias) { a.Version = "v1.2.4" }},
		{"checksum", func(a *discoveryEmbeddedModuleAlias) { a.ModuleSum = "h1:invalid" }},
		{"source escape", func(a *discoveryEmbeddedModuleAlias) { a.SourceDir = "../outside" }},
		{"same import module", func(a *discoveryEmbeddedModuleAlias) { a.ImportModule = a.Module }},
		{"non-HTTPS evidence", func(a *discoveryEmbeddedModuleAlias) { a.EvidenceURL = "http://example.com" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := alias
			change.edit(&changed)
			writeManifest([]discoveryEmbeddedModuleAlias{changed})
			if _, err := loadDiscoveryEmbeddedModuleAliases(repoRoot, known); err == nil {
				t.Fatal("invalid embedded-module alias was accepted")
			}
		})
	}
	writeManifest([]discoveryEmbeddedModuleAlias{alias, alias})
	if _, err := loadDiscoveryEmbeddedModuleAliases(repoRoot, known); err == nil {
		t.Fatal("duplicate embedded-module alias was accepted")
	}
}

func TestCuratedEmbeddedAliasesMatchDiscoveryLedger(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	candidates, err := loadDiscoveryCandidates(filepath.Join(repoRoot, "testdata", "discovery", "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	aliases, err := loadDiscoveryEmbeddedModuleAliases(repoRoot, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(aliases) != 2 {
		t.Fatalf("embedded aliases = %d, want 2", len(aliases))
	}
	for _, modulePath := range []string{
		"github.com/EthanGYoung/ContainerFS",
		"github.com/ethangyoung/containerfs",
	} {
		key := modulePath + "@v0.0.0-20190824181837-c8de36334a9e"
		if aliases[key].SourceDir != "ContainerFS" {
			t.Fatalf("missing exact embedded alias for %s", key)
		}
	}
}

func TestDiscoveryEmbeddedAliasCopiesPinnedModuleSource(t *testing.T) {
	moduleDir := t.TempDir()
	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(moduleDir, "nested", "pkg", "dep"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(moduleDir, "nested", "pkg", "dep", "dep.go"),
		"package dep\nconst Value = 42\n")

	alias := discoveryEmbeddedModuleAlias{
		Module:       "example.com/fork",
		Version:      "v1.2.3",
		ModuleSum:    "h1:example-pinned-sum",
		SourceDir:    "nested",
		ImportModule: "example.com/original",
	}
	download := moduleDownloadInfo{
		Path: alias.Module, Version: alias.Version,
		Dir: moduleDir, Sum: alias.ModuleSum,
	}
	if err := prepareDiscoveryEmbeddedAlias(workDir, download, alias); err != nil {
		t.Fatal(err)
	}
	copyDir := filepath.Join(workDir, "embedded-module-alias")
	contents, err := os.ReadFile(filepath.Join(copyDir, "pkg", "dep", "dep.go"))
	if err != nil || string(contents) != "package dep\nconst Value = 42\n" {
		t.Fatalf("copied embedded package = %q, %v", contents, err)
	}
	goMod, err := os.ReadFile(filepath.Join(copyDir, "go.mod"))
	if err != nil || string(goMod) != "module example.com/original\n\ngo 1.27\n" {
		t.Fatalf("embedded go.mod = %q, %v", goMod, err)
	}
	if _, err := os.Stat(filepath.Join(moduleDir, "nested", "go.mod")); !os.IsNotExist(err) {
		t.Fatalf("downloaded source was modified: %v", err)
	}

	plan, err := makeDiscoveryExecutionPlan(discoveryCandidate{
		Module: alias.Module, Version: alias.Version,
	}, alias.Module)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = addDiscoveryEmbeddedAliasToPlan(plan, alias)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"require example.com/original v0.0.0",
		"replace example.com/original => ./embedded-module-alias",
	} {
		if !strings.Contains(plan.GoMod, want) {
			t.Fatalf("go.mod missing %q:\n%s", want, plan.GoMod)
		}
	}
}

func TestDiscoveryEmbeddedAliasRejectsUnpinnedOrEscapingSource(t *testing.T) {
	moduleDir := t.TempDir()
	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(moduleDir, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(moduleDir, "nested", "dep.go"), "package nested\n")
	alias := discoveryEmbeddedModuleAlias{
		Module:       "example.com/fork",
		Version:      "v1.2.3",
		ModuleSum:    "h1:expected",
		SourceDir:    "nested",
		ImportModule: "example.com/original",
	}
	download := moduleDownloadInfo{
		Path: alias.Module, Version: alias.Version,
		Dir: moduleDir, Sum: "h1:changed",
	}
	if err := prepareDiscoveryEmbeddedAlias(workDir, download, alias); err == nil {
		t.Fatal("mismatched module checksum was accepted")
	}
	if _, err := os.Stat(filepath.Join(workDir, "embedded-module-alias")); !os.IsNotExist(err) {
		t.Fatalf("rejected alias created a workspace: %v", err)
	}

	download.Sum = alias.ModuleSum
	alias.SourceDir = "../outside"
	if err := prepareDiscoveryEmbeddedAlias(workDir, download, alias); err == nil {
		t.Fatal("escaping embedded source was accepted")
	}
	alias.SourceDir = "nested"
	writeTestFile(t, filepath.Join(moduleDir, "nested", "go.mod"),
		"module example.com/other\n")
	if err := prepareDiscoveryEmbeddedAlias(workDir, download, alias); err == nil {
		t.Fatal("nested module with an unrelated go.mod was overwritten")
	}
}
