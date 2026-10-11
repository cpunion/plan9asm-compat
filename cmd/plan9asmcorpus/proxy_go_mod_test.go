package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func fixtureAuthenticatedProxyGoMod(t *testing.T) *gotoolprofile.ProxyGoModProof {
	t.Helper()
	data, err := os.ReadFile("testdata/aez_proxy_go_mod.json")
	if err != nil {
		t.Fatal(err)
	}
	var proof gotoolprofile.ProxyGoModProof
	if err := json.Unmarshal(data, &proof); err != nil {
		t.Fatal(err)
	}
	return &proof
}

// Only protocol accounting is synthetic here. The metadata signature and
// record inclusion are real public evidence; this is not a library pass.
func fixtureLegacyProxyProgress(t *testing.T) discoveryProgress {
	t.Helper()
	progress := fixtureSemanticProgress(t)
	candidate := &progress.Candidates[0]
	metadata := fixtureAuthenticatedProxyGoMod(t)
	plan := candidate.OrdinarySelectionPlan
	candidate.Module, candidate.Version = metadata.Module, metadata.Version
	plan.Module, plan.Version, plan.ModuleSum = metadata.Module, metadata.Version, metadata.ModuleSum
	plan.ProxyGoMod = metadata
	var sources []ordinarySelectionSource
	for _, source := range plan.Sources {
		if source.File != "go.mod" {
			sources = append(sources, source)
		}
	}
	plan.Sources = sources
	for index := range plan.Directories {
		if plan.Directories[index].Directory != "." {
			continue
		}
		var entries []ordinarySelectionEntry
		for _, entry := range plan.Directories[index].Entries {
			if entry.Name != "go.mod" {
				entries = append(entries, entry)
			}
		}
		plan.Directories[index].Entries = entries
	}
	plan.CPPInputs.Module, plan.CPPInputs.Version, plan.CPPInputs.ModuleSum = metadata.Module, metadata.Version, metadata.ModuleSum
	for _, proof := range candidate.FeatureConsumption {
		for index := range proof.Packages {
			pkg := &proof.Packages[index]
			pkg.PackagePath, pkg.ModulePath, pkg.SourceModule = metadata.Module, metadata.Module, metadata.Module
			pkg.ModuleVersion, pkg.SourceVersion = metadata.Version, metadata.Version
			pkg.Macros.PackagePath = metadata.Module
			pkg.GoModOrigin, pkg.GoModSHA256, pkg.GoModSum = metadata.Protocol, metadata.SHA256, metadata.GoModSum
		}
	}
	return progress
}

func TestLegacyProxyMetadataKeepsProducerConsumerAndLedgerContracts(t *testing.T) {
	valid := fixtureLegacyProxyProgress(t)
	if err := requireVerifiedAssemblyLedger(valid); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	if err := writeAssemblyLedger(output, valid, valid.Source.SHA256); err != nil {
		t.Fatal(err)
	}
	restored, err := readAssemblyLedger(output, valid.LedgerSHA256, valid.Source.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := compareAssemblyLedgerProgress(valid, restored); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*discoveryCandidateProgress)
	}{
		{"legacy relabel lacks independent proof", func(c *discoveryCandidateProgress) { c.OrdinarySelectionPlan.ProxyGoMod = nil }},
		{"missing actual metadata role", func(c *discoveryCandidateProgress) { c.FeatureConsumption[0].Packages[0].GoModOrigin = "" }},
		{"missing actual metadata hash", func(c *discoveryCandidateProgress) { c.FeatureConsumption[0].Packages[0].GoModSHA256 = "" }},
		{"wrong actual metadata sum", func(c *discoveryCandidateProgress) {
			c.FeatureConsumption[0].Packages[0].GoModSum = c.OrdinarySelectionPlan.ModuleSum
		}},
		{"unsigned tree", func(c *discoveryCandidateProgress) { c.OrdinarySelectionPlan.ProxyGoMod.SignedTree = "" }},
		{"no inclusion", func(c *discoveryCandidateProgress) { c.OrdinarySelectionPlan.ProxyGoMod.Inclusion = nil }},
		{"metadata of another version", func(c *discoveryCandidateProgress) { c.OrdinarySelectionPlan.ProxyGoMod.Version = "v1.0.0" }},
		{"metadata of another ZIP", func(c *discoveryCandidateProgress) {
			c.OrdinarySelectionPlan.ModuleSum = c.OrdinarySelectionPlan.ProxyGoMod.GoModSum
		}},
		{"fake ZIP member", func(c *discoveryCandidateProgress) {
			c.OrdinarySelectionPlan.Sources = append(c.OrdinarySelectionPlan.Sources, ordinarySelectionSource{File: "go.mod"})
		}},
		{"fake original directory member", func(c *discoveryCandidateProgress) {
			c.OrdinarySelectionPlan.Directories[0].Entries = append(c.OrdinarySelectionPlan.Directories[0].Entries, ordinarySelectionEntry{Name: "go.mod", Kind: "file"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := cloneSemanticProgress(t, valid)
			test.mutate(&mutated.Candidates[0])
			if err := requireVerifiedAssemblyLedger(mutated); err == nil {
				t.Fatal("legacy metadata bypassed producer/consumer/ledger proof closure")
			}
		})
	}
}

func TestLegacyProxyMetadataGuardRetainsPreLoadHash(t *testing.T) {
	progress := fixtureLegacyProxyProgress(t)
	plan := progress.Candidates[0].OrdinarySelectionPlan
	metadata := filepath.Join(t.TempDir(), "metadata.mod")
	if err := os.WriteFile(metadata, []byte(plan.ProxyGoMod.Contents), 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err := filepath.EvalSymlinks(metadata)
	if err != nil {
		t.Fatal(err)
	}
	plan.proxyGoModPath = metadata
	if err := verifyDiscoveryProxyGoMod(plan); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadata, []byte("module example.invalid/changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryProxyGoMod(plan); err == nil {
		t.Fatal("native package checks could change metadata after authentication")
	}
}

func TestLegacyProxyMetadataComparesIndependentSignedCheckpoints(t *testing.T) {
	first := fixtureLegacyProxyProgress(t)
	later := cloneSemanticProgress(t, first)
	data, err := os.ReadFile("testdata/aez_proxy_go_mod_later_tree.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, later.Candidates[0].OrdinarySelectionPlan.ProxyGoMod); err != nil {
		t.Fatal(err)
	}
	if err := requireVerifiedAssemblyLedger(later); err != nil {
		t.Fatal(err)
	}
	if err := compareAssemblyLedgerProgress(first, later); err != nil {
		t.Fatalf("independently authenticated checkpoints for the same record differ: %v", err)
	}
	later.Candidates[0].OrdinarySelectionPlan.ProxyGoMod.Inclusion = nil
	if err := compareAssemblyLedgerProgress(first, later); err == nil {
		t.Fatal("semantic comparison accepted an unauthenticated checkpoint")
	}
}
