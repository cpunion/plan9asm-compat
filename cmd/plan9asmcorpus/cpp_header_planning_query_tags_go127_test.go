//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCPPHeaderPlanningQueryGoOnlyTagsActualEmbed(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.invalid/queryembed", Version: "v1.0.0",
		AsmFiles: []string{"probe_amd64.s", "second/probe_amd64.s"}}
	sources := map[string]string{
		"go.mod":                  "module example.invalid/queryembed\ngo 1.20\n",
		"probe.go":                "package queryembed\nfunc Probe() uint64\n",
		"base.go":                 "//go:build !alternate\n\npackage queryembed\nconst Answer = 7\n",
		"alternate.go":            "//go:build alternate\n\npackage queryembed\nimport _ \"example.invalid/queryembed/internal/data\"\nconst Answer = 11\n",
		"internal/data/value.go":  "package data\nimport _ \"embed\"\n//go:embed value.bin\nvar Value []byte\n",
		"internal/data/value.bin": "original ordinary dependency asset\n",
		"probe_amd64.s":           "#include \"go_asm.h\"\n#include \"textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-8\nMOVQ $const_Answer,ret+0(FP)\nRET\n",
		"second/base.go":          "//go:build !(alpha && beta)\n\npackage second\nconst Answer = 19\nfunc Probe() uint64\n",
		"second/combination.go":   "//go:build alpha && beta\n\npackage second\nconst Answer = 23\nfunc Probe() uint64\n",
		"second/probe_amd64.s":    "//go:build alpha && beta\n\n#include \"go_asm.h\"\n#include \"textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-8\nMOVQ $const_Answer,ret+0(FP)\nRET\n",
	}
	compilerEnv := os.Environ()
	download := fixtureProfileModuleDownload(t, candidate, sources)
	installGeneratedFixtureProxy(t, candidate, download, sources["go.mod"])
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "plan9asmll")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", binary, ".")
	command.Dir, command.Env = filepath.Join(root, "cmd", "plan9asmll"), compilerEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build owned translator: %v\n%s", err, output)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{"darwin/amd64", "linux/amd64", "windows/amd64"}
	// Each target retains all original baseline, embed and combined-tag
	// queries, followed by nine final object consumers. The former three-
	// minute whole-candidate budget expired during the last target's planning.
	// This is a correctness-fixture budget, not a production or benchmark limit.
	started := time.Now()
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: binary, LLC: llc, Targets: targets, CandidateTimeout: 6 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatalf("Go-only tag planning must bind actual original dependency embeds and registration: %v", err)
	}
	plan := matrix.OrdinarySelectionPlan
	// The Go-only alternate scope needs its own final original Go/LLVM
	// object, not just a successful planning query for a baseline object.
	if matrix.Success != 3*len(targets) || plan == nil || plan.HeaderPlanning == nil {
		t.Fatal("actual metadata planning and final LLVM consumer evidence are both required")
	}
	seen := make(map[string]bool)
	scopes := make(map[string]bool)
	for _, query := range plan.HeaderPlanning.Queries {
		key := discoveryHeaderPlanningKey(query.Profile.Request, query.Assembly, query.BuildTags)
		if seen[key] || query.Metadata == nil || len(query.Metadata.Headers) != 1 {
			t.Fatalf("duplicate/incomplete actual query: %s", key)
		}
		seen[key] = true
		scopes[query.Profile.Request.Target+"/"+query.Assembly+"/"+strings.Join(query.BuildTags, "+")] = true
		header := query.Metadata.Headers[0]
		selected, excluded, answer := "base.go", "alternate.go", "7"
		if query.Assembly == "second/probe_amd64.s" {
			selected, excluded, answer = "second/combination.go", "second/base.go", "23"
			if !equalDiscoveryStrings(query.BuildTags, []string{"alpha", "beta"}) {
				t.Fatal("second package borrowed the first package's custom-tag scope")
			}
		} else if len(query.BuildTags) != 0 {
			selected, excluded, answer = "alternate.go", "base.go", "11"
			if !equalDiscoveryStrings(query.BuildTags, []string{"alternate"}) {
				t.Fatal("first package borrowed the second package's custom-tag scope")
			}
			if query.Metadata.Dependencies.Candidate.Sources["internal/data/value.bin"] == "" {
				t.Fatal("tag-selected dependency lost original embed asset evidence")
			}
		}
		if header.Definitions["const_Answer"] != answer || header.CompiledGoSHA256[selected] == "" || header.CompiledGoSHA256[excluded] != "" {
			t.Fatalf("actual source/header selection differs from query %s: %+v", key, header.CompiledGoSHA256)
		}
	}
	for _, target := range targets {
		for _, suffix := range []string{"/probe_amd64.s/", "/probe_amd64.s/alternate", "/second/probe_amd64.s/alpha+beta"} {
			if !scopes[target+suffix] {
				t.Fatalf("missing actual package/custom-tag observation: %s%s", target, suffix)
			}
		}
	}
	if len(scopes) != 3*len(targets) {
		t.Fatalf("unexpected package/tag scope expansion: %d", len(scopes))
	}
	inventory, refs := fixtureOrdinaryMatrixFeatureInventory(t, matrix)
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: candidate.AsmFiles,
		BuildConfigurations: configs, Translations: matrix.Success, OrdinarySelectionPlan: plan,
		FeatureProfiles: refs, FeatureConsumption: matrix.FeatureConsumption, featureInventory: inventory,
	}
	if err := validateOrdinaryProfileResult(result, targets, plan.GoVersion); err != nil {
		t.Fatalf("full actual query/consumer/LLVM replay: %v", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, axis := range []string{"query tags", "query source", "query value", "consumer tags"} {
		t.Run(axis, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			changed.featureInventory = inventory
			switch axis {
			case "query tags":
				changed.OrdinarySelectionPlan.HeaderPlanning.Queries[0].BuildTags = []string{"borrowed"}
			case "query source":
				changed.OrdinarySelectionPlan.HeaderPlanning.Sources["base.go"] += "// changed\n"
			case "query value":
				changed.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Metadata.Headers[0].Definitions["const_Answer"] = "99"
			case "consumer tags":
				changed.FeatureConsumption[0].CustomTags = []string{"borrowed"}
			}
			if err := validateOrdinaryProfileResult(changed, targets, plan.GoVersion); err == nil {
				t.Fatal("mutated source/tag projection borrowed another planning or execution scope")
			}
		})
	}
	t.Logf("query-tag closure: %d actual metadata queries, %d LLVM22 objects, %d targets; candidate elapsed %s",
		len(seen), matrix.Success, len(targets), time.Since(started))
}
