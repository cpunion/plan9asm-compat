package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileProtocolEntryPointsUseStrictCurrentReaders(t *testing.T) {
	if discoveryReportSchema != 12 || discoveryProgressSchema != 3 || assemblyLedgerFormat != "module-hashed-assembly-ledger-v3" {
		t.Fatal("profile-aware producer, progress and ledger protocols must advance together")
	}
	root := filepath.Join("..", "..")
	for name, flags := range map[string][]string{
		"check-discovered-library-corpus.sh":  {"./cmd/plan9asmcorpus", "-discovery-report=", "-discovery-shard-count="},
		"verify-discovered-library-corpus.sh": {"./cmd/plan9asmcorpus", "-verify-discovery-reports", "-compare-assembly-ledger"},
		"discovery-status.sh":                 {"./cmd/plan9asmcorpus", "-discovery-progress", "-discovery-shard-count"},
		"update-assembly-ledger.sh":           {"./cmd/plan9asmcorpus", "-write-assembly-ledger", "-assembly-ledger-status"},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, "scripts", name))
			if err != nil {
				t.Fatal(err)
			}
			for _, flag := range flags {
				if !strings.Contains(string(data), flag) {
					t.Fatalf("script bypasses current strict CLI reader: missing %s", flag)
				}
			}
			if strings.Contains(string(data), "module-hashed-assembly-ledger-v1") {
				t.Fatal("script still routes to an obsolete ledger protocol")
			}
		})
	}
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "go-ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []string{"scripts/verify-discovered-library-corpus.sh", "-require-verified-assembly-ledger"} {
		if !strings.Contains(string(workflow), check) {
			t.Fatalf("CI omitted a strict report or ledger gate: %s", check)
		}
	}
	guide, err := os.ReadFile(filepath.Join(root, "docs", "development", "validation.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(guide), "all 128 schema-12 reports") || strings.Contains(string(guide), "schema-10 reports") {
		t.Fatal("frozen validation guide requires an obsolete discovery protocol")
	}
}
