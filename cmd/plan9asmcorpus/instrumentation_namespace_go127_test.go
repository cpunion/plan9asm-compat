//go:build go1.27

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestInstrumentationCorpusOriginalVersionedAliasReachesStrictObjects(t *testing.T) {
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	translator := filepath.Join(t.TempDir(), "plan9asmll")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	_, stderr, err := gotoolprofile.RunBounded(ctx, filepath.Join(root, "cmd", "plan9asmll"), os.Environ(),
		"go", "build", "-p=1", "-o", translator, ".")
	if err != nil {
		t.Fatalf("build current translator: %v\n%s", err, stderr)
	}
	testInstrumentationCorpusOriginalMode(t, root, translator, "race", "1", "darwin/arm64", true,
		"example.invalid/instrumented-mirror")
}

func testInstrumentationAliasHeaderQueryScopes(t *testing.T, plan *discoveryInstrumentationPlan, cgo string) {
	t.Helper()
	if plan.HeaderPlanning == nil || len(plan.HeaderPlanning.Queries) != 32 {
		t.Fatal("alias fixture lost its complete 32-query ARM64 CPU denominator")
	}
	expected := instrumentationARM64QueryFixtureCPUs()
	seen := make(map[string]bool)
	for _, query := range plan.HeaderPlanning.Queries {
		if query.Observation == nil || query.Observation.Early == nil ||
			query.Metadata == nil || len(query.Metadata.Headers) != 1 {
			t.Fatal("alias fixture lost an actual observation/native header")
		}
		cpu := query.Observation.Early.Environment["GOARM64"]
		if seen[cpu] || !containsTargetFeature(expected, cpu) ||
			query.Requirement.Target != "darwin/arm64" || query.Requirement.CGO != cgo ||
			query.Requirement.Mode != gotoolprofile.InstrumentationRace ||
			query.Metadata.Headers[0].Header.Definitions["const_answer"] != "41" ||
			query.PackagePlan.PackagePath != "example.invalid/instrumented" {
			t.Fatalf("alias fixture changed or duplicated actual CPU/header/namespace scope %q", cpu)
		}
		seen[cpu] = true
	}
	t.Logf("ALIAS_COMPLETE_CPU_QUERIES actual=%d; these queries are not LLVM object credit", len(seen))
}
