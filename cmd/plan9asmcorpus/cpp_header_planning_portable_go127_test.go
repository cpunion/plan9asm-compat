//go:build go1.27

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func assertCPPHeaderPlanningActualPortable(t *testing.T, candidate discoveryCandidate, matrix matrixReport, configs []discoveryBuildConfiguration, targets []string) {
	t.Helper()
	plan := matrix.OrdinarySelectionPlan
	if plan == nil || plan.HeaderPlanning == nil || plan.headerPlanningQueryStarts != len(plan.HeaderPlanning.Queries) ||
		len(plan.HeaderPlanning.Sources) != 1 || len(plan.GeneratedHeaders) != len(targets) {
		t.Fatalf("planning observations were lost or confused with executed scopes: %#v", plan.HeaderPlanning)
	}
	inventory, refs := fixtureOrdinaryMatrixFeatureInventory(t, matrix)
	assertCPPHeaderPlanningActualBaselineScopes(t, candidate, matrix, configs, targets, refs)
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: candidate.AsmFiles, BuildConfigurations: configs,
		Translations: matrix.Success, OrdinarySelectionPlan: plan, FeatureProfiles: refs, FeatureConsumption: matrix.FeatureConsumption,
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	replay := func(data []byte) error {
		var actual discoveryCorpusResult
		if err := json.Unmarshal(data, &actual); err != nil {
			return err
		}
		actual.featureInventory = inventory
		return validateOrdinaryProfileResult(actual, targets, plan.GoVersion)
	}
	if err := replay(encoded); err != nil {
		t.Fatalf("full11 actual original/header/query/CPP/LLVM portable replay: %v", err)
	}
	// This condition-free fixture has the same actual baseline observations
	// in planning and execution. The independent formal/generated-include
	// fixture retains assertCPPHeaderPlanningQueryInventoryRequired and its
	// real query-only inventory deletion control; none is invented here.
	mutations := map[string]func(*discoveryCorpusResult){
		"paired role deletion":   func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.HeaderPlanning = nil },
		"protocol downgrade":     func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.HeaderPlanning.Protocol = "legacy" },
		"paired source deletion": func(r *discoveryCorpusResult) { delete(r.OrdinarySelectionPlan.HeaderPlanning.Sources, "probe.go") },
		"source bytes changed": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Sources["probe.go"] += "// late mutation\n"
		},
		"extra original source": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Sources["extra.go"] = "package header\n"
		},
		"query deletion": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Queries = r.OrdinarySelectionPlan.HeaderPlanning.Queries[1:]
		},
		"all queries deleted": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.HeaderPlanning.Queries = nil },
		"duplicate query": func(r *discoveryCorpusResult) {
			role := r.OrdinarySelectionPlan.HeaderPlanning
			role.Queries = append(role.Queries, role.Queries[0])
		},
		"extra unconsumed query": func(r *discoveryCorpusResult) {
			role := r.OrdinarySelectionPlan.HeaderPlanning
			query := role.Queries[0]
			query.Assembly = "extra.s"
			role.Queries = append(role.Queries, query)
		},
		"query requested CPU": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Profile.Request.Overrides = map[string]string{"GOAMD64": "v4"}
		},
		"query selected tags": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].BuildTags = []string{"unobserved"}
		},
		"query actual profile": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Profile.ID = strings.Repeat("1", 64)
		},
		"query language": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Metadata.Headers[0].LanguageVersion = "go1.27"
		},
		"query selected source hash": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Metadata.Headers[0].CompiledGoSHA256["probe.go"] = strings.Repeat("1", 64)
		},
		"paired complete header mutation": func(r *discoveryCorpusResult) {
			header := &r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Metadata.Headers[0]
			header.Definitions["Record__size"] = "16"
			header.DefinitionsSHA256 = gotoolprofile.HeaderDefinitionSHA256(header.Definitions)
			canonical, err := gotoolprofile.CanonicalGeneratedHeader(header.Definitions)
			if err != nil {
				t.Fatal(err)
			}
			header.HeaderSHA256 = discoveryFeatureBytesSHA256(canonical)
		},
		"SDK source rules deleted": func(r *discoveryCorpusResult) {
			delete(r.OrdinarySelectionPlan.HeaderPlanning.Rules.SourceSHA256, "src/cmd/compile/internal/types/size.go")
		},
		"SDK rule paired substitution":           func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.HeaderPlanning.Rules.GoVersion = "go1.20.14" },
		"planning is not execution":              func(r *discoveryCorpusResult) { r.FeatureConsumption = nil; r.Translations = 0 },
		"planning cannot replace executed query": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.GeneratedHeaders = nil },
	}
	if plan.HeaderPlanning.Queries[0].Metadata.Headers[0].ImportMap["unsafe"] == "unsafe" {
		mutations["builtin import paired deletion"] = func(r *discoveryCorpusResult) {
			delete(r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Metadata.Headers[0].ImportMap, "unsafe")
		}
		mutations["builtin import rewrite"] = func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Metadata.Headers[0].ImportMap["unsafe"] = "example.invalid/unsafe"
		}
		mutations["builtin import extra unconsumed edge"] = func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Metadata.Headers[0].ImportMap["fmt"] = "fmt"
		}
	}
	if len(plan.HeaderPlanning.Queries[0].Metadata.Headers[0].Imports) != 0 {
		mutations["independent import paired deletion"] = func(r *discoveryCorpusResult) {
			header := &r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Metadata.Headers[0]
			delete(header.ImportMap, header.Imports[0].ImportPath)
			header.Imports = header.Imports[1:]
		}
		mutations["independent import source role deletion"] = func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Metadata.Headers[0].Imports[0].GoSHA256 = nil
		}
		mutations["independent import export deletion"] = func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Metadata.Headers[0].Imports[0].ExportSHA256 = ""
		}
		mutations["independent import unobserved map edge"] = func(r *discoveryCorpusResult) {
			header := &r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Metadata.Headers[0]
			header.ImportMap[header.Imports[0].ImportPath] = "example.invalid/unobserved"
		}
	}
	if len(plan.HeaderPlanning.ImportedSources) != 0 {
		mutations["planning imported role deletion"] = func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.ImportedSources = nil
		}
		mutations["planning imported paired role deletion"] = func(r *discoveryCorpusResult) {
			role := r.OrdinarySelectionPlan.HeaderPlanning
			role.ImportedSources = nil
			for index := range role.Queries {
				role.Queries[index].ImportedGoSHA256 = nil
			}
		}
		mutations["planning imported query reassignment"] = func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].ImportedGoSHA256 = map[string]string{
				"probe.go": discoveryFeatureBytesSHA256([]byte(r.OrdinarySelectionPlan.HeaderPlanning.Sources["probe.go"])),
			}
		}
		mutations["planning imported unconsumed source"] = func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.ImportedSources["extra/value.go"] = "package extra\n"
		}
		mutations["planning imported source mutation"] = func(r *discoveryCorpusResult) {
			for file := range r.OrdinarySelectionPlan.HeaderPlanning.ImportedSources {
				r.OrdinarySelectionPlan.HeaderPlanning.ImportedSources[file] += "// changed\n"
			}
		}
		mutations["planning imported version mutation"] = func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].Metadata.Headers[0].Imports[0].Version = "v9.0.0"
		}
		mutations["planning imported source-map mutation"] = func(r *discoveryCorpusResult) {
			for file := range r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].ImportedGoSHA256 {
				r.OrdinarySelectionPlan.HeaderPlanning.Queries[0].ImportedGoSHA256[file] = strings.Repeat("1", 64)
			}
		}
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			data, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if err := replay(data); err == nil {
				t.Fatal("erased/forged native planning authority passed full original portable replay")
			}
		})
	}
	// The same complete actual result crosses the report, progress and ledger
	// readers. These first-party fixture headers are not external provenance.
	assertCPPHeaderPlanningReportTransport(t, result, inventory, targets)
	physical := discoveryProgress{Provenance: &discoveryCorpusProvenance{}, FeatureInventory: inventory,
		Candidates: []discoveryCandidateProgress{{OrdinarySelectionPlan: plan, FeatureConsumption: result.FeatureConsumption}}}
	view, err := semanticAssemblyLedgerProgress(physical)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(view.Candidates[0].OrdinarySelectionPlan.HeaderPlanning.Sources, plan.HeaderPlanning.Sources) ||
		!reflect.DeepEqual(view.Candidates[0].OrdinarySelectionPlan.HeaderPlanning.ImportedSources, plan.HeaderPlanning.ImportedSources) ||
		!reflect.DeepEqual(view.Candidates[0].OrdinarySelectionPlan.HeaderPlanning.Rules, plan.HeaderPlanning.Rules) {
		t.Fatal("semantic projection lost complete original bytes or source rules")
	}
	for _, query := range view.Candidates[0].OrdinarySelectionPlan.HeaderPlanning.Queries {
		if query.Metadata.ProfileID != query.Profile.ID || query.Metadata.Headers[0].ObjectSHA256 != "" {
			t.Fatal("query semantic identity kept physical objects or lost source-bound profiles")
		}
	}
	if output := os.Getenv("PLAN9ASM_HEADER_PLANNING_ARTIFACTS"); output != "" {
		if err := os.MkdirAll(output, 0700); err != nil {
			t.Fatal(err)
		}
		for name, value := range map[string]any{"result.json": result, "inventory.json": inventory} {
			body, err := json.MarshalIndent(value, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(output, name), body, 0600); err != nil {
				t.Fatal(err)
			}
			t.Logf("NATIVE_HEADER_PLANNING_SIZE artifact=%s bytes=%d sha256=%s", name, len(body), discoveryFeatureBytesSHA256(body))
		}
	}
	roleBytes, err := json.Marshal(plan.HeaderPlanning)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NATIVE_HEADER_PLANNING_FULL11 queries=%d source_copies=%d role_bytes=%d executed_headers=%d LLVM_objects=%d", len(plan.HeaderPlanning.Queries), len(plan.HeaderPlanning.Sources), len(roleBytes), len(plan.GeneratedHeaders), matrix.Success)
}

func assertCPPHeaderPlanningActualBaselineScopes(t *testing.T, candidate discoveryCandidate, matrix matrixReport,
	configs []discoveryBuildConfiguration, targets []string, refs []discoveryFeatureProfileReference) {
	t.Helper()
	plan := matrix.OrdinarySelectionPlan
	wantedTargets := uniqueSortedDiscoveryStrings(targets)
	if len(wantedTargets) != len(targets) || len(refs) != len(targets) || len(configs) != len(targets) ||
		len(plan.HeaderPlanning.Queries) != len(refs) || !equalDiscoveryStrings(plan.Targets, wantedTargets) {
		t.Fatalf("condition-free planning/execution differs from the complete requested target inventory: "+
			"refs=%d configurations=%d queries=%d starts=%d requested=%q canonical=%q",
			len(refs), len(configs), len(plan.HeaderPlanning.Queries), plan.headerPlanningQueryStarts, targets, plan.Targets)
	}
	expected := make(map[string]discoveryFeatureProfileReference, len(targets))
	for _, ref := range refs {
		if _, duplicate := expected[ref.Request.Target]; duplicate || !containsTargetFeature(targets, ref.Request.Target) ||
			!ref.Request.Baseline || len(ref.Request.Overrides) != 0 || len(ref.Request.Expected) != 0 {
			t.Fatalf("fixture acquired a duplicate, foreign or nonbaseline actual request: %+v", ref)
		}
		expected[ref.Request.Target] = ref
	}
	seen := make(map[string]bool, len(targets))
	for _, query := range plan.HeaderPlanning.Queries {
		ref, present := expected[query.Profile.Request.Target]
		if !present || seen[ref.Request.Target] || !reflect.DeepEqual(query.Profile, ref) ||
			query.Assembly != candidate.AsmFiles[0] || len(query.BuildTags) != 0 || query.Metadata == nil ||
			query.Metadata.ProfileID != ref.ID || len(query.Metadata.Headers) != 1 ||
			query.Metadata.Headers[0].Target != ref.Request.Target {
			t.Fatalf("planning query lost its unique real baseline/source/profile binding: %+v", query)
		}
		seen[ref.Request.Target] = true
	}
	seen = make(map[string]bool, len(targets))
	for _, config := range configs {
		if len(config.Targets) != 1 {
			t.Fatalf("actual configuration lost its exact individual target: %+v", config)
		}
		ref, present := expected[config.Targets[0]]
		if !present || seen[ref.Request.Target] || config.ProfileID != ref.ID || len(config.BuildTags) != 0 ||
			!equalDiscoveryStrings(config.AsmFiles, candidate.AsmFiles) {
			t.Fatalf("actual configuration differs from its planning baseline/source: %+v", config)
		}
		seen[ref.Request.Target] = true
	}
	seen = make(map[string]bool, len(targets))
	for _, query := range plan.GeneratedHeaders {
		ref, present := expected[query.Target]
		if !present || seen[ref.Request.Target] || query.ProfileID != ref.ID || len(query.BuildTags) != 0 ||
			!equalDiscoveryStrings(query.AsmFiles, candidate.AsmFiles) || query.Metadata == nil ||
			query.Metadata.ProfileID != ref.ID || len(query.Metadata.Headers) != 1 ||
			query.Metadata.Headers[0].Target != ref.Request.Target {
			t.Fatalf("executed metadata differs from the unique actual target/profile/source: %+v", query)
		}
		seen[ref.Request.Target] = true
	}
}

func assertCPPHeaderPlanningQueryInventoryRequired(t *testing.T, result discoveryCorpusResult, inventory *discoveryFeatureInventory, targets []string) {
	t.Helper()
	plan := result.OrdinarySelectionPlan
	if plan == nil || plan.HeaderPlanning == nil {
		t.Fatal("actual generated-header fixture lost its planning-only role")
	}
	executed := make(map[string]bool)
	for _, reference := range result.FeatureProfiles {
		executed[reference.ID] = true
	}
	queryOnly := make(map[string]bool)
	for _, query := range plan.HeaderPlanning.Queries {
		if !executed[query.Profile.ID] {
			queryOnly[query.Profile.ID] = true
		}
	}
	ids := sortedDiscoverySet(queryOnly)
	if len(ids) == 0 {
		t.Fatal("fixture has no independent query-only observation to remove")
	}
	t.Run("missing_query_only_inventory", func(t *testing.T) {
		// Cross the JSON boundary so the producer's private inventory and
		// capture callback cannot repair the deliberately missing record.
		encoded, err := json.Marshal(struct {
			Result    discoveryCorpusResult
			Inventory *discoveryFeatureInventory
		}{result, inventory})
		if err != nil {
			t.Fatal(err)
		}
		var missing struct {
			Result    discoveryCorpusResult
			Inventory *discoveryFeatureInventory
		}
		if err := json.Unmarshal(encoded, &missing); err != nil {
			t.Fatal(err)
		}
		delete(missing.Inventory.Observations, ids[0])
		if _, err := resolveDiscoveryFeatureProfiles(missing.Inventory, missing.Result.FeatureProfiles); err != nil {
			t.Fatalf("query-only deletion changed executed profile transport: %v", err)
		}
		missing.Result.featureInventory = missing.Inventory
		err = validateOrdinaryProfileResult(missing.Result, targets, plan.GoVersion)
		if err == nil || !strings.Contains(err.Error(), "unresolved or duplicate source-required feature reference "+ids[0]) {
			t.Fatalf("missing query-only profile did not fail the independent ordinary reader: %v", err)
		}
	})
}

func assertCPPHeaderPlanningReportTransport(t *testing.T, result discoveryCorpusResult, inventory *discoveryFeatureInventory, targets []string) {
	t.Helper()
	ledger := filepath.Join(t.TempDir(), "scan")
	if err := os.MkdirAll(filepath.Join(ledger, "records"), 0700); err != nil {
		t.Fatal(err)
	}
	record := discoveryRecord{Kind: "matched", Module: result.Module, Version: result.Version,
		Architectures: []string{"386", "amd64", "arm", "arm64", "wasm"}, AsmFiles: result.DiscoveredAsmFiles}
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(ledger, "records", "source.jsonl"), string(body)+"\n")
	provenance := fixtureDiscoveryProvenance(t, ledger)
	provenance.GoVersion = result.OrdinarySelectionPlan.GoVersion
	report := discoveryCorpusReport{
		SchemaVersion: discoveryReportSchema, Provenance: provenance, Targets: targets,
		ShardCount: 1, CandidateTotal: 1, EligibleCandidates: 1, Selected: 1, Passed: 1,
		Translations: result.Translations, FeatureInventory: inventory, Results: []discoveryCorpusResult{result},
	}
	if err := validateDiscoveryCorpusAccounting(report); err != nil {
		t.Fatal(err)
	}
	reports := t.TempDir()
	if err := writeDiscoveryCorpusReport(filepath.Join(reports, "shard-0.json"), report); err != nil {
		t.Fatal(err)
	}
	progress, err := collectDiscoveryProgress(ledger, reports, targets, provenance.Source, 1)
	if err != nil || !progress.Verified || progress.Translations != len(targets) || progress.ModeTranslations != 0 {
		t.Fatalf("actual full11 report/progress completion: %v %#v", err, progress)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	semanticSource := strings.Repeat("a", 64)
	if err := writeAssemblyLedger(output, progress, semanticSource); err != nil {
		t.Fatal(err)
	}
	replayed, err := readAssemblyLedger(output, progress.LedgerSHA256, semanticSource)
	if err != nil || !replayed.Verified || replayed.Translations != progress.Translations ||
		!reflect.DeepEqual(replayed.Candidates[0].OrdinarySelectionPlan.HeaderPlanning, progress.Candidates[0].OrdinarySelectionPlan.HeaderPlanning) {
		t.Fatalf("actual full11 ledger source/query roundtrip: %v", err)
	}
	encoded, err := json.Marshal(replayed)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*discoveryProgress){
		"different target set":          func(p *discoveryProgress) { p.Targets = append(p.Targets, "freebsd/amd64") },
		"ledger planning role deletion": func(p *discoveryProgress) { p.Candidates[0].OrdinarySelectionPlan.HeaderPlanning = nil },
		"ledger query paired deletion":  func(p *discoveryProgress) { p.Candidates[0].OrdinarySelectionPlan.HeaderPlanning.Queries = nil },
		"ledger source paired deletion": func(p *discoveryProgress) { p.Candidates[0].OrdinarySelectionPlan.HeaderPlanning.Sources = nil },
	} {
		t.Run(name, func(t *testing.T) {
			var altered discoveryProgress
			if err := json.Unmarshal(encoded, &altered); err != nil {
				t.Fatal(err)
			}
			mutate(&altered)
			if err := validateAssemblyLedgerProgress(altered); err == nil {
				t.Fatal("ledger accepted a different complete scope or erased planning authority")
			}
		})
	}
}
