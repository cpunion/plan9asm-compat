//go:build go1.27

package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// This explicit fixture oracle is independent of the planner's CPU catalog.
// Bare and ,lse requests remain separate actual observations even when their
// assembler macros or native generated-header definitions happen to coincide.
func instrumentationARM64QueryFixtureCPUs() []string {
	var values []string
	for _, level := range []string{
		"v8.0", "v8.1", "v8.2", "v8.3", "v8.4",
		"v8.5", "v8.6", "v8.7", "v8.8", "v8.9",
		"v9.0", "v9.1", "v9.2", "v9.3", "v9.4", "v9.5",
	} {
		values = append(values, level, level+",lse")
	}
	sort.Strings(values)
	return values
}

func TestInstrumentationARM64CPPQueryDomainCompleteness(t *testing.T) {
	// This checks current-Go planning grammar, not an actual export or object.
	expected := instrumentationARM64QueryFixtureCPUs()
	for _, baseline := range []string{"v8.0", "v8.0,lse", "v9.5,lse"} {
		actual := discoveryCPPFeatureCPUValues("arm64", 27, baseline)
		sort.Strings(actual)
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("complete ARM64 query domain changed: baseline=%s actual=%v expected=%v", baseline, actual, expected)
		}
	}
}

func testInstrumentationImportedSDKQueryScopes(t *testing.T, proof *discoveryInstrumentationPlan) {
	t.Helper()
	if proof.HeaderPlanning == nil {
		t.Fatal("imported SDK fixture lost its actual native header planning")
	}
	seen := make(map[string]bool)
	for _, query := range proof.HeaderPlanning.Queries {
		if query.Observation == nil || query.Observation.Early == nil ||
			query.Metadata == nil || len(query.Metadata.Headers) != 1 {
			t.Fatal("imported SDK query lost its actual observation/header")
		}
		level := query.Observation.Early.Environment["GOAMD64"]
		if seen[level] || !containsTargetFeature([]string{"v1", "v2", "v3", "v4"}, level) {
			t.Fatalf("imported SDK fixture duplicated or borrowed another CPU domain: %q", level)
		}
		seen[level] = true
		if query.Requirement.Target != "darwin/amd64" ||
			query.Requirement.Mode != gotoolprofile.InstrumentationRace || query.Requirement.CGO != "0" ||
			query.Metadata.Headers[0].Header.Definitions["const_answer"] != "64" ||
			!equalDiscoveryStrings(query.PackagePlan.GoFiles, []string{"probe.go"}) ||
			!equalDiscoveryStrings(query.PackagePlan.SFiles, []string{"probe_amd64.s"}) {
			t.Fatal("actual imported SDK source/header selection changed")
		}
		// The renamed result type and the header constant have distinct complete
		// source roles. A paired metadata record cannot replace either capture.
		for _, role := range []struct {
			contents discoveryInstrumentationHeaderTypes
			path     string
		}{
			{query.Signatures, "syscall"},
			{query.PropertyTypes, "math/bits"},
		} {
			sources, err := restoreInstrumentationHeaderTypes(proof.HeaderPlanning, role.contents)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, dependency := range sources.Dependencies {
				if dependency.Dependency.Source.PackagePath == role.path {
					found = len(dependency.Contents) != 0 &&
						dependency.Dependency.Source.SourceRole == "stdlib" &&
						dependency.Dependency.Source.ExportSHA256 != ""
				}
			}
			if !found {
				t.Fatalf("independent original SDK %s source/export role disappeared", role.path)
			}
		}
	}
	if len(seen) != 4 {
		t.Fatalf("imported SDK transport fixture lost an actual AMD64 query: %v", seen)
	}
	t.Logf("IMPORTED_SDK_TRANSPORT target=darwin/amd64 actual_CPU_queries=%d LLVM_objects=%d; not original wide ARM64 fixture coverage", len(seen), len(proof.Outcomes))
}

func testInstrumentationARM64OriginalQueryScopes(t *testing.T, proof *discoveryInstrumentationPlan, sources map[string]string) {
	t.Helper()
	role := proof.HeaderPlanning
	if role == nil || len(role.Queries) != 32 {
		t.Fatalf("complete ARM64 actual query fixture lost proposals: %v", role != nil)
	}
	expected := instrumentationARM64QueryFixtureCPUs()
	seen := make(map[string]bool)
	for _, query := range role.Queries {
		if query.Observation == nil || query.Observation.Early == nil ||
			query.Metadata == nil || len(query.Metadata.Headers) != 1 {
			t.Fatal("ARM64 CPU query lost its independent actual mode/header")
		}
		cpu := query.Observation.Early.Environment["GOARM64"]
		if seen[cpu] || !containsTargetFeature(expected, cpu) {
			t.Fatalf("unexpected or duplicated actual ARM64 CPU query %q", cpu)
		}
		seen[cpu] = true
		wantFile, wantValue := "model/wide.go", "2"
		if strings.TrimSuffix(cpu, ",lse") == "v8.0" {
			wantFile, wantValue = "model/base.go", "1"
		}
		if query.Requirement.Target != "darwin/arm64" ||
			query.Requirement.Mode != gotoolprofile.InstrumentationRace || query.Requirement.CGO != "0" ||
			query.Metadata.Headers[0].Header.Definitions["const_Answer"] != wantValue {
			t.Fatalf("actual ARM64 CPU %s changed its selected native header property", cpu)
		}
		properties, err := restoreInstrumentationHeaderTypes(role, query.PropertyTypes)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, dependency := range properties.Dependencies {
			if dependency.Dependency.Source.PackagePath != "example.invalid/cpu-layout/model" {
				continue
			}
			found = true
			wantText := sources[wantFile]
			if wantText == "" ||
				!reflect.DeepEqual(dependency.Contents, map[string]string{wantFile: wantText}) ||
				!reflect.DeepEqual(dependency.Dependency.Source.GoSHA256, map[string]string{
					wantFile: discoveryFeatureBytesSHA256([]byte(wantText)),
				}) || dependency.Dependency.Source.SourceVersion != "v1.0.0" {
				t.Fatalf("CPU %s did not retain the exact independently ZIP-bound %s source", cpu, wantFile)
			}
		}
		if !found {
			t.Fatalf("CPU %s omitted its actual selected imported property source", cpu)
		}
	}
	if len(seen) != len(expected) {
		t.Fatalf("complete explicit ARM64 query set was not observed: %v", seen)
	}
	t.Logf("ARM64_COMPLETE_ORIGINAL_SELECTION actual_CPU_queries=%d selected_source_properties=2 independently_consumed_LLVM_objects=%d", len(seen), len(proof.Outcomes))
}

func testInstrumentationARM64QueryOmissions(t *testing.T, result discoveryCorpusResult, inventory *discoveryFeatureInventory, target string) {
	t.Helper()
	for index, query := range result.OrdinarySelectionPlan.InstrumentationPlan.HeaderPlanning.Queries {
		cpu := query.Observation.Early.Environment["GOARM64"]
		t.Run(fmt.Sprintf("actual CPU query omitted %s", cpu), func(t *testing.T) {
			changed := cloneInstrumentationSelectionResult(t, result)
			queries := changed.OrdinarySelectionPlan.InstrumentationPlan.HeaderPlanning.Queries
			changed.OrdinarySelectionPlan.InstrumentationPlan.HeaderPlanning.Queries = append(queries[:index:index], queries[index+1:]...)
			changed.featureInventory = inventory
			if err := validateOrdinaryProfileResult(changed, []string{target}, result.OrdinarySelectionPlan.GoVersion); err == nil {
				t.Fatal("removing one required actual CPU header query acquired complete union credit")
			}
		})
	}
}

func cloneInstrumentationSelectionResult(t *testing.T, result discoveryCorpusResult) discoveryCorpusResult {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var copy discoveryCorpusResult
	if err := json.Unmarshal(data, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}
