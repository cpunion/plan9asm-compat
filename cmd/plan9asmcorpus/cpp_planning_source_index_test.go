package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// This first-party planning model has independent complete assembly originals
// and ordinary Go partners. It grants no compiler, source or object evidence.
// All sources match every legal ARM64 CPU proposal, with no conditional CPP or
// generated header whose failure could stop enumeration early.
func cppPlanningSourceIndexFixture(t testing.TB, units, partners int) (*discoveryOrdinarySelectionPlan, []string, []*discoveryTargetFeatures) {
	t.Helper()
	data, err := os.ReadFile("testdata/go127_feature_protocol_fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var captured featureProtocolFixture
	if err := json.Unmarshal(data, &captured); err != nil {
		t.Fatal(err)
	}
	baseline := captured.Observed["linux/arm64"]
	if baseline == nil {
		t.Fatal("missing independent ARM64 namespace")
	}
	plan := &discoveryOrdinarySelectionPlan{
		Module: "example.invalid/planning-fanout", Version: "v1.0.0", GoVersion: baseline.GoVersion,
		Targets: []string{baseline.Target}, ModuleSum: "h1:" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
		ZipSHA256: discoveryFeatureBytesSHA256([]byte("query-only source fanout fixture")),
	}
	inputs := &discoveryCPPInputs{
		Protocol: discoveryReplayCPPInputsProtocol, Module: plan.Module, Version: plan.Version,
		ModuleSum: plan.ModuleSum, ZipSHA256: plan.ZipSHA256, Registration: captured.CPP,
		Sources: make(map[string]discoveryCPPSource),
	}
	add := func(file, text string) {
		plan.Sources = append(plan.Sources, ordinarySelectionSource{
			File: file, Header: text, SHA256: discoveryFeatureBytesSHA256([]byte(text)),
		})
	}
	add("go.mod", "module example.invalid/planning-fanout\n\ngo 1.20\n")
	for partner := 0; partner < partners; partner++ {
		add(fmt.Sprintf("pkg/decl_%03d.go", partner),
			fmt.Sprintf("package fixture\nfunc Helper%d() {}\n", partner))
	}
	var files []string
	for unit := 0; unit < units; unit++ {
		file := fmt.Sprintf("pkg/probe_%03d_arm64.s", unit)
		text := fmt.Sprintf("TEXT ·Probe%d(SB),4,$0-0\nRET\n", unit) +
			strings.Repeat("DATA ·table(SB)/8,$0x0123456789abcdef\n", 64)
		add(file, text)
		parsed, err := discoveryReplayCPPSource(file, []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		inputs.Sources["module/"+file] = parsed
		inputs.Units = append(inputs.Units, discoveryCPPUnit{File: file})
		files = append(files, file)
	}
	plan.CPPInputs = inputs
	return plan, files, []*discoveryTargetFeatures{baseline}
}

func testCPPPlanningSourceIndexRequests(t testing.TB, plan *discoveryOrdinarySelectionPlan,
	files []string, baselines []*discoveryTargetFeatures, partners int) {
	t.Helper()
	requests, err := planDiscoveryFeatureProfiles(plan, files, baselines)
	if err != nil || len(requests) != 1 || !requests[0].Baseline || len(requests[0].pairs) != len(files)*partners {
		t.Fatalf("complete original source-pair denominator changed: requests=%+v error=%v", requests, err)
	}
}

func TestCPPPlanningSourceIndexAvoidsQuadraticLexing(t *testing.T) {
	measure := func(units int) float64 {
		plan, files, baselines := cppPlanningSourceIndexFixture(t, units, 4)
		return testing.AllocsPerRun(1, func() {
			testCPPPlanningSourceIndexRequests(t, plan, files, baselines, 4)
		})
	}
	small, large := measure(2), measure(8)
	t.Logf("complete planning allocations: 2 ASM x 4 Go=%g; 8 ASM x 4 Go=%g; legal ARM64 CPU domain=32", small, large)
	// Four times as many ASM roots permits eight times the allocations, with
	// room for mandatory whole-graph field/edge validation on every query.
	// Relexing every complete source for every other root grows quadratically.
	if small == 0 || large > 8*small {
		t.Fatalf("same-call full source parsing grows quadratically: %g > 8 * %g", large, small)
	}
}

func BenchmarkCPPPlanningSourceIndexFanout(b *testing.B) {
	for _, units := range []int{2, 8} {
		b.Run(fmt.Sprintf("asm%d_go4", units), func(b *testing.B) {
			plan, files, baselines := cppPlanningSourceIndexFixture(b, units, 4)
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				testCPPPlanningSourceIndexRequests(b, plan, files, baselines, 4)
			}
		})
	}
}

func TestCPPPlanningSourceIndexKeepsEveryCPUProposal(t *testing.T) {
	for _, indexed := range []bool{false, true} {
		t.Run(fmt.Sprint(indexed), func(t *testing.T) {
			plan, files, baselines := cppPlanningSourceIndexFixture(t, 2, 4)
			model, err := discoveryContextForFeatureProfile(baselines[0])
			if err != nil {
				t.Fatal(err)
			}
			contents := make(map[string]string)
			for _, source := range plan.Sources {
				contents[source.File] = source.Header
			}
			reads := 0
			model.OpenFile = func(file string) (io.ReadCloser, error) {
				reads++
				text, found := contents[file]
				if !found {
					return nil, fmt.Errorf("missing complete source %s", file)
				}
				return io.NopCloser(strings.NewReader(text)), nil
			}
			var index *discoveryCPPPlanningSourceIndex
			if indexed {
				index = &discoveryCPPPlanningSourceIndex{}
			}
			requests, err := planDiscoveryCPPFeaturePairWithIndex(plan, model, baselines[0], files[0], "pkg/decl_000.go",
				discoveryFeatureProfileRequest{Target: model.GOOS + "/" + model.GOARCH, Baseline: true}, nil, index)
			// Each of 32 legal CPU proposals reads both constraints and asks
			// stock MatchFile for both files. discoveryGoFileMatches then
			// independently reads Go imports to check cgo: five reads each.
			if err != nil || len(requests) != 0 || reads != 32*5 {
				t.Fatalf("CPU/source predicate denominator changed: indexed=%t reads=%d requests=%+v error=%v", indexed, reads, requests, err)
			}
			t.Logf("indexed=%t actual_source_reads=%d legal_cpu_proposals=32", indexed, reads)
		})
	}
}

func TestCPPPlanningSourceIndexRejectsMutationsAfterWarmParse(t *testing.T) {
	for _, axis := range []string{
		"filename", "text", "hash", "projection", "nil original", "missing source",
		"graph edge", "extra unit", "module scope", "protocol", "SDK registration", "cancellation",
	} {
		t.Run(axis, func(t *testing.T) {
			plan, files, baselines := cppPlanningSourceIndexFixture(t, 2, 4)
			index := &discoveryCPPPlanningSourceIndex{}
			if err := validateDiscoveryReplayCPPInputsWithIndex(plan.CPPInputs, plan, files, index); err != nil {
				t.Fatal(err)
			}
			model, err := discoveryContextForFeatureProfile(baselines[0])
			if err != nil {
				t.Fatal(err)
			}
			contents := make(map[string]string)
			for _, source := range plan.Sources {
				contents[source.File] = source.Header
			}
			operation, cancel := context.WithCancel(context.Background())
			defer cancel()
			mutated := false
			model.OpenFile = func(file string) (io.ReadCloser, error) {
				if !mutated {
					mutated = true
					inputs := plan.CPPInputs
					id := "module/" + files[0]
					source := inputs.Sources[id]
					switch axis {
					case "filename":
						source.File = files[1]
					case "text":
						*source.Original += "// changed after cached parse\n"
					case "hash":
						source.SHA256 = strings.Repeat("0", 64)
					case "projection":
						source.Directives = append(source.Directives, discoveryCPPDirective{Line: 1, Kind: "define", Name: "FORGED"})
					case "nil original":
						source.Original = nil
					case "missing source":
						delete(inputs.Sources, "module/"+files[1])
					case "graph edge":
						inputs.Units[0].Includes = map[string]string{id + "#0": "module/" + files[1]}
					case "extra unit":
						inputs.Units = append(inputs.Units, inputs.Units[0])
					case "module scope":
						inputs.Version = "v2.0.0"
					case "protocol":
						inputs.Protocol = "unregistered_parse_mode"
					case "SDK registration":
						inputs.Registration = nil
					case "cancellation":
						cancel()
					}
					inputs.Sources[id] = source
				}
				return io.NopCloser(strings.NewReader(contents[file])), nil
			}
			requests, err := planDiscoveryCPPFeaturePairWithIndex(plan, model, baselines[0], files[0], "pkg/decl_000.go",
				discoveryFeatureProfileRequest{Target: "linux/arm64", Baseline: true}, nil, index, operation)
			if !mutated || err == nil || requests != nil || axis == "cancellation" && !errors.Is(err, context.Canceled) {
				t.Fatalf("warm parse concealed callback mutation/cancellation: mutated=%t requests=%+v error=%v", mutated, requests, err)
			}
		})
	}
}

func TestCPPPlanningSourceIndexOwnsParsesAndKeysCompleteInput(t *testing.T) {
	index := &discoveryCPPPlanningSourceIndex{}
	text := "#define VALUE 7\nTEXT ·Probe(SB),4,$0-0\nRET\n"
	first, err := discoveryReplayCPPSource("one.s", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := index.validate("one.s", first); err != nil {
		t.Fatal(err)
	}
	// Public projection mutation must not change the private parse or make
	// a later unchanged complete input fail by poisoning an aliased slice.
	first.Directives[0].Name = "FORGED"
	if _, err := index.validate("one.s", first); err == nil {
		t.Fatal("public projection changed the cached original parse")
	}
	for _, fixture := range []struct{ file, text string }{
		{"one.s", text}, {"two.s", text}, {"one.s", strings.Replace(text, "VALUE 7", "VALUE 9", 1)},
	} {
		source, err := discoveryReplayCPPSource(fixture.file, []byte(fixture.text))
		if err != nil {
			t.Fatal(err)
		}
		resources, err := index.validate(fixture.file, source)
		if err != nil || resources.file != fixture.file || resources.original != fixture.text {
			t.Fatalf("filename/complete-text parse key changed: %v", err)
		}
	}
	if len(index.sources) != 3 {
		t.Fatal("distinct complete inputs did not keep separate pure parse results")
	}
}

func TestCPPPlanningSourceIndexConcurrentCallsRemainPrivate(t *testing.T) {
	plan, files, baselines := cppPlanningSourceIndexFixture(t, 2, 1)
	before, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	// Portable inputs have no private index. Calls share immutable sources
	// and CPP graphs, but own the plan's existing header-query bookkeeping.
	// The parser cache must likewise remain private to each invocation.
	var portable discoveryOrdinarySelectionPlan
	if err := json.Unmarshal(before, &portable); err != nil {
		t.Fatal(err)
	}
	const workers = 4
	results := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			invocation := portable
			requests, err := planDiscoveryFeatureProfiles(&invocation, files, baselines)
			if err == nil && (len(requests) != 1 || !requests[0].Baseline || len(requests[0].pairs) != len(files)) {
				err = fmt.Errorf("concurrent planning changed the complete source pairs")
			}
			results <- err
		}()
	}
	for worker := 0; worker < workers; worker++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	for _, source := range portable.CPPInputs.Sources {
		if source.resourceIndex != nil {
			t.Fatal("planning published a private parser index into portable inputs")
		}
	}
	after, err := json.Marshal(&portable)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("planning changed its caller's portable source graph: %v", err)
	}
}

func TestCPPPlanningSourceIndexEvictionRetainsProjectionChecks(t *testing.T) {
	for _, bound := range []string{"files", "bytes"} {
		t.Run(bound, func(t *testing.T) {
			index := &discoveryCPPPlanningSourceIndex{}
			text := "TEXT ·Probe(SB),4,$0-0\nRET\n"
			for file := 0; file < 512; file++ {
				name := fmt.Sprintf("probe_%03d.s", file)
				source, err := discoveryReplayCPPSource(name, []byte(text))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := index.validate(name, source); err != nil {
					t.Fatal(err)
				}
				if bound == "bytes" {
					// Exercise the byte-cap branch without a 64 MiB test input.
					index.bytes = discoveryReplayCPPGraphBytes
					break
				}
			}
			source, err := discoveryReplayCPPSource("next.s", []byte(text))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := index.validate("next.s", source); err != nil || len(index.sources) != 1 || index.bytes != len(text) {
				t.Fatalf("pure parse cache did not retain its bounded scope: entries=%d bytes=%d error=%v", len(index.sources), index.bytes, err)
			}
			source.SHA256 = strings.Repeat("0", 64)
			if _, err := index.validate("next.s", source); err == nil {
				t.Fatal("eviction disabled public projection checks")
			}
		})
	}
}
