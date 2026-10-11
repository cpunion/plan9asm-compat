package main

import (
	"fmt"
	"testing"
)

func TestCPPOriginalConsumerRejectsUnregisteredResourceEdges(t *testing.T) {
	for _, axis := range []string{"literal", "generated-header", "candidate"} {
		t.Run(axis, func(t *testing.T) {
			inputs := cppResourceComplexityFixture(t, 2)
			key := "module/" + inputs.Units[0].File + "#unregistered"
			switch axis {
			case "literal":
				inputs.Units[0].Includes = map[string]string{key: "module/" + inputs.Units[1].File}
			case "generated-header":
				inputs.Units[0].DeferredIncludes = map[string]string{key: "generated_go_asm"}
			case "candidate":
				inputs.Units[0].DeferredIncludes = map[string]string{key: "unresolved_candidate"}
			}
			if _, err := discoveryCPPOriginalConsumerInput(inputs); err == nil {
				t.Fatal("CPP query silently dropped an unregistered original resource edge")
			}
		})
	}
}

func TestCPPOriginalReplayRevalidatesUnconsumedSource(t *testing.T) {
	inputs := cppResourceComplexityFixture(t, 2)
	root := inputs.Units[0]
	if _, _, err := replayDiscoveryOriginalCPP(inputs, root, nil, nil); err != nil {
		t.Fatal(err)
	}

	// Replay only the first unit, but require the second complete source to
	// remain authenticated. A prior successful query cannot authorize edits.
	id := "module/" + inputs.Units[1].File
	source := inputs.Sources[id]
	changed := *source.Original + "DATA ·changed(SB)/8,$1\n"
	source.Original = &changed
	inputs.Sources[id] = source
	if _, _, err := replayDiscoveryOriginalCPP(inputs, root, nil, nil); err == nil {
		t.Fatal("CPP replay reused validation or omitted an unconsumed complete source")
	}
	if _, err := discoveryCPPOriginalConsumerInput(inputs); err == nil {
		t.Fatal("direct CPP consumer omitted complete-source validation")
	}

	// A freshly parsed replacement is valid, not a cached failure or grant.
	replacement, err := discoveryReplayCPPSource(source.File, []byte(changed))
	if err != nil {
		t.Fatal(err)
	}
	inputs.Sources[id] = replacement
	if _, _, err := replayDiscoveryOriginalCPP(inputs, root, nil, nil); err != nil {
		t.Fatalf("CPP replay retained stale validation after a fresh replacement: %v", err)
	}
}

// Sparse originals exercise edge-index work separately from lexer work.
// These are source-query fixtures, never compiler acceptance or library passes.
func cppSparseResourceGraphFixture(t testing.TB, units, resources int) *discoveryCPPInputs {
	t.Helper()
	inputs := &discoveryCPPInputs{Protocol: discoveryReplayCPPInputsProtocol, Sources: make(map[string]discoveryCPPSource)}
	for unit := 0; unit < units; unit++ {
		file := fmt.Sprintf("pkg/native_%03d.s", unit)
		text := fmt.Sprintf("TEXT ·Probe%d(SB),4,$0-0\nRET\n", unit)
		for resource := 0; resource < resources; resource++ {
			text += fmt.Sprintf("DATA ·table%d+%d(SB)/8,$\"r%03d.h\"\n", unit, resource*8, resource)
		}
		source, err := discoveryReplayCPPSource(file, []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		id := "module/" + file
		inputs.Sources[id] = source
		registered, err := discoveryCPPRegisteredResources(inputs, source)
		if err != nil || len(registered) != resources {
			t.Fatalf("sparse original resources: %d: %v", len(registered), err)
		}
		links := make(map[string]string, resources)
		for _, resource := range registered {
			links[id+resource.key] = "unresolved_candidate"
		}
		inputs.Units = append(inputs.Units, discoveryCPPUnit{File: file, DeferredIncludes: links})
	}
	return inputs
}

func BenchmarkCPPOriginalConsumerSparseResourceGraph(b *testing.B) {
	for _, units := range []int{64, 256} {
		b.Run(fmt.Sprint(units), func(b *testing.B) {
			inputs := cppSparseResourceGraphFixture(b, units, 16)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := discoveryCPPOriginalConsumerInput(inputs); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkCPPOriginalProfileReplayFullGraph(b *testing.B) {
	for _, units := range []int{2, 16} {
		b.Run(fmt.Sprint(units), func(b *testing.B) {
			inputs := cppResourceComplexityFixture(b, units)
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, _, err := replayDiscoveryOriginalCPP(inputs, inputs.Units[0], nil, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
