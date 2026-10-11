package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestCPPOriginalConsumerReusesParsedSourceResources(t *testing.T) {
	parsed := cppResourceComplexityFixture(t, 16)
	data, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	var restored discoveryCPPInputs
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	want, err := discoveryCPPOriginalConsumerInput(&restored)
	if err != nil {
		t.Fatal(err)
	}
	got, err := discoveryCPPOriginalConsumerInput(parsed)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed and portable originals produce different consumers: %v", err)
	}
	measure := func(inputs *discoveryCPPInputs) float64 {
		return testing.AllocsPerRun(1, func() {
			if _, err := discoveryCPPOriginalConsumerInput(inputs); err != nil {
				t.Fatal(err)
			}
		})
	}
	warm, cold := measure(parsed), measure(&restored)
	t.Logf("query allocations: parsed=%g; restored=%g", warm, cold)
	// Restored JSON has no private lexer index and must parse the complete
	// originals. A captured source must not pay that cost for each profile.
	if cold == 0 || warm > cold/8 {
		t.Fatalf("captured originals are lexed again for every query: %g > %g / 8", warm, cold)
	}
}

func TestCPPParsedSourceResourcesRemainFreshAndOwned(t *testing.T) {
	text := "#include \"literal.h\"\nDATA ·name(SB)/8,$\"candidate.h\"\n"
	source, err := discoveryReplayCPPSource("pkg/native.s", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	inputs := &discoveryCPPInputs{Protocol: discoveryReplayCPPInputsProtocol}
	for _, fixture := range []struct {
		name   string
		mutate func(*discoveryCPPSource)
	}{
		{"unchanged", func(*discoveryCPPSource) {}},
		{"file", func(s *discoveryCPPSource) { s.File = "other/native.s" }},
		{"hash", func(s *discoveryCPPSource) { s.SHA256 = strings.Repeat("0", 64) }},
		{"original", func(s *discoveryCPPSource) {
			changed := *s.Original + "DATA ·other(SB)/8,$\"new.h\"\n"
			s.Original = &changed
		}},
		{"directives", func(s *discoveryCPPSource) { s.Directives[0].Include = "candidate.h" }},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			changed := source
			changed.Directives = append([]discoveryCPPDirective(nil), source.Directives...)
			fixture.mutate(&changed)
			data, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			var restored discoveryCPPSource
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			want, err := discoveryCPPRegisteredResources(inputs, restored)
			if err != nil {
				t.Fatal(err)
			}
			got, err := discoveryCPPRegisteredResources(inputs, changed)
			if err != nil || !reflect.DeepEqual(got, want) || len(got) == 0 {
				t.Fatalf("query reused stale source resources: got=%+v want=%+v error=%v", got, want, err)
			}
			got[0].directive.Include = "forged.h"
			again, err := discoveryCPPRegisteredResources(inputs, changed)
			if err != nil || !reflect.DeepEqual(again, want) {
				t.Fatalf("returned resources alias the private source index: %v", err)
			}
		})
	}
}

func TestCPPOriginalConsumerParsedResourcesConcurrent(t *testing.T) {
	inputs := cppResourceComplexityFixture(t, 2)
	want, err := discoveryCPPOriginalConsumerInput(inputs)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 8
	results := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			for query := 0; query < 4; query++ {
				got, err := discoveryCPPOriginalConsumerInput(inputs)
				if err != nil || !reflect.DeepEqual(got, want) {
					results <- fmt.Errorf("concurrent source query changed consumer: %v", err)
					return
				}
				got.CPPOriginals.Sources["module/"+inputs.Units[0].File] = "private consumer mutation"
			}
			results <- nil
		}()
	}
	for worker := 0; worker < workers; worker++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	again, err := discoveryCPPOriginalConsumerInput(inputs)
	if err != nil || !reflect.DeepEqual(again, want) {
		t.Fatalf("parallel query mutation escaped its consumer: %v", err)
	}
}

// This fixture measures query-graph construction, not source authentication or
// assembly coverage. Increasing independent units must not multiply the lexer
// work for every other unit's complete original source.
func cppResourceComplexityFixture(t testing.TB, units int) *discoveryCPPInputs {
	t.Helper()
	inputs := &discoveryCPPInputs{
		Protocol: discoveryReplayCPPInputsProtocol,
		Sources:  make(map[string]discoveryCPPSource),
	}
	for index := 0; index < units; index++ {
		file := fmt.Sprintf("pkg/native_%03d.s", index)
		text := fmt.Sprintf("TEXT ·Probe%d(SB),4,$0-0\nRET\n", index) +
			strings.Repeat("DATA ·table(SB)/8,$0x0123456789abcdef\n", 1024)
		source, err := discoveryReplayCPPSource(file, []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		inputs.Sources["module/"+file] = source
		inputs.Units = append(inputs.Units, discoveryCPPUnit{File: file})
	}
	return inputs
}

func TestCPPOriginalConsumerResourcePlanningScalesLinearly(t *testing.T) {
	small := cppResourceComplexityFixture(t, 2)
	large := cppResourceComplexityFixture(t, 16)
	measure := func(inputs *discoveryCPPInputs) float64 {
		return testing.AllocsPerRun(1, func() {
			consumer, err := discoveryCPPOriginalConsumerInput(inputs)
			if err != nil {
				t.Fatal(err)
			}
			if len(consumer.CPPOriginals.Sources) != len(inputs.Sources) ||
				len(consumer.CPPOriginals.Units) != len(inputs.Units) ||
				len(consumer.AsmFiles) != len(inputs.Units) {
				t.Fatal("resource planning discarded complete sources or units")
			}
		})
	}
	smallAllocs, largeAllocs := measure(small), measure(large)
	t.Logf("query graph allocations: 2 units=%g; 16 units=%g", smallAllocs, largeAllocs)
	// Eight times the source/units allows twelve times the allocations. This
	// has headroom for maps, but rejects per-unit rescans (quadratic growth).
	if smallAllocs == 0 || largeAllocs > 12*smallAllocs {
		t.Fatalf("CPP resource lexer work is multiplied by every unit: %g > 12 * %g", largeAllocs, smallAllocs)
	}
}

func TestCPPOriginalConsumerResourcePlanningRemainsFreshAndIndependent(t *testing.T) {
	inputs := cppResourceComplexityFixture(t, 2)
	before, err := discoveryCPPOriginalConsumerInput(inputs)
	if err != nil {
		t.Fatal(err)
	}
	again, err := discoveryCPPOriginalConsumerInput(inputs)
	if err != nil || !reflect.DeepEqual(before, again) {
		t.Fatalf("unchanged complete query graph changed: %v", err)
	}
	file := inputs.Units[0].File
	changedText := *inputs.Sources["module/"+file].Original + "DATA ·name(SB)/8,$\"missing.h\"\n"
	changed, err := discoveryReplayCPPSource(file, []byte(changedText))
	if err != nil {
		t.Fatal(err)
	}
	inputs.Sources["module/"+file] = changed
	after, err := discoveryCPPOriginalConsumerInput(inputs)
	if err != nil || after.CPPOriginals.Sources["module/"+file] != changedText ||
		before.CPPOriginals.Sources["module/"+file] == changedText {
		t.Fatalf("resource planning reused stale source or aliased an earlier consumer: %v", err)
	}
	after.CPPOriginals.Sources["module/"+file] = "forged"
	if *inputs.Sources["module/"+file].Original != changedText {
		t.Fatal("consumer mutation changed the original query graph")
	}
	missing := inputs.Sources["module/"+file]
	missing.Original = nil
	inputs.Sources["module/"+file] = missing
	if _, err := discoveryCPPOriginalConsumerInput(inputs); err == nil {
		t.Fatal("previous graph construction hid missing complete original bytes")
	}
}

func BenchmarkCPPOriginalConsumerResourcePlanning(b *testing.B) {
	inputs := cppResourceComplexityFixture(b, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := discoveryCPPOriginalConsumerInput(inputs); err != nil {
			b.Fatal(err)
		}
	}
}
