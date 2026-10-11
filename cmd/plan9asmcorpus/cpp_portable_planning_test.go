package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func portableCPPPlanningInput(t testing.TB, plan *discoveryOrdinarySelectionPlan) *discoveryOrdinarySelectionPlan {
	t.Helper()
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var restored discoveryOrdinarySelectionPlan
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	return &restored
}

// A report has complete originals, but deliberately has no private lexer
// indexes. Offline planning must build its own bounded index, rather than
// relex every original for each source pair and CPU environment. This fixture
// proves work and exact query equality, not source authentication or objects.
func TestCPPPortablePlanningRetainsParsedQueryComplexity(t *testing.T) {
	plan, files, baselines := cppPlanningSourceIndexFixture(t, 8, 4)
	portable := portableCPPPlanningInput(t, plan)
	before, err := json.Marshal(portable)
	if err != nil {
		t.Fatal(err)
	}
	want, err := planDiscoveryFeatureProfiles(plan, files, baselines)
	if err != nil {
		t.Fatal(err)
	}
	measure := func(input *discoveryOrdinarySelectionPlan) float64 {
		return testing.AllocsPerRun(1, func() {
			got, err := planDiscoveryFeatureProfiles(input, files, baselines)
			if err != nil || !reflect.DeepEqual(got, want) || len(got) != 1 || len(got[0].pairs) != 32 {
				t.Fatalf("portable planning changed complete source-pair requests: %v", err)
			}
		})
	}
	captured, restored := measure(plan), measure(portable)
	t.Logf("whole planning allocations: captured=%g portable=%g", captured, restored)
	if captured == 0 || restored > 1.05*captured {
		t.Errorf("portable source lexing multiplied by source/profile fanout: %g > 1.05 * %g", restored, captured)
	}
	for _, source := range portable.CPPInputs.Sources {
		if source.resourceIndex != nil {
			t.Fatal("planning published its private parser index into the report")
		}
	}
	after, err := json.Marshal(portable)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("planning changed the report's complete original inputs: %v", err)
	}
}

func BenchmarkCPPPortablePlanningFanout(b *testing.B) {
	plan, files, baselines := cppPlanningSourceIndexFixture(b, 8, 4)
	portable := portableCPPPlanningInput(b, plan)
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		testCPPPlanningSourceIndexRequests(b, portable, files, baselines, 4)
	}
}
