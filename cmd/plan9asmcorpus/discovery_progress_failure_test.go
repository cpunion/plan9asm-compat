package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestDiscoveryProgressFailureSummaryPreservesOriginalEvidence(t *testing.T) {
	for _, status := range []string{"failed", "early_target_rejected"} {
		t.Run(status, func(t *testing.T) {
			raw := "tool failed: /private/runner-only/cache/input.go\nsecond diagnostic\n"
			original := &discoveryOrdinarySelectionPlan{
				InstrumentationPlan: &discoveryInstrumentationPlan{
					Outcomes: []discoveryInstrumentationOutcome{{
						RequirementID: "original-requirement", ObservationID: "original-observation",
						Status: status, Stage: "metadata_query", Error: raw,
					}},
				},
			}
			before, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			result := summarizeDiscoverySelectionFailures(original)
			digest := sha256.Sum256([]byte(raw))
			wanted := "metadata_query " + status + "; raw_diagnostic_sha256=" + fmt.Sprintf("%x", digest)
			outcome := result.InstrumentationPlan.Outcomes[0]
			if outcome.Error != wanted || strings.Contains(outcome.Error, "/private/") {
				t.Fatalf("portable diagnostic = %q, want %q", outcome.Error, wanted)
			}
			if result == original || result.InstrumentationPlan == original.InstrumentationPlan {
				t.Fatal("collector aliases the mutable raw evidence nodes")
			}
			after, err := json.Marshal(original)
			if err != nil || string(before) != string(after) {
				t.Fatal("collection changed the original report")
			}
			outcome.Error = raw
			if !reflect.DeepEqual(outcome, original.InstrumentationPlan.Outcomes[0]) {
				t.Fatal("diagnostic compaction changed authoritative outcome fields")
			}
			if err := validateDiscoverySelectionFailureSummaries(result); err != nil {
				t.Fatalf("portable failure rejected: %v", err)
			}
			if err := validateDiscoverySelectionFailureSummaries(original); err == nil {
				t.Fatal("raw private-path failure accepted by the ledger guard")
			}
		})
	}
}

func TestDiscoveryProgressFailureSummaryDoesNotRepairInvalidOutcomes(t *testing.T) {
	if summarizeDiscoverySelectionFailures(nil) != nil {
		t.Fatal("nil plan acquired evidence")
	}
	plain := &discoveryOrdinarySelectionPlan{}
	if summarizeDiscoverySelectionFailures(plain) != plain {
		t.Fatal("ordinary plan acquired instrumentation")
	}
	for _, original := range []discoveryInstrumentationOutcome{
		{Status: "failed", Stage: "metadata_query"},
		{Status: "llvm_objects_only", Stage: "complete"},
		{Status: "llvm_objects_only", Stage: "complete", Error: "unexplained successful output"},
		{Status: "unknown", Stage: "metadata_query", Error: "unregistered failure"},
	} {
		plan := &discoveryOrdinarySelectionPlan{InstrumentationPlan: &discoveryInstrumentationPlan{
			Outcomes: []discoveryInstrumentationOutcome{original},
		}}
		result := summarizeDiscoverySelectionFailures(plan)
		if !reflect.DeepEqual(result, plan) {
			t.Fatalf("collector repaired an invalid/missing outcome: %+v", original)
		}
	}
}
