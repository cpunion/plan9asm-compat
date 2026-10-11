package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryPhaseEventsActualCandidateJournal(t *testing.T) {
	cfg, candidates := exactDiscoveryFixtureCount(t, 1)
	cfg.ExactCandidates = []string{candidates[0].exactKey()}
	events := filepath.Join(t.TempDir(), "events.jsonl")
	// This configuration seam compiles against the original driver too. Its
	// ignored unknown key reproduces the missing optional journal after the
	// actual first-party candidate operation, rather than a build-only RED.
	data, err := json.Marshal(map[string]string{"EventsPath": events})
	if err != nil || json.Unmarshal(data, &cfg) != nil {
		t.Fatal("cannot configure first-party phase fixture")
	}
	cause := errors.New("first-party operation remains failed, not timing pass")
	calls := 0
	cfg.runCandidate = func(_ discoveryCorpusConfig, candidate discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
		calls++
		if candidate.exactKey() != candidates[0].exactKey() {
			t.Fatal("candidate scope changed")
		}
		return matrixReport{}, nil, nil, cause
	}
	if err := runDiscoveryCorpus(cfg); err == nil || !strings.Contains(err.Error(), "failed=1") || calls != 1 {
		t.Fatalf("actual original operation was not retained: calls=%d error=%v", calls, err)
	}
	report, err := readDiscoveryCorpusReport(cfg.ReportPath)
	if err != nil || report.SchemaVersion != 11 || report.Failed != 1 || report.Passed != 0 || report.Results[0].Error != cause.Error() {
		t.Fatalf("timing changed original report/failure: report=%+v error=%v", report, err)
	}
	t.Logf("actual callback calls=%d; original schema=%d passed=%d failed=%d; report EOF verified; error=%q",
		calls, report.SchemaVersion, report.Passed, report.Failed, report.Results[0].Error)
	file, err := os.Open(events)
	if err != nil {
		t.Fatalf("actual candidate ran, but requested phase journal is absent: %v", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var kinds []string
	for scanner.Scan() {
		var event struct {
			Kind      string `json:"kind"`
			Candidate string `json:"candidate"`
			Phase     string `json:"phase"`
			Status    string `json:"status"`
			Error     string `json:"error"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, event.Kind)
		if event.Kind == "span_end" && (event.Candidate != candidates[0].exactKey() || event.Phase != "candidate" || event.Status != "failed" || event.Error != cause.Error()) {
			t.Fatalf("failed candidate is not independently timed: %+v", event)
		}
	}
	if err := scanner.Err(); err != nil || strings.Join(kinds, ",") != "run_start,span_start,span_end,run_end" {
		t.Fatalf("incomplete phase journal: kinds=%v error=%v", kinds, err)
	}
}
