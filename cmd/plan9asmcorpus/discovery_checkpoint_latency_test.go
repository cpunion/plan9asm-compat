package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDiscoverySlowCandidatePublishesBeforeNextCandidate(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "passed"
		if failed {
			name = "failed"
		}
		t.Run(name, func(t *testing.T) {
			cfg, candidates := exactDiscoveryFixture(t)
			cfg.ExactCandidates = []string{candidates[0].exactKey(), candidates[1].exactKey()}
			now := time.Unix(100, 0)
			cfg.checkpointNow = func() time.Time { return now }
			calls := 0
			cfg.runCandidate = func(cfg discoveryCorpusConfig, candidate discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
				if calls == 1 {
					report, err := readDiscoveryCorpusReport(cfg.ReportPath)
					if err != nil || !report.Partial || report.Selected != 1 || len(report.Results) != 1 {
						t.Fatalf("completed slow candidate missing before next candidate: selected=%d results=%d partial=%v err=%v", report.Selected, len(report.Results), report.Partial, err)
					}
					if report.Results[0].Module != candidates[0].Module || report.CandidateTotal != len(candidates) {
						t.Fatal("partial checkpoint changed ownership or the full denominator")
					}
					if failed && (report.Failed != 1 || report.Passed != 0) || !failed && (report.Passed != 1 || report.Failed != 0) {
						t.Fatalf("checkpoint disguised the terminal candidate status: passed=%d failed=%d", report.Passed, report.Failed)
					}
				}
				calls++
				if calls == 1 {
					now = now.Add(time.Minute)
					if failed {
						return matrixReport{}, nil, nil, errors.New("independent fixture failure")
					}
				}
				return exactDiscoveryPass(t, cfg, candidate)
			}
			err := runDiscoveryCorpus(cfg)
			if (err != nil) != failed || calls != 2 {
				t.Fatalf("candidate execution calls=%d failed=%v err=%v", calls, failed, err)
			}
			report, err := readDiscoveryCorpusReport(cfg.ReportPath)
			if err != nil || !report.Partial || report.Selected != 2 {
				t.Fatalf("terminal exact subset changed completion semantics: selected=%d partial=%v err=%v", report.Selected, report.Partial, err)
			}
		})
	}
}

func TestDiscoverySlowCheckpointRechecksProvenance(t *testing.T) {
	cfg, candidates := exactDiscoveryFixture(t)
	cfg.ExactCandidates = []string{candidates[0].exactKey(), candidates[1].exactKey()}
	now := time.Unix(100, 0)
	cfg.checkpointNow = func() time.Time { return now }
	changed := false
	capture := cfg.captureProvenance
	cfg.captureProvenance = func(cfg discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
		proof, err := capture(cfg)
		if changed {
			proof.LLCBinarySHA256 = strings.Repeat("f", 64)
		}
		return proof, err
	}
	calls := 0
	cfg.runCandidate = func(cfg discoveryCorpusConfig, candidate discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
		calls++
		if calls != 1 {
			t.Fatal("changed tools passed the slow-candidate checkpoint")
		}
		now = now.Add(time.Minute)
		changed = true
		return exactDiscoveryPass(t, cfg, candidate)
	}
	err := runDiscoveryCorpus(cfg)
	if err == nil || !strings.Contains(err.Error(), "provenance invalidated during checkpoint") || calls != 1 {
		t.Fatalf("changed provenance was not rejected before another candidate: calls=%d err=%v", calls, err)
	}
	report, err := readDiscoveryCorpusReport(cfg.ReportPath)
	if err != nil || report.Provenance.Invalidated == "" || !report.Partial || report.Selected != 1 {
		t.Fatalf("mutation failure was not retained in partial evidence: %+v; %v", report, err)
	}
}
