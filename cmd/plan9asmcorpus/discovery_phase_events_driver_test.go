package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type phaseFixtureCloser struct {
	io.WriteCloser
	cause error
}

func (writer phaseFixtureCloser) Close() error {
	return errors.Join(writer.WriteCloser.Close(), writer.cause)
}

func TestDiscoveryPhaseEventsRequestedFailureInvalidatesReport(t *testing.T) {
	for _, failure := range []string{"close", "EOF", "write"} {
		t.Run(failure, func(t *testing.T) {
			cfg, candidates := exactDiscoveryFixtureCount(t, 1)
			cfg.ExactCandidates = []string{candidates[0].exactKey()}
			cfg.EventsPath = filepath.Join(t.TempDir(), "events.jsonl")
			input := fixtureOrdinaryPassedResult(t, candidates[0], cfg.Targets)
			cause := errors.New("original close or write error must remain failure")
			cfg.runCandidate = func(cfg discoveryCorpusConfig, _ discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
				if failure == "close" {
					cfg.phaseEvents.writer = phaseFixtureCloser{cfg.phaseEvents.writer, cause}
				} else if failure == "write" {
					// This closes only the journal's actual owned descriptor.
					if err := cfg.phaseEvents.writer.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					file, err := os.OpenFile(cfg.EventsPath, os.O_APPEND|os.O_WRONLY, 0600)
					if err != nil {
						t.Fatal(err)
					}
					_, writeErr := file.WriteString("{broken JSONL input}\n")
					if err := errors.Join(writeErr, file.Close()); err != nil {
						t.Fatal(err)
					}
				}
				return fixtureProfileMatrix(t, input), input.ApplicableAsmFiles, input.BuildConfigurations, nil
			}
			if err := runDiscoveryCorpus(cfg); !errors.Is(err, errDiscoveryPhaseEvents) || failure == "close" && !errors.Is(err, cause) {
				t.Fatalf("requested event failure was suppressed: %v", err)
			}
			report, err := readDiscoveryCorpusReport(cfg.ReportPath)
			if err != nil || report.SchemaVersion != 11 || !strings.Contains(report.Provenance.Invalidated, "phase journal failed") {
				t.Fatalf("broken timing could certify report: report=%+v error=%v", report, err)
			}
		})
	}
}

func TestDiscoveryPhaseEventsFailurePreservesExistingInvalidation(t *testing.T) {
	cfg, candidates := exactDiscoveryFixtureCount(t, 1)
	cfg.ExactCandidates = []string{candidates[0].exactKey()}
	cfg.EventsPath = filepath.Join(t.TempDir(), "events.jsonl")
	input := fixtureOrdinaryPassedResult(t, candidates[0], cfg.Targets)
	cause := errors.New("actual journal close error alongside source invalidation")
	originalCapture := cfg.captureProvenance
	completed := false
	cfg.captureProvenance = func(cfg discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
		provenance, err := originalCapture(cfg)
		if completed {
			provenance.Source.Revision = strings.Repeat("b", 40)
		}
		return provenance, err
	}
	cfg.runCandidate = func(cfg discoveryCorpusConfig, _ discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
		completed = true
		cfg.phaseEvents.writer = phaseFixtureCloser{cfg.phaseEvents.writer, cause}
		return fixtureProfileMatrix(t, input), input.ApplicableAsmFiles, input.BuildConfigurations, nil
	}
	err := runDiscoveryCorpus(cfg)
	if !errors.Is(err, cause) || !errors.Is(err, errDiscoveryPhaseEvents) || !strings.Contains(err.Error(), "provenance invalidated") {
		t.Fatalf("an original failure was hidden: %v", err)
	}
	report, err := readDiscoveryCorpusReport(cfg.ReportPath)
	if err != nil || !strings.Contains(report.Provenance.Invalidated, "source, ledger or tools changed") ||
		!strings.Contains(report.Provenance.Invalidated, "phase journal failed") || report.Passed != 1 || report.Failed != 0 {
		t.Fatalf("journal replaced the original invalidation or counters: report=%+v error=%v", report, err)
	}
}

func TestDiscoveryPhaseEventsEmptyAndEarlyReturn(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty-selection", true: "preflight-error"}[failure], func(t *testing.T) {
			cfg, candidates := exactDiscoveryFixtureCount(t, 1)
			cfg.EventsPath = filepath.Join(t.TempDir(), "events.jsonl")
			cfg.runCandidate = func(discoveryCorpusConfig, discoveryCandidate, string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
				t.Fatal("empty/preflight fixture must not execute a candidate")
				return matrixReport{}, nil, nil, nil
			}
			for shard := 0; shard < cfg.ShardCount; shard++ {
				if len(selectDiscoveryShard(candidates, shard, cfg.ShardCount)) == 0 {
					cfg.ShardIndex = shard
					break
				}
			}
			if failure {
				cfg.RepoRoot = t.TempDir()
				dir := filepath.Join(cfg.RepoRoot, "testdata", "corpus")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, filepath.Join(dir, "superseded-modules.json"), "{broken}")
			}
			err := runDiscoveryCorpus(cfg)
			if (err != nil) != failure {
				t.Fatalf("original preflight outcome changed: %v", err)
			}
			data, readErr := os.ReadFile(cfg.EventsPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			summary, readErr := readDiscoveryPhaseEvents(bytes.NewReader(data))
			if readErr != nil || summary.Spans != 0 || (summary.Status == "failed") != failure {
				t.Fatalf("zero-operation journal not honestly closed: summary=%+v error=%v", summary, readErr)
			}
		})
	}
}

func TestDiscoveryPhaseEventsParentCancellationDoesNotStartOperation(t *testing.T) {
	writer := &phaseFixtureWriter{}
	journal := newPhaseFixtureJournal(t, writer)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg, _ := exactDiscoveryFixture(t)
	cfg.phaseEvents = journal
	calls := 0
	err := cfg.runPhaseOperationContext(ctx, discoveryCandidate{Module: "example.com/phase", Version: "v1.0.0"}, "header_query", "cancelled parent", func(context.Context) error {
		calls++
		return nil
	})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("timing renewed cancelled parent: calls=%d error=%v", calls, err)
	}
	if err := journal.close(err); err != nil {
		t.Fatal(err)
	}
}
