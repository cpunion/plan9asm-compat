package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const phaseFixtureCandidate = "example.com/phase@v1.0.0"

type phaseFixtureWriter struct {
	bytes.Buffer
	writes, failAt, closes int
	writeErr, closeErr     error
	short                  bool
}

func (writer *phaseFixtureWriter) Write(data []byte) (int, error) {
	writer.writes++
	if writer.writes == writer.failAt {
		if writer.short {
			return len(data) - 1, nil
		}
		return 0, writer.writeErr
	}
	return writer.Buffer.Write(data)
}

func (writer *phaseFixtureWriter) Close() error {
	writer.closes++
	return writer.closeErr
}

func newPhaseFixtureJournal(t *testing.T, writer io.WriteCloser) *discoveryPhaseJournal {
	t.Helper()
	clock := int64(0)
	journal := &discoveryPhaseJournal{writer: writer, active: make(map[uint64]discoveryPhaseSpan),
		now: func() discoveryPhaseInstant {
			clock++
			return discoveryPhaseInstant{wall: time.Unix(1000, clock), tick: time.Duration(clock)}
		}}
	if err := journal.record(discoveryPhaseEvent{Kind: "run_start", At: journal.now().wall,
		ShardCount: 64, Provenance: &discoveryCorpusProvenance{}}); err != nil {
		t.Fatal(err)
	}
	return journal
}

func phaseFixtureRecords(t *testing.T, data []byte) []discoveryPhaseEvent {
	t.Helper()
	var records []discoveryPhaseEvent
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		var event discoveryPhaseEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		records = append(records, event)
	}
	return records
}

func encodePhaseFixture(t *testing.T, events []discoveryPhaseEvent) []byte {
	t.Helper()
	var buffer bytes.Buffer
	for _, event := range events {
		if err := json.NewEncoder(&buffer).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	return buffer.Bytes()
}

func TestDiscoveryPhaseEventsOperationErrorsAndPanic(t *testing.T) {
	for _, mode := range []string{"success", "error", "cancel", "panic"} {
		t.Run(mode, func(t *testing.T) {
			writer := &phaseFixtureWriter{}
			journal := newPhaseFixtureJournal(t, writer)
			cause := errors.New("actual first-party early return")
			if mode == "cancel" {
				cause = context.Canceled
			}
			calls := 0
			var result error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				result = journal.run(phaseFixtureCandidate, "ordinary_target", "linux/amd64", func() error {
					calls++
					if mode == "panic" {
						panic(cause)
					}
					if mode != "success" {
						return cause
					}
					return nil
				})
			}()
			if calls != 1 || mode == "panic" && recovered != cause || mode != "panic" && recovered != nil ||
				mode != "panic" && mode != "success" && !errors.Is(result, cause) || mode == "success" && result != nil {
				t.Fatalf("timing changed operation outcome: calls=%d error=%v panic=%v", calls, result, recovered)
			}
			if mode == "panic" {
				result = cause
			}
			if err := journal.close(result); err != nil || writer.closes != 1 || len(journal.active) != 0 {
				t.Fatalf("journal/owner did not close: error=%v active=%d", err, len(journal.active))
			}
			summary, err := readDiscoveryPhaseEvents(bytes.NewReader(writer.Bytes()))
			if err != nil || summary.Spans != 1 || (summary.Failed == 0) != (mode == "success") || (summary.Panicked != 0) != (mode == "panic") {
				t.Fatalf("error or panic became timing completion: summary=%+v error=%v", summary, err)
			}
		})
	}
}

func TestDiscoveryPhaseEventsHandledInnerFailureRetainsOuterOutcome(t *testing.T) {
	writer := &phaseFixtureWriter{}
	journal := newPhaseFixtureJournal(t, writer)
	innerCause := errors.New("actual phase error handled by the original operation")
	err := journal.run(phaseFixtureCandidate, "candidate", "", func() error {
		innerErr := journal.run(phaseFixtureCandidate, "ordinary_target", "linux/amd64", func() error {
			return innerCause
		})
		if !errors.Is(innerErr, innerCause) {
			t.Fatalf("journal changed the original inner error: %v", innerErr)
		}
		// The existing caller, not timing, owns whether an operation error is
		// handled. A completed outer operation does not erase the failed span.
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.close(nil); err != nil {
		t.Fatal(err)
	}
	summary, err := readDiscoveryPhaseEvents(bytes.NewReader(writer.Bytes()))
	if err != nil || summary.Spans != 2 || summary.Failed != 1 || summary.Status != "complete" {
		t.Fatalf("diagnostic timing changed handled operation semantics: summary=%+v error=%v", summary, err)
	}
	records := phaseFixtureRecords(t, writer.Bytes())
	if records[3].Status != "failed" || records[3].Error != innerCause.Error() || records[4].Status != "complete" {
		t.Fatalf("inner error was hidden or promoted to the outer result: %+v", records)
	}
}

func TestDiscoveryPhaseEventsWritesCloseAndOriginalError(t *testing.T) {
	for _, failure := range []string{"start-write", "end-write", "short-write", "close", "readback"} {
		t.Run(failure, func(t *testing.T) {
			cause := errors.New("original operation error")
			ioCause := errors.New("injected journal I/O failure")
			writer := &phaseFixtureWriter{writeErr: ioCause}
			journal := newPhaseFixtureJournal(t, writer)
			switch failure {
			case "start-write":
				writer.failAt = 2
			case "end-write":
				writer.failAt = 3
			case "short-write":
				writer.failAt, writer.short = 3, true
			case "close":
				writer.closeErr = ioCause
			case "readback":
				journal.readback = func() error { return ioCause }
			}
			calls := 0
			result := journal.run(phaseFixtureCandidate, "candidate", "", func() error { calls++; return cause })
			closed := journal.close(result)
			if failure == "start-write" && calls != 0 || failure != "start-write" && (calls != 1 || !errors.Is(result, cause)) {
				t.Fatalf("lost original operation/failed admission: calls=%d result=%v", calls, result)
			}
			if !errors.Is(errors.Join(result, closed), errDiscoveryPhaseEvents) || writer.closes != 1 || !isDiscoveryInfrastructureFailure(errors.Join(result, closed)) {
				t.Fatalf("requested timing failure could become N/A: result=%v close=%v closes=%d", result, closed, writer.closes)
			}
		})
	}
}

func TestDiscoveryPhaseEventsReaderRejectsIncompleteOrTampered(t *testing.T) {
	writer := &phaseFixtureWriter{}
	journal := newPhaseFixtureJournal(t, writer)
	if err := journal.run(phaseFixtureCandidate, "candidate", "exact", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := journal.close(nil); err != nil {
		t.Fatal(err)
	}
	controls := map[string]func([]discoveryPhaseEvent) []discoveryPhaseEvent{
		"missing-start": func(e []discoveryPhaseEvent) []discoveryPhaseEvent { return e[1:] },
		"missing-end":   func(e []discoveryPhaseEvent) []discoveryPhaseEvent { return e[:3] },
		"duplicate-end": func(e []discoveryPhaseEvent) []discoveryPhaseEvent { return append(e[:3], e[2], e[3]) },
		"cross-candidate": func(e []discoveryPhaseEvent) []discoveryPhaseEvent {
			e[2].Candidate = "example.com/other@v1.0.0"
			return e
		},
		"wrong-span":        func(e []discoveryPhaseEvent) []discoveryPhaseEvent { e[2].Span++; return e },
		"wrong-phase":       func(e []discoveryPhaseEvent) []discoveryPhaseEvent { e[2].Phase = "other"; return e },
		"wrong-scope":       func(e []discoveryPhaseEvent) []discoveryPhaseEvent { e[2].Scope = "other"; return e },
		"sequence-gap":      func(e []discoveryPhaseEvent) []discoveryPhaseEvent { e[2].Sequence++; return e },
		"undefined-elapsed": func(e []discoveryPhaseEvent) []discoveryPhaseEvent { e[2].ElapsedNS = nil; return e },
		"negative-elapsed":  func(e []discoveryPhaseEvent) []discoveryPhaseEvent { n := int64(-1); e[2].ElapsedNS = &n; return e },
		"false-complete":    func(e []discoveryPhaseEvent) []discoveryPhaseEvent { e[2].Error = "failed"; return e },
		"invalid-protocol":  func(e []discoveryPhaseEvent) []discoveryPhaseEvent { e[1].Protocol = "unknown"; return e },
		"injected-run-role": func(e []discoveryPhaseEvent) []discoveryPhaseEvent {
			e[2].Provenance = &discoveryCorpusProvenance{}
			return e
		},
		"after-terminal": func(e []discoveryPhaseEvent) []discoveryPhaseEvent { return append(e, e[0]) },
	}
	for name, mutate := range controls {
		t.Run(name, func(t *testing.T) {
			events := phaseFixtureRecords(t, writer.Bytes())
			if _, err := readDiscoveryPhaseEvents(bytes.NewReader(encodePhaseFixture(t, mutate(events)))); err == nil {
				t.Fatal("accepted invalid timing journal")
			}
		})
	}
	for name, tail := range map[string]string{"malformed": "{", "unknown-field": "{\"extra\":true}\n", "blank": "\n", "trailing-json": "{} {}\n"} {
		t.Run(name, func(t *testing.T) {
			if _, err := readDiscoveryPhaseEvents(strings.NewReader(writer.String() + tail)); err == nil {
				t.Fatal("accepted corrupt terminal tail")
			}
		})
	}
}

func TestDiscoveryPhaseEventsWallClockAndBoundedConcurrentState(t *testing.T) {
	writer := &phaseFixtureWriter{}
	journal := newPhaseFixtureJournal(t, writer)
	clock := int64(0)
	journal.now = func() discoveryPhaseInstant {
		clock++
		return discoveryPhaseInstant{wall: time.Unix(1000-clock, 0), tick: time.Duration(clock) * time.Second}
	}
	var workers sync.WaitGroup
	for index := 0; index < 16; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			for operation := 0; operation < 100; operation++ {
				if err := journal.run(phaseFixtureCandidate, "unit", fmt.Sprint(index), func() error { return nil }); err != nil {
					t.Error(err)
				}
			}
		}(index)
	}
	workers.Wait()
	if len(journal.active) != 0 || journal.lastSpan != 1600 {
		t.Fatalf("completed spans retained: active=%d total=%d", len(journal.active), journal.lastSpan)
	}
	if err := journal.close(nil); err != nil {
		t.Fatal(err)
	}
	summary, err := readDiscoveryPhaseEvents(bytes.NewReader(writer.Bytes()))
	if err != nil || summary.Spans != 1600 || summary.Failed != 0 {
		t.Fatalf("wall-clock reversal corrupted monotonic timing: summary=%+v error=%v", summary, err)
	}
	events := phaseFixtureRecords(t, writer.Bytes())
	for _, event := range events {
		if event.Kind == "span_end" && (event.ElapsedNS == nil || *event.ElapsedNS <= 0) {
			t.Fatalf("wall-clock reversal manufactured negative work: %+v", event)
		}
	}
}

func TestDiscoveryPhaseEventsActiveAdmissionAndPhysicalRoles(t *testing.T) {
	t.Run("active-bound-and-mismatched-end", func(t *testing.T) {
		writer := &phaseFixtureWriter{}
		journal := newPhaseFixtureJournal(t, writer)
		var spans []discoveryPhaseSpan
		for index := 0; index < discoveryPhaseActiveLimit; index++ {
			span, err := journal.begin(phaseFixtureCandidate, "unit", fmt.Sprint(index))
			if err != nil {
				t.Fatal(err)
			}
			spans = append(spans, span)
		}
		if _, err := journal.begin(phaseFixtureCandidate, "unit", "overflow"); !errors.Is(err, errDiscoveryPhaseEvents) {
			t.Fatal("unbounded active timing state admitted")
		}
		wrong := spans[0]
		wrong.event.Candidate = "example.com/foreign@v1.0.0"
		if err := journal.end(wrong, "complete", nil); !errors.Is(err, errDiscoveryPhaseEvents) || len(journal.active) != discoveryPhaseActiveLimit {
			t.Fatal("different candidate closed another span")
		}
		for _, span := range spans {
			if err := journal.end(span, "complete", nil); err != nil {
				t.Fatal(err)
			}
		}
		if err := journal.end(spans[0], "complete", nil); !errors.Is(err, errDiscoveryPhaseEvents) {
			t.Fatal("duplicate physical end admitted")
		}
		if err := journal.close(nil); err != nil {
			t.Fatal(err)
		}
	})
	for _, mode := range []string{"existing-file", "existing-symlink", "file-replaced", "parent-replaced", "tampered-tail", "unfinished"} {
		t.Run(mode, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "events")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(dir, "phase.jsonl")
			const canary = "foreign owner bytes must survive"
			if strings.HasPrefix(mode, "existing") {
				writeTestFile(t, name, canary)
				if mode == "existing-symlink" {
					link := filepath.Join(dir, "link.jsonl")
					if err := os.Symlink(name, link); err != nil {
						t.Fatal(err)
					}
					name = link
				}
			}
			journal, err := openDiscoveryPhaseJournal(name, discoveryCorpusConfig{ShardCount: 64}, discoveryCorpusProvenance{})
			if strings.HasPrefix(mode, "existing") {
				if err == nil || journal != nil {
					t.Fatal("existing source/alias was overwritten")
				}
				if data, err := os.ReadFile(name); err != nil || string(data) != canary {
					t.Fatal("existing canary changed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unfinished" {
				if _, err := journal.begin(phaseFixtureCandidate, "unit", ""); err != nil {
					t.Fatal(err)
				}
			} else if mode == "file-replaced" {
				if err := os.Rename(name, name+".original"); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, name, canary)
			} else if mode == "parent-replaced" {
				if err := os.Rename(dir, dir+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, name, canary)
			} else {
				file, err := os.OpenFile(name, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, writeErr := file.WriteString("{corrupt tail}\n")
				if err := errors.Join(writeErr, file.Close()); err != nil {
					t.Fatal(err)
				}
			}
			if err := journal.close(nil); !errors.Is(err, errDiscoveryPhaseEvents) {
				t.Fatalf("physical/tail/incomplete role became complete: %v", err)
			}
			if strings.HasSuffix(mode, "replaced") {
				if data, err := os.ReadFile(name); err != nil || string(data) != canary {
					t.Fatal("foreign replacement was removed or written")
				}
			}
		})
	}
}

func TestDiscoveryPhaseEventsDefaultReportAndActualCLIControls(t *testing.T) {
	cfg, candidates := exactDiscoveryFixtureCount(t, 1)
	cfg.ExactCandidates = []string{candidates[0].exactKey()}
	input := fixtureOrdinaryPassedResult(t, candidates[0], cfg.Targets)
	var reports []discoveryCorpusReport
	for _, enabled := range []bool{false, true} {
		cfg.EventsPath = ""
		if enabled {
			cfg.EventsPath = filepath.Join(t.TempDir(), "events.jsonl")
		}
		cfg.runCandidate = func(cfg discoveryCorpusConfig, candidate discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
			return fixtureProfileMatrix(t, input), input.ApplicableAsmFiles, input.BuildConfigurations, nil
		}
		if err := runDiscoveryCorpus(cfg); err != nil {
			t.Fatal(err)
		}
		report, err := readDiscoveryCorpusReport(cfg.ReportPath)
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, report)
	}
	if !reflect.DeepEqual(reports[0], reports[1]) || reports[0].SchemaVersion != 11 {
		t.Fatal("optional timing changed the complete source/profile/object report")
	}
	for _, args := range [][]string{{"-discovery-events=events.jsonl", "-list"}, {"-discovery-events=events.jsonl", "-discovery-progress=missing", "-discovery-ledger=missing"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		output, err := runDiscoveryExactCandidateTestCLI(ctx, t.TempDir(), "1", args...)
		cancel()
		if err == nil || !strings.Contains(string(output), "requires discovery execution") || strings.Contains(string(output), "flag provided but not defined") {
			t.Fatalf("actual timing CLI crossed into a reader mode: error=%v output=%s", err, output)
		}
	}
}

func TestDiscoveryPhaseEventsActualChildCancellationAndParentDeadline(t *testing.T) {
	name := filepath.Join(t.TempDir(), "child-events.jsonl")
	journal, err := openDiscoveryPhaseJournal(name, discoveryCorpusConfig{ShardCount: 64}, discoveryCorpusProvenance{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	cfg := discoveryCorpusConfig{CandidateTimeout: time.Minute, phaseEvents: journal}
	err = cfg.runPhaseOperationContext(ctx, discoveryCandidate{Module: "example.com/phase", Version: "v1.0.0"}, "header_query", "actual child", func(ctx context.Context) error {
		_, err := runDiscoveryExactCandidateTestCLI(ctx, t.TempDir(), "wait-for-deadline")
		return err
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timing lost parent cancellation: %v", err)
	}
	if err := journal.close(err); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := readDiscoveryPhaseEvents(bytes.NewReader(data))
	if err != nil || summary.Spans != 1 || summary.Failed != 1 {
		t.Fatalf("cancelled child became complete: summary=%+v error=%v", summary, err)
	}
}
