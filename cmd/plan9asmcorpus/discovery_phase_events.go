package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Timing is diagnostic, never a source, object, completion or ledger proof.
const discoveryPhaseEventsProtocol = "discovery_phase_events_v1"
const discoveryPhaseActiveLimit = 256

var errDiscoveryPhaseEvents = errors.New("requested discovery phase journal failed")

type discoveryPhaseEvent struct {
	Protocol   string                     `json:"protocol"`
	Sequence   uint64                     `json:"sequence"`
	Kind       string                     `json:"kind"`
	Span       uint64                     `json:"span,omitempty"`
	Candidate  string                     `json:"candidate,omitempty"`
	Phase      string                     `json:"phase,omitempty"`
	Scope      string                     `json:"scope,omitempty"`
	At         time.Time                  `json:"at"`
	ElapsedNS  *int64                     `json:"elapsed_ns,omitempty"`
	Status     string                     `json:"status,omitempty"`
	Error      string                     `json:"error,omitempty"`
	ShardIndex int                        `json:"shard_index,omitempty"`
	ShardCount int                        `json:"shard_count,omitempty"`
	Provenance *discoveryCorpusProvenance `json:"provenance,omitempty"`
}

type discoveryPhaseInstant struct {
	wall time.Time
	tick time.Duration
}

type discoveryPhaseSpan struct {
	event discoveryPhaseEvent
	start discoveryPhaseInstant
}

type discoveryPhaseJournal struct {
	mu       sync.Mutex
	writer   io.WriteCloser
	now      func() discoveryPhaseInstant
	sequence uint64
	lastSpan uint64
	active   map[uint64]discoveryPhaseSpan
	failure  error
	closed   bool
	verify   func() error
	readback func() error
}

func openDiscoveryPhaseJournal(name string, cfg discoveryCorpusConfig, provenance discoveryCorpusProvenance) (*discoveryPhaseJournal, error) {
	if name == "" {
		return nil, nil
	}
	name, err := filepath.Abs(name)
	if err != nil {
		return nil, phaseJournalError(err)
	}
	dir := filepath.Dir(name)
	physical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, phaseJournalError(err)
	}
	directory, err := os.Lstat(dir)
	if err != nil || !directory.IsDir() {
		return nil, phaseJournalError(fmt.Errorf("events parent is not a regular directory: %v", err))
	}
	// Never truncate an existing artifact, source file or symlink destination.
	// Append prevents this descriptor's old offset from overwriting a foreign
	// appended tail. The mandatory EOF readback must still reject that tail.
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, phaseJournalError(err)
	}
	original, err := file.Stat()
	if err != nil {
		return nil, phaseJournalError(errors.Join(err, file.Close()))
	}
	verify := func() error {
		actual, err := filepath.EvalSymlinks(dir)
		if err != nil || actual != physical {
			return fmt.Errorf("events parent physical role changed: %v", err)
		}
		after, err := os.Lstat(dir)
		if err != nil || !after.IsDir() || !os.SameFile(directory, after) {
			return fmt.Errorf("events parent directory changed: %v", err)
		}
		after, err = os.Lstat(name)
		if err != nil || !after.Mode().IsRegular() || !os.SameFile(original, after) {
			return fmt.Errorf("events file physical role changed: %v", err)
		}
		return nil
	}
	anchor := time.Now()
	journal := &discoveryPhaseJournal{writer: file, active: make(map[uint64]discoveryPhaseSpan), verify: verify,
		now: func() discoveryPhaseInstant {
			// Sub retains Go's monotonic clock; wall time is merely a label.
			now := time.Now()
			return discoveryPhaseInstant{wall: now.UTC(), tick: now.Sub(anchor)}
		},
	}
	journal.readback = func() error {
		if err := verify(); err != nil {
			return err
		}
		reader, err := os.Open(name)
		if err != nil {
			return err
		}
		_, readErr := readDiscoveryPhaseEvents(reader)
		return errors.Join(readErr, reader.Close(), verify())
	}
	if err := journal.record(discoveryPhaseEvent{Kind: "run_start", At: journal.now().wall,
		ShardIndex: cfg.ShardIndex, ShardCount: cfg.ShardCount, Provenance: &provenance}); err != nil {
		return nil, errors.Join(err, phaseJournalError(file.Close()))
	}
	return journal, nil
}

func phaseJournalError(err error) error {
	if err == nil {
		return nil
	}
	return errors.Join(errDiscoveryPhaseEvents, err)
}

// Caller holds mu (or has not published the journal). One writer owns all
// records. No completed-span or candidate map is retained.
func (journal *discoveryPhaseJournal) record(event discoveryPhaseEvent) error {
	if journal.failure != nil {
		return journal.failure
	}
	if journal.verify != nil {
		if err := journal.verify(); err != nil {
			journal.failure = phaseJournalError(err)
			return journal.failure
		}
	}
	event.Protocol, event.Sequence = discoveryPhaseEventsProtocol, journal.sequence+1
	data, err := json.Marshal(event)
	if err == nil {
		data = append(data, '\n')
		var n int
		n, err = journal.writer.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		journal.failure = phaseJournalError(err)
		return journal.failure
	}
	journal.sequence++
	return nil
}

func (journal *discoveryPhaseJournal) begin(candidate, phase, scope string) (discoveryPhaseSpan, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.closed || len(journal.active) >= discoveryPhaseActiveLimit || phase == "" || validateDiscoveryExactCandidateKey(candidate) != nil {
		return discoveryPhaseSpan{}, phaseJournalError(fmt.Errorf("invalid, closed or over-budget phase start"))
	}
	instant := journal.now()
	span := discoveryPhaseSpan{event: discoveryPhaseEvent{Kind: "span_start", Span: journal.lastSpan + 1,
		Candidate: candidate, Phase: phase, Scope: scope, At: instant.wall}, start: instant}
	if err := journal.record(span.event); err != nil {
		return discoveryPhaseSpan{}, err
	}
	journal.lastSpan++
	journal.active[span.event.Span] = span
	return span, nil
}

func (journal *discoveryPhaseJournal) end(span discoveryPhaseSpan, status string, operationErr error) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	original, present := journal.active[span.event.Span]
	if journal.closed || !present || original.event != span.event ||
		(status != "complete" && status != "failed" && status != "panic") || (status == "complete") != (operationErr == nil) {
		return phaseJournalError(fmt.Errorf("phase end differs from its active candidate/span"))
	}
	instant := journal.now()
	elapsed := int64(instant.tick - original.start.tick)
	if elapsed < 0 {
		return phaseJournalError(fmt.Errorf("phase monotonic clock moved backwards"))
	}
	event := original.event
	event.Kind, event.At, event.ElapsedNS, event.Status = "span_end", instant.wall, &elapsed, status
	if operationErr != nil {
		event.Error = operationErr.Error()
	}
	if err := journal.record(event); err != nil {
		return err
	}
	delete(journal.active, event.Span)
	return nil
}

func (journal *discoveryPhaseJournal) run(candidate, phase, scope string, operation func() error) (result error) {
	if journal == nil {
		return operation() // The default command/permission path is unchanged.
	}
	span, err := journal.begin(candidate, phase, scope)
	if err != nil {
		return err
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			_ = journal.end(span, "panic", fmt.Errorf("operation panic: %v", recovered))
			panic(recovered) // Timing cannot convert a panic into completion.
		}
		status := "complete"
		if result != nil {
			status = "failed"
		}
		result = errors.Join(result, journal.end(span, status, result))
	}()
	return operation()
}

func (journal *discoveryPhaseJournal) close(operationErr error) error {
	if journal == nil {
		return nil
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.closed {
		return phaseJournalError(fmt.Errorf("phase journal already closed"))
	}
	if len(journal.active) != 0 {
		journal.failure = errors.Join(journal.failure, phaseJournalError(fmt.Errorf("phase journal has %d unfinished spans", len(journal.active))))
	}
	event := discoveryPhaseEvent{Kind: "run_end", At: journal.now().wall, Status: "complete"}
	if operationErr != nil {
		event.Status, event.Error = "failed", operationErr.Error()
	}
	writeErr := journal.record(event)
	journal.closed = true
	closeErr := journal.writer.Close()
	var readErr error
	if journal.readback != nil {
		readErr = journal.readback()
	}
	return phaseJournalError(errors.Join(writeErr, closeErr, readErr))
}

func (cfg discoveryCorpusConfig) runPhaseOperation(candidate discoveryCandidate, phase, scope string, operation func(context.Context) error) error {
	return cfg.runPhaseOperationContext(context.Background(), candidate, phase, scope, operation)
}

func (cfg discoveryCorpusConfig) runPhaseOperationContext(parent context.Context, candidate discoveryCandidate, phase, scope string, operation func(context.Context) error) error {
	return cfg.phaseEvents.run(candidate.exactKey(), phase, scope, func() error {
		return runDiscoveryOperationContext(parent, cfg.CandidateTimeout, operation)
	})
}

type discoveryPhaseSummary struct {
	Spans, Failed, Panicked uint64
	Status                  string
}

func readDiscoveryPhaseEvents(reader io.Reader) (discoveryPhaseSummary, error) {
	var summary discoveryPhaseSummary
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), 32<<20)
	active := make(map[uint64]discoveryPhaseEvent)
	var sequence, lastSpan uint64
	ended := false
	for scanner.Scan() {
		var event discoveryPhaseEvent
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return discoveryPhaseSummary{}, fmt.Errorf("decode phase event: %w", err)
		}
		if err := ensureJSONEOF(decoder); err != nil {
			return discoveryPhaseSummary{}, err
		}
		if ended || event.Protocol != discoveryPhaseEventsProtocol || event.Sequence != sequence+1 || event.At.IsZero() {
			return discoveryPhaseSummary{}, fmt.Errorf("invalid phase protocol/sequence/terminal tail")
		}
		sequence++
		switch event.Kind {
		case "run_start":
			if sequence != 1 || event.ShardCount <= 0 || event.ShardIndex < 0 || event.ShardIndex >= event.ShardCount || event.Provenance == nil ||
				event.Span != 0 || event.Candidate != "" || event.Phase != "" || event.Scope != "" || event.ElapsedNS != nil || event.Status != "" || event.Error != "" {
				return discoveryPhaseSummary{}, fmt.Errorf("invalid phase run start")
			}
		case "span_start":
			if sequence == 1 || event.Span != lastSpan+1 || len(active) >= discoveryPhaseActiveLimit || event.Phase == "" || validateDiscoveryExactCandidateKey(event.Candidate) != nil ||
				event.ElapsedNS != nil || event.Status != "" || event.Error != "" || event.Provenance != nil || event.ShardIndex != 0 || event.ShardCount != 0 {
				return discoveryPhaseSummary{}, fmt.Errorf("invalid phase span start")
			}
			lastSpan = event.Span
			active[event.Span] = event
		case "span_end":
			start, present := active[event.Span]
			if !present || event.Candidate != start.Candidate || event.Phase != start.Phase || event.Scope != start.Scope || event.ElapsedNS == nil || *event.ElapsedNS < 0 ||
				event.Provenance != nil || event.ShardIndex != 0 || event.ShardCount != 0 ||
				(event.Status != "complete" && event.Status != "failed" && event.Status != "panic") || (event.Status == "complete") != (event.Error == "") {
				return discoveryPhaseSummary{}, fmt.Errorf("invalid phase span end")
			}
			delete(active, event.Span)
			summary.Spans++
			if event.Status != "complete" {
				summary.Failed++
			}
			if event.Status == "panic" {
				summary.Panicked++
			}
		case "run_end":
			// This status is the original top-level outcome, not an aggregate
			// assertion that every child succeeded. An existing caller may
			// handle a failed child; its failed span and cause remain recorded.
			if sequence == 1 || len(active) != 0 || event.Span != 0 || event.Candidate != "" || event.Phase != "" || event.Scope != "" || event.ElapsedNS != nil || event.Provenance != nil ||
				event.ShardIndex != 0 || event.ShardCount != 0 || (event.Status != "complete" && event.Status != "failed") ||
				(event.Status == "complete") != (event.Error == "") {
				return discoveryPhaseSummary{}, fmt.Errorf("invalid phase run end")
			}
			ended, summary.Status = true, event.Status
		default:
			return discoveryPhaseSummary{}, fmt.Errorf("unknown phase event %q", event.Kind)
		}
	}
	if err := scanner.Err(); err != nil {
		return discoveryPhaseSummary{}, err
	}
	if !ended || len(active) != 0 {
		return discoveryPhaseSummary{}, fmt.Errorf("phase journal is incomplete at EOF")
	}
	return summary, nil
}
