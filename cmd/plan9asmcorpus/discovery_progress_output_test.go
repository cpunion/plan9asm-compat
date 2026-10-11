package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestDiscoveryProgressOutputPublishesFreshCompleteJSON(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "assembly-progress.json")
	if err := writeDiscoveryProgressOutput(filename, progress); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var restored discoveryProgress
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&restored); err != nil {
		t.Fatal(err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		t.Fatal(err)
	}
	originalJSON, err := json.Marshal(progress)
	if err != nil {
		t.Fatal(err)
	}
	restoredJSON, err := json.Marshal(restored)
	if err != nil {
		t.Fatal(err)
	}
	// Empty omitted slices decode as nil. Compare every retained wire field,
	// rather than requiring an in-memory representation JSON cannot preserve.
	if !bytes.Equal(originalJSON, restoredJSON) {
		t.Fatal("publication changed the audited object")
	}
	if err := writeDiscoveryProgressOutput(filename, progress); err == nil {
		t.Fatal("overwrote previously published evidence")
	}
	unchanged, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(unchanged, data) {
		t.Fatal("failed repeat changed the original progress")
	}
	checkProgressOutputCleanup(t, filepath.Dir(filename))
}

func TestDiscoveryProgressOutputRejectsUnsafeOrOccupiedDestination(t *testing.T) {
	for _, name := range []string{"relative", "shard filename", "missing parent", "occupied", "symlink"} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			filename := filepath.Join(parent, "assembly-progress.json")
			var retained string
			switch name {
			case "relative":
				filename = "assembly-progress.json"
			case "shard filename":
				filename = filepath.Join(parent, "shard-1.json")
			case "missing parent":
				filename = filepath.Join(parent, "missing", "assembly-progress.json")
			case "occupied":
				retained = filename
				writeTestFile(t, filename, "original evidence\n")
			case "symlink":
				retained = filepath.Join(parent, "original.json")
				writeTestFile(t, retained, "original evidence\n")
				if err := os.Symlink(retained, filename); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeDiscoveryProgressOutput(filename, discoveryProgress{}); err == nil {
				t.Fatalf("accepted %s destination", name)
			}
			if retained != "" {
				data, err := os.ReadFile(retained)
				if err != nil || string(data) != "original evidence\n" {
					t.Fatal("failed publication modified prior evidence")
				}
			}
			checkProgressOutputCleanup(t, parent)
		})
	}
}

func TestDiscoveryProgressOutputConcurrentPublicationHasOneWinner(t *testing.T) {
	parent := t.TempDir()
	filename := filepath.Join(parent, "assembly-progress.json")
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- writeDiscoveryProgressOutput(filename, discoveryProgress{})
		}()
	}
	wait.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("publication winners = %d, want one", winners)
	}
	checkProgressOutputCleanup(t, parent)
}

func checkProgressOutputCleanup(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".assembly-progress-") {
			t.Fatalf("owned temporary output retained: %s", entry.Name())
		}
	}
}
