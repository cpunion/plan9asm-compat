package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeSupersededInterestLedger(t *testing.T, directory bool, unrelated int, tail string) string {
	t.Helper()
	ledger := filepath.Join(t.TempDir(), "ledger.jsonl")
	if directory {
		ledger = filepath.Join(t.TempDir(), "ledger")
		if err := os.MkdirAll(filepath.Join(ledger, "records"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	path := ledger
	if directory {
		path = filepath.Join(ledger, "records", "00.jsonl")
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := bufio.NewWriter(file)
	for _, record := range []string{
		`{"kind":"matched","module":"example.com/old","version":"v1.2.0","architectures":["amd64"],"asm_files":["old_amd64.s"]}`,
		`{"kind":"scanned","module":"example.com/current","version":"v1.3.0"}`,
		`{"kind":"matched","module":"example.com/assembly","version":"v1.4.0","architectures":["arm64"],"asm_files":["assembly_arm64.s"]}`,
	} {
		if _, err := fmt.Fprintln(writer, record); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	for index := 0; index < unrelated; index++ {
		if _, err := fmt.Fprintf(writer, "{\"kind\":\"scanned\",\"module\":\"example.com/unrelated%06d\",\"version\":\"v1.0.0\"}\n", index); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if !directory {
		if _, err := writer.WriteString(tail); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if directory && tail != "" {
		writeTestFile(t, filepath.Join(ledger, "records", "ff.jsonl"), tail)
	}
	return ledger
}

func writeSupersededInterestManifest(t *testing.T, skips []discoverySupersededSkip) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "testdata", "corpus"), 0755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(discoverySupersededManifest{SchemaVersion: 1, Skips: skips})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "testdata", "corpus", "superseded-modules.json"), string(data))
	return root
}

func supersededInterestSkip(module, version string) discoverySupersededSkip {
	return discoverySupersededSkip{
		Module: "example.com/old", Version: "v1.2.0",
		ReplacementModule: module, ReplacementVersion: version,
		Reason: "reviewed renamed project", EvidenceURLs: []string{"https://example.com/proof"},
	}
}

func TestSupersededReplacementKeysRetainOnlyExactInterests(t *testing.T) {
	const unrelated = 60000
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprintf("directory=%t", directory), func(t *testing.T) {
			ledger := writeSupersededInterestLedger(t, directory, unrelated, "")
			requested := map[string]bool{
				"example.com/current@v1.3.0":  true,
				"example.com/assembly@v1.4.0": true,
				"example.com/absent@v1.5.0":   true,
			}
			want := map[string]bool{
				"example.com/current@v1.3.0":  true,
				"example.com/assembly@v1.4.0": true,
			}
			keys, err := scannedDiscoveryVersionKeysFor(ledger, requested)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("unrelated scanned=%d, requested=%d, retained keys=%d", unrelated, len(requested), len(keys))
			if len(keys) > len(requested) || !reflect.DeepEqual(keys, want) {
				t.Fatalf("replacement lookup retained %d keys, want exactly %d requested successes", len(keys), len(want))
			}
			all, err := scannedDiscoveryVersionKeys(ledger)
			if err != nil || len(all) != unrelated+3 {
				t.Fatalf("full reference retained %d keys, want %d: %v", len(all), unrelated+3, err)
			}
			for key := range requested {
				if keys[key] != all[key] {
					t.Errorf("exact interest %s differs from the full reference", key)
				}
			}
			if !requested["example.com/absent@v1.5.0"] || len(requested) != 3 {
				t.Fatal("replacement lookup modified caller interests")
			}
		})
	}
}

func TestSupersededReplacementKeysEmptyInterestsStillReadAllInput(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprintf("directory=%t", directory), func(t *testing.T) {
			ledger := writeSupersededInterestLedger(t, directory, 1000, "")
			keys, err := scannedDiscoveryVersionKeysFor(ledger, map[string]bool{})
			if err != nil || len(keys) != 0 {
				t.Fatalf("empty interests retained %d keys: %v", len(keys), err)
			}
			corrupt := writeSupersededInterestLedger(t, directory, 1000, "{unselected broken JSON}\n")
			if _, err := scannedDiscoveryVersionKeysFor(corrupt, map[string]bool{}); err == nil {
				t.Fatal("empty interests hid a corrupt unselected tail")
			}
			root := writeSupersededInterestManifest(t, nil)
			if _, err := loadSupersededSkips(root, corrupt); err == nil {
				t.Fatal("empty manifest hid a corrupt ledger")
			}
		})
	}
}

func TestSupersededInterestLookupPreservesExactReplacementObligations(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprintf("directory=%t", directory), func(t *testing.T) {
			ledger := writeSupersededInterestLedger(t, directory, 1000, "")
			before, err := loadDiscoveryCandidates(ledger)
			if err != nil {
				t.Fatal(err)
			}
			for _, replacement := range []struct {
				module, version string
			}{
				{"example.com/current", "v1.3.0"},  // Scanned, with no assembly.
				{"example.com/assembly", "v1.4.0"}, // Matched legacy fixture compatibility.
			} {
				root := writeSupersededInterestManifest(t, []discoverySupersededSkip{supersededInterestSkip(replacement.module, replacement.version)})
				skips, err := loadSupersededSkips(root, ledger)
				if err != nil || len(skips) != 1 {
					t.Fatalf("proved replacement %s@%s: %v, %v", replacement.module, replacement.version, skips, err)
				}
			}
			after, err := loadDiscoveryCandidates(ledger)
			if err != nil || !reflect.DeepEqual(before, after) || len(after) != 2 {
				t.Fatalf("supersession changed the matched candidate denominator: %v, %v", after, err)
			}
			for _, replacement := range []struct {
				module, version string
			}{
				{"example.com/unknown", "v1.3.0"},
				{"example.com/current", "v1.3.1"},
				{"example.com/current", "v2.0.0"},
				{"example.com/current", "v1.2.0"},
			} {
				root := writeSupersededInterestManifest(t, []discoverySupersededSkip{supersededInterestSkip(replacement.module, replacement.version)})
				if _, err := loadSupersededSkips(root, ledger); err == nil {
					t.Errorf("unproved replacement %s@%s was accepted", replacement.module, replacement.version)
				}
			}
		})
	}
}

func TestSupersededInterestLookupRejectsUnselectedTailAfterAllKeysFound(t *testing.T) {
	for _, directory := range []bool{false, true} {
		for _, tail := range []string{
			"{unselected broken JSON}\n",
			`{"kind":"matched","module":"example.com/unselected","version":"v1.5.0","architectures":["amd64"],"asm_files":[]}` + "\n",
		} {
			t.Run(fmt.Sprintf("directory=%t/tail=%q", directory, tail), func(t *testing.T) {
				ledger := writeSupersededInterestLedger(t, directory, 1000, tail)
				root := writeSupersededInterestManifest(t, []discoverySupersededSkip{supersededInterestSkip("example.com/current", "v1.3.0")})
				if _, err := loadSupersededSkips(root, ledger); err == nil {
					t.Fatal("found replacement hid an invalid unselected tail")
				}
			})
		}
	}
	corrupt := writeSupersededInterestLedger(t, false, 1000, "{unselected broken JSON}\n")
	if _, err := scannedDiscoveryVersionKeysFor(corrupt, map[string]bool{"example.com/current@v1.3.0": true}); err == nil {
		t.Fatal("replacement key reader stopped before EOF after finding its only interest")
	}
}
