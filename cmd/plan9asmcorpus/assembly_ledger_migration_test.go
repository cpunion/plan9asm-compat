package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func legacyPendingLedgerFixture(t *testing.T) (string, discoveryProgress, string) {
	t.Helper()
	ledger, reports, source := writeDiscoveryReportFixture(t)
	for _, shard := range []string{"shard-0.json", "shard-1.json"} {
		if err := os.Remove(filepath.Join(reports, shard)); err != nil {
			t.Fatal(err)
		}
	}
	progress, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	semanticSource := strings.Repeat("a", 64)
	if err := writeAssemblyLedger(output, progress, semanticSource); err != nil {
		t.Fatal(err)
	}
	mutateLegacyLedgerManifest(t, output, func(manifest *assemblyLedgerManifest) {
		manifest.Format = "module-hashed-assembly-ledger-v1"
		manifest.Progress.SchemaVersion = 1
		manifest.Progress.FeatureInventory = nil
	})
	return output, progress, semanticSource
}

func mutateLegacyLedgerManifest(t *testing.T, output string, mutate func(*assemblyLedgerManifest)) {
	t.Helper()
	file := filepath.Join(output, "manifest.json")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var manifest assemblyLedgerManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	mutate(&manifest)
	data, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestAssemblyLedgerWriterReplacesValidatedLegacyPendingOnly(t *testing.T) {
	output, pending, oldSource := legacyPendingLedgerFixture(t)
	if _, err := readAssemblyLedger(output, pending.LedgerSHA256, oldSource); err == nil {
		t.Fatal("ordinary reader accepted legacy evidence without current profile proofs")
	}
	ledger, reports, source := writeDiscoveryReportFixture(t)
	actual, err := collectDiscoveryProgress(ledger, reports, []string{"linux/amd64", "linux/arm64"}, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	newSource := strings.Repeat("b", 64)
	if err := writeAssemblyLedger(output, actual, newSource); err != nil {
		t.Fatalf("fresh audited reports cannot replace the intact legacy pending queue: %v", err)
	}
	got, err := readAssemblyLedger(output, actual.LedgerSHA256, newSource)
	if err != nil {
		t.Fatal(err)
	}
	if err := compareAssemblyLedgerProgress(got, actual); err != nil {
		t.Fatalf("migration changed fresh audited evidence: %v", err)
	}
}

func TestAssemblyLedgerLargePendingRecordRoundTrip(t *testing.T) {
	_, progress, source := legacyPendingLedgerFixture(t)
	// Stress serialization only: this artificial pending path is never counted
	// as a scanned module, a translation or an executed corpus pass.
	progress.Candidates[0].Module = "example.com/" + strings.Repeat("nested/", 11000) + "pending"
	encoded, err := json.Marshal(progress.Candidates[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) <= 64*1024 {
		t.Fatal("fixture did not exceed Scanner's default token limit")
	}
	output := filepath.Join(t.TempDir(), "assembly-ledger")
	if err := writeAssemblyLedger(output, progress, source); err != nil {
		t.Fatal(err)
	}
	got, err := readAssemblyLedger(output, progress.LedgerSHA256, source)
	if err != nil {
		t.Fatalf("writer published evidence its own reader cannot consume: %v", err)
	}
	if got.CandidateTotal != progress.CandidateTotal || got.Pending != progress.Pending || got.Passed != 0 || got.Verified {
		t.Fatalf("large pending record changed outcome accounting: %+v", got)
	}
	for _, candidate := range got.Candidates {
		if candidate.Module == progress.Candidates[0].Module {
			return
		}
	}
	t.Fatal("large pending record was lost")
}

func TestAssemblyLedgerLegacyReplacementRefusesClaimedOrDamagedEvidence(t *testing.T) {
	for _, name := range []string{"outcome", "reported shard", "wrong schema", "unknown format", "tampered shard", "record proof", "unknown field", "unrelated file"} {
		t.Run(name, func(t *testing.T) {
			output, progress, source := legacyPendingLedgerFixture(t)
			mutateLegacyLedgerManifest(t, output, func(manifest *assemblyLedgerManifest) {
				switch name {
				case "outcome":
					manifest.Progress.Passed = 1
				case "reported shard":
					manifest.Progress.ReportedShards = 1
				case "wrong schema":
					manifest.Progress.SchemaVersion = discoveryProgressSchema
				case "unknown format":
					manifest.Format = "unknown-ledger"
				}
			})
			if name == "tampered shard" {
				shards, err := filepath.Glob(filepath.Join(output, "records", "*.jsonl"))
				if err != nil || len(shards) == 0 {
					t.Fatalf("fixture shards: %v: %v", shards, err)
				}
				if err := os.WriteFile(shards[0], []byte("{}\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if name == "unrelated file" {
				writeTestFile(t, filepath.Join(output, "keep.txt"), "owned by someone else\n")
			}
			if name == "record proof" || name == "unknown field" {
				mutateLegacyLedgerManifest(t, output, func(manifest *assemblyLedgerManifest) {
					shard := &manifest.Shards[0]
					file := filepath.Join(output, "records", shard.Name)
					data, err := os.ReadFile(file)
					if err != nil {
						t.Fatal(err)
					}
					lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
					var record map[string]any
					if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
						t.Fatal(err)
					}
					if name == "record proof" {
						record["feature_profiles"] = []discoveryFeatureProfileReference{{ID: strings.Repeat("a", 64)}}
					} else {
						record["future_evidence"] = "must not silently discard"
					}
					encoded, err := json.Marshal(record)
					if err != nil {
						t.Fatal(err)
					}
					lines[0] = string(encoded)
					data = []byte(strings.Join(lines, "\n") + "\n")
					if err := os.WriteFile(file, data, 0644); err != nil {
						t.Fatal(err)
					}
					digest := sha256.Sum256(data)
					shard.SHA256 = fmt.Sprintf("%x", digest)
				})
			}
			manifest := filepath.Join(output, "manifest.json")
			before, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeAssemblyLedger(output, progress, source); err == nil {
				t.Fatal("replaced an unrecognized, claimed or damaged legacy ledger")
			}
			after, err := os.ReadFile(manifest)
			if err != nil || string(before) != string(after) {
				t.Fatalf("rejected existing evidence was modified: %v", err)
			}
		})
	}
}
