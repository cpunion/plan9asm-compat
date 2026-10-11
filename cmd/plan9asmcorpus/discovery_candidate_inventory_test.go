package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeDiscoveryForeignPayloadLedger(t *testing.T, directory bool, foreign int) (string, discoveryCandidate) {
	t.Helper()
	const shardIndex, shardCount = 36, 64
	selected := discoveryCandidate{Module: "example.com/exact/0000", Version: "v1.0.0",
		Architectures: []string{"amd64"}, AsmFiles: []string{"selected_amd64.s"}}
	for index := 0; discoveryCandidateShard(selected, shardCount) != shardIndex; index++ {
		selected.Module = fmt.Sprintf("example.com/selected/%06d", index)
	}
	ledger := filepath.Join(t.TempDir(), "ledger.jsonl")
	filePath := ledger
	if directory {
		if err := os.MkdirAll(filepath.Join(ledger, "records"), 0700); err != nil {
			t.Fatal(err)
		}
		filePath = filepath.Join(ledger, "records", "00.jsonl")
	}
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	writer := bufio.NewWriter(file)
	encoder := json.NewEncoder(writer)
	write := func(candidate discoveryCandidate) {
		t.Helper()
		err := encoder.Encode(discoveryRecord{Kind: "matched", Module: candidate.Module,
			Version: candidate.Version, Architectures: candidate.Architectures, AsmFiles: candidate.AsmFiles})
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	write(selected)
	prefix := strings.Repeat("nested_source_directory/", 32)
	paths := make([]string, 4)
	for index := range paths {
		paths[index] = fmt.Sprintf("%soperation%d_amd64.s", prefix, index)
	}
	for index, written := 0, 0; written < foreign; index++ {
		candidate := discoveryCandidate{Module: fmt.Sprintf("example.com/foreign/%06d", index),
			Version: "v1.0.0", Architectures: []string{"amd64", "arm64", "s390x"}, AsmFiles: paths}
		if discoveryCandidateShard(candidate, shardCount) == shardIndex {
			continue
		}
		write(candidate)
		written++
	}
	if err := writer.Flush(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return ledger, selected
}

func TestDiscoveryCorpusRetainsOnlySelectedShardPayload(t *testing.T) {
	const foreign, budget = 18000, 32 << 20
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprintf("directory=%t", directory), func(t *testing.T) {
			ledger, selected := writeDiscoveryForeignPayloadLedger(t, directory, foreign)
			provenance := fixtureDiscoveryProvenance(t, ledger)
			cause := errors.New("first-party memory orchestration fixture")
			cfg := discoveryCorpusConfig{
				LedgerPath: ledger, RepoRoot: t.TempDir(), ShardIndex: 36, ShardCount: 64,
				Targets: []string{"linux/amd64"}, CandidateTimeout: time.Minute,
				ReportPath: filepath.Join(t.TempDir(), "shard.json"),
				captureProvenance: func(discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
					return provenance, nil
				},
			}
			// Real repository startup loads both manifests, even when their
			// exceptions belong to another shard. Include those preflight paths.
			writeDiscoveryInventoryExceptionManifests(t, cfg.RepoRoot, ledger, selected.exactKey())
			calls := 0
			cfg.runCandidate = func(_ discoveryCorpusConfig, candidate discoveryCandidate, _ string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
				calls++
				if !reflect.DeepEqual(candidate, selected) {
					t.Errorf("selected payload changed: got %+v, want %+v", candidate, selected)
				}
				// An orchestration fixture is not translation/pass evidence.
				return matrixReport{}, nil, nil, cause
			}
			growth, err := sampleSupersededMatchedHeap(func() error {
				err := runDiscoveryCorpus(cfg)
				if err == nil || !strings.Contains(err.Error(), "failed=1") {
					return fmt.Errorf("intentional first-party failure was suppressed: %v", err)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			report, err := readDiscoveryCorpusReport(cfg.ReportPath)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || report.CandidateTotal != foreign+1 || report.EligibleCandidates != foreign+1 ||
				report.Partial || report.Selected != 1 || report.Failed != 1 || report.Passed != 0 ||
				report.NotApplicable != 0 || report.Results[0].Error != cause.Error() {
				t.Fatalf("global denominator/selected failure changed: calls=%d report=%+v", calls, report)
			}
			t.Logf("foreign matched=%d, paths/record=4, selected=1, sampled HeapAlloc growth=%d, budget=%d", foreign, growth, budget)
			if growth > budget {
				t.Errorf("corpus retains foreign shard payloads: sampled growth %d exceeds %d", growth, budget)
			}
		})
	}
}

func writeDiscoveryInventoryExceptionManifests(t *testing.T, root, ledger, selected string) {
	t.Helper()
	var foreign discoveryRecord
	if err := walkDiscoveryRecords(ledger, func(record discoveryRecord) error {
		if foreign.Module == "" && record.Kind == "matched" && record.Module+"@"+record.Version != selected {
			foreign = record
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if foreign.Module == "" {
		t.Fatal("missing foreign exception fixture")
	}
	dir := filepath.Join(root, "testdata", "corpus")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	private := discoveryPrivateExtensionManifest{SchemaVersion: 1,
		Skips: []discoveryPrivateExtensionSkip{{Module: foreign.Module, Version: foreign.Version,
			AsmFile: foreign.AsmFiles[0], Target: "darwin/arm64", SourceSHA256: strings.Repeat("a", 64),
			Opcode: "0x00201220", Reason: "first-party preflight fixture",
			EvidenceURLs: []string{"https://example.com/private-fixture"}}}}
	native := discoveryNativeLayoutManifest{SchemaVersion: 1,
		Skips: []discoveryNativeLayoutSkip{{Module: foreign.Module, Version: foreign.Version,
			AsmFile: foreign.AsmFiles[0], Targets: []string{"linux/amd64"}, SourceSHA256: strings.Repeat("a", 64),
			Symbol: "fixture", ObjectHex: "90", Reason: "first-party preflight fixture",
			EvidenceURLs: []string{"https://example.com/native-fixture"}}}}
	for name, manifest := range map[string]any{"private-extensions.json": private, "native-layout.json": native} {
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(dir, name), string(data))
	}
}

func appendDiscoveryInventoryRecords(t *testing.T, ledger string, records ...string) {
	t.Helper()
	info, err := os.Stat(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		ledger = filepath.Join(ledger, "records", "01.jsonl")
	}
	file, err := os.OpenFile(ledger, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if _, err := fmt.Fprintln(file, record); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryCandidateInventoryMatchesCompleteReference(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprintf("directory=%t", directory), func(t *testing.T) {
			ledger, selected := writeDiscoveryForeignPayloadLedger(t, directory, 4)
			duplicate := discoveryRecord{Kind: "matched", Module: selected.Module, Version: selected.Version,
				Architectures: []string{"amd64", "arm64", "unknown"},
				AsmFiles:      []string{"selected_amd64.s", "operation_linux_arm64.s", "operation_amd64x.s", "future_riscv64.s"}}
			encoded, err := json.Marshal(duplicate)
			if err != nil {
				t.Fatal(err)
			}
			appendDiscoveryInventoryRecords(t, ledger, string(encoded), string(encoded),
				`{"kind":"scanned","module":"example.com/noasm","version":"v1.0.0"}`,
				`{"kind":"failure","module":"example.com/retry","version":"@latest"}`)
			all, err := loadDiscoveryCandidates(ledger)
			if err != nil || len(all) != 5 {
				t.Fatalf("reference inventory: %v, %v", all, err)
			}
			identities := make([]discoveryCandidate, len(all))
			for index, candidate := range all {
				identities[index] = discoveryCandidate{Module: candidate.Module, Version: candidate.Version}
			}
			for _, targets := range [][]string{nil, {"linux/amd64"}, {"linux/riscv64"}, {"js/wasm", "windows/arm64"}} {
				t.Run(fmt.Sprintf("targets=%v", targets), func(t *testing.T) {
					eligible := all
					if targets != nil {
						eligible, err = filterDiscoveryCandidatesForTargets(all, targets)
						if err != nil {
							t.Fatal(err)
						}
					}
					seen := make(map[string]int)
					for shard := 0; shard < 8; shard++ {
						cfg := discoveryCorpusConfig{ShardIndex: shard, ShardCount: 8,
							FilterTargets: targets != nil, Targets: targets}
						got, err := loadDiscoveryCandidateInventory(ledger, cfg)
						if err != nil {
							t.Fatal(err)
						}
						want := selectDiscoveryShard(eligible, shard, 8)
						if !reflect.DeepEqual(got.Identities, identities) || got.Eligible != len(eligible) ||
							!reflect.DeepEqual(got.FullShard, want) {
							t.Fatalf("shard=%d inventory=%+v, want identities=%+v eligible=%d shard=%+v",
								shard, got, identities, len(eligible), want)
						}
						for _, candidate := range got.FullShard {
							seen[candidate.exactKey()]++
						}
					}
					for _, candidate := range eligible {
						if seen[candidate.exactKey()] != 1 {
							t.Fatalf("eligible candidate %s appears %d times", candidate.exactKey(), seen[candidate.exactKey()])
						}
					}
				})
			}
		})
	}
}

func TestDiscoveryCandidateInventoryValidatesUnselectedTail(t *testing.T) {
	for _, directory := range []bool{false, true} {
		for _, tail := range []string{
			"{truncated JSON",
			`{"kind":"matched","module":"example.com/foreign","version":"v1.0.0","asm_files":["../unsafe.s"]}`,
			`{"kind":"matched","module":"example.com/foreign","version":"v1.0.0","asm_files":[]}`,
			`{"kind":"matched","module":"bad module","version":"v1.0.0","asm_files":["safe_amd64.s"]}`,
			`{"kind":"matched","module":"example.com/foreign","version":"bad version","asm_files":["safe_amd64.s"]}`,
		} {
			t.Run(fmt.Sprintf("directory=%t/tail=%q", directory, tail), func(t *testing.T) {
				ledger, _ := writeDiscoveryForeignPayloadLedger(t, directory, 2)
				appendDiscoveryInventoryRecords(t, ledger, tail)
				for _, filtered := range []bool{false, true} {
					cfg := discoveryCorpusConfig{ShardIndex: 36, ShardCount: 64,
						FilterTargets: filtered, Targets: []string{"js/wasm"}}
					got, err := loadDiscoveryCandidateInventory(ledger, cfg)
					if err == nil || !reflect.DeepEqual(got, discoveryCandidateInventory{}) {
						t.Fatalf("filtered=%t concealed unselected invalid tail: %+v, %v", filtered, got, err)
					}
				}
			})
		}
	}
}

func TestDiscoveryCandidateInventoryRetainsForeignAliasMembership(t *testing.T) {
	ledger, _ := writeDiscoveryForeignPayloadLedger(t, true, 1)
	inventory, err := loadDiscoveryCandidateInventory(ledger, discoveryCorpusConfig{ShardIndex: 36, ShardCount: 64})
	if err != nil {
		t.Fatal(err)
	}
	var foreign discoveryCandidate
	for _, identity := range inventory.Identities {
		if discoveryCandidateShard(identity, 64) != 36 {
			foreign = identity
		}
	}
	if foreign.Module == "" || len(foreign.AsmFiles) != 0 || len(foreign.Architectures) != 0 {
		t.Fatalf("foreign identity carries no valid lightweight membership: %+v", foreign)
	}
	alias := discoveryEmbeddedModuleAlias{Module: foreign.Module, Version: foreign.Version,
		ModuleSum: "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", SourceDir: "nested",
		ImportModule: "example.com/original", EvidenceURL: "https://example.com/source"}
	root := t.TempDir()
	manifest := filepath.Join(root, "testdata", "corpus", "embedded-modules.json")
	if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
		t.Fatal(err)
	}
	for _, valid := range []bool{true, false} {
		if !valid {
			alias.Version = "v1.0.1"
		}
		data, err := json.Marshal(discoveryEmbeddedModuleManifest{SchemaVersion: 1, Aliases: []discoveryEmbeddedModuleAlias{alias}})
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, manifest, string(data))
		aliases, err := loadDiscoveryEmbeddedModuleAliases(root, inventory.Identities)
		if valid {
			if err != nil || aliases[foreign.exactKey()] != alias {
				t.Fatalf("foreign ledger membership lost: %v, %v", aliases, err)
			}
		} else if err == nil || aliases != nil {
			t.Fatalf("unknown exact alias version accepted: %v, %v", aliases, err)
		}
	}
}

func TestDiscoveryAssemblyFileMembershipRetainsOnlyExactInterests(t *testing.T) {
	ledger, selected := writeDiscoveryForeignPayloadLedger(t, true, 2)
	key := discoveryAssemblyFileKey{Module: selected.Module, Version: selected.Version, AsmFile: selected.AsmFiles[0]}
	duplicate := discoveryRecord{Kind: "matched", Module: key.Module, Version: key.Version,
		AsmFiles: []string{key.AsmFile, "second_arm64.s"}}
	data, err := json.Marshal(duplicate)
	if err != nil {
		t.Fatal(err)
	}
	appendDiscoveryInventoryRecords(t, ledger, string(data), string(data),
		`{"kind":"scanned","module":"example.com/noasm","version":"v1.0.0"}`)
	second := key
	second.AsmFile = "second_arm64.s"
	wrongVersion, wrongFile, ignored := key, key, key
	wrongVersion.Version = "v1.0.1"
	wrongFile.AsmFile = "missing.s"
	ignored.Module = "example.com/noasm"
	interests := map[discoveryAssemblyFileKey]bool{key: true, second: true,
		wrongVersion: true, wrongFile: true, ignored: false}
	before := make(map[discoveryAssemblyFileKey]bool, len(interests))
	for key, value := range interests {
		before[key] = value
	}
	got, err := discoveryAssemblyFileMembershipFor(ledger, interests)
	if err != nil || !reflect.DeepEqual(got, map[discoveryAssemblyFileKey]bool{key: true, second: true}) ||
		!reflect.DeepEqual(interests, before) {
		t.Fatalf("exact membership changed: got=%v input=%v err=%v", got, interests, err)
	}
}

func TestDiscoveryExceptionPreflightValidatesUnselectedTailAndEmptyInterests(t *testing.T) {
	for _, directory := range []bool{false, true} {
		for _, empty := range []bool{false, true} {
			for _, tail := range []string{"{truncated JSON",
				`{"kind":"matched","module":"example.com/foreign","version":"v1.0.0","asm_files":["../unsafe.s"]}`,
				`{"kind":"matched","module":"example.com/foreign","version":"v1.0.0","asm_files":[]}`} {
				t.Run(fmt.Sprintf("directory=%t/empty=%t/tail=%q", directory, empty, tail), func(t *testing.T) {
					ledger, selected := writeDiscoveryForeignPayloadLedger(t, directory, 2)
					root := t.TempDir()
					writeDiscoveryInventoryExceptionManifests(t, root, ledger, selected.exactKey())
					if empty {
						for _, name := range []string{"private-extensions.json", "native-layout.json"} {
							writeTestFile(t, filepath.Join(root, "testdata", "corpus", name), `{"schema_version":1,"skips":[]}`)
						}
					}
					appendDiscoveryInventoryRecords(t, ledger, tail)
					if got, err := discoveryAssemblyFileMembershipFor(ledger, nil); err == nil || got != nil {
						t.Fatalf("empty interests hid invalid tail: %v, %v", got, err)
					}
					if got, err := loadPrivateExtensionSkips(root, ledger); err == nil || got != nil {
						t.Fatalf("private manifest hid invalid tail: %v, %v", got, err)
					}
					if got, err := loadNativeLayoutSkips(root, ledger); err == nil || got != nil {
						t.Fatalf("native manifest hid invalid tail: %v, %v", got, err)
					}
				})
			}
		}
	}
}
