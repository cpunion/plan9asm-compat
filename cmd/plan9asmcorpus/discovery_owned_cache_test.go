package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiscoveryShardCreatesOwnedBuildCacheBeforeCandidate(t *testing.T) {
	root := t.TempDir()
	temporary := filepath.Join(root, "temporary")
	if err := os.Mkdir(temporary, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", temporary)
	t.Setenv("TMP", temporary)
	t.Setenv("TEMP", temporary)
	ledger := filepath.Join(root, "records.jsonl")
	writeTestFile(t, ledger, `{"kind":"matched","module":"example.invalid/owned-cache","version":"v1.0.0","architectures":["amd64"],"asm_files":["probe_amd64.s"]}`+"\n")
	var observedCache string
	err := runDiscoveryCorpus(discoveryCorpusConfig{
		LedgerPath: ledger, ShardCount: 1, CandidateTimeout: time.Minute,
		Targets: []string{"linux/amd64"},
		captureProvenance: func(discoveryCorpusConfig) (discoveryCorpusProvenance, error) {
			return fixtureDiscoveryProvenance(t, ledger), nil
		},
		runCandidate: func(cfg discoveryCorpusConfig, candidate discoveryCandidate, workDir string) (matrixReport, []string, []discoveryBuildConfiguration, error) {
			observedCache = cfg.buildCache
			if cfg.buildCache != filepath.Join(filepath.Dir(workDir), "build-cache") {
				t.Errorf("default cache is outside the exact owned shard workspace: %s", cfg.buildCache)
			}
			info, err := os.Stat(cfg.buildCache)
			if err != nil || !info.IsDir() {
				t.Errorf("actual tool routing cannot resolve an uncreated cache: %v", err)
			}
			result := fixtureOrdinaryPassedResult(t, candidate, cfg.Targets)
			return fixtureProfileMatrix(t, result), result.ApplicableAsmFiles, result.BuildConfigurations, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if observedCache == "" {
		t.Fatal("candidate never observed the owned cache")
	}
	if _, err := os.Stat(observedCache); !os.IsNotExist(err) {
		t.Fatalf("owned cache outlived the normal shard cleanup lifecycle: %v", err)
	}
}
