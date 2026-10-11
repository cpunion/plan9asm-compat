package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryProgressRejectsPreviousShardLayout(t *testing.T) {
	ledger, reports, source := writeDiscoveryReportFixture(t)
	file := filepath.Join(reports, "shard-0.json")
	report, err := readDiscoveryCorpusReport(file)
	if err != nil {
		t.Fatal(err)
	}
	report.ShardCount = 64
	if err := writeDiscoveryCorpusReport(file, report); err != nil {
		t.Fatal(err)
	}

	_, err = collectDiscoveryProgress(ledger, reports,
		[]string{"linux/amd64", "linux/arm64"}, source, 128)
	if err == nil || !strings.Contains(err.Error(), "shard_count") {
		t.Fatalf("old shard layout error = %v, want shard_count rejection", err)
	}
}

func TestDiscoveryShardSplitPreservesEveryParentCandidate(t *testing.T) {
	// Distinct version lines and non-ASCII paths exercise the exact-key bytes;
	// changing the scheduler must not change or drop the candidate denominator.
	candidates := make([]discoveryCandidate, 4096)
	for index := range candidates {
		candidates[index] = discoveryCandidate{
			Module:  fmt.Sprintf("example.com/模块-%03d/v%d", index/4, index%4+1),
			Version: fmt.Sprintf("v%d.2.0-pre.3", index%4+1),
		}
	}

	const oldCount, newCount = 64, 128
	seen := make(map[string]int, len(candidates))
	for parent := 0; parent < oldCount; parent++ {
		want := make(map[string]bool)
		for _, candidate := range selectDiscoveryShard(candidates, parent, oldCount) {
			want[candidate.exactKey()] = true
		}
		if len(want) == 0 {
			t.Fatalf("fixture misses parent %d", parent)
		}
		for _, child := range []int{parent, parent + oldCount} {
			selected := selectDiscoveryShard(candidates, child, newCount)
			if len(selected) == 0 {
				t.Fatalf("fixture misses child %d", child)
			}
			for _, candidate := range selected {
				key := candidate.exactKey()
				if !want[key] {
					t.Fatalf("child %d contains unexpected or duplicate candidate %s", child, key)
				}
				delete(want, key)
				seen[key]++
			}
		}
		if len(want) != 0 {
			t.Fatalf("parent %d lost %d candidates", parent, len(want))
		}
	}
	for _, candidate := range candidates {
		if seen[candidate.exactKey()] != 1 {
			t.Fatalf("candidate %s occurs %d times, want one", candidate.exactKey(), seen[candidate.exactKey()])
		}
	}
}
