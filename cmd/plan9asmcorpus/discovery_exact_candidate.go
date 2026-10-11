package main

import (
	"fmt"
	"strings"

	"golang.org/x/mod/semver"
)

// Exact requests limit execution, never the scan, shard or proof denominator.
type discoveryExactCandidateFlags []string

func (values *discoveryExactCandidateFlags) String() string {
	return strings.Join(*values, ",")
}

func (values *discoveryExactCandidateFlags) Set(value string) error {
	if err := validateDiscoveryExactCandidateKey(value); err != nil {
		return err
	}
	for _, previous := range *values {
		if previous == value {
			return fmt.Errorf("duplicate exact discovery candidate %q", value)
		}
	}
	*values = append(*values, value)
	return nil
}

func validateDiscoveryExactCandidateKey(key string) error {
	parts := strings.Split(key, "@")
	if len(parts) != 2 || parts[0] == "" || strings.ContainsAny(key, " \r\n\t") || !semver.IsValid(parts[1]) {
		return fmt.Errorf("exact discovery candidate must be module@version with a pinned Go version, got %q", key)
	}
	return nil
}

func validateDiscoveryExactCandidateMode(keys []string, ledger string, targetFiltered, otherMode bool) error {
	if len(keys) == 0 {
		return nil
	}
	if ledger == "" || targetFiltered || otherMode {
		return fmt.Errorf("-discovery-exact-candidate requires unfiltered discovery production, not a reader or curated mode")
	}
	return nil
}

func selectDiscoveryExactCandidates(cfg discoveryCorpusConfig, all, fullShard []discoveryCandidate) ([]discoveryCandidate, error) {
	if len(cfg.ExactCandidates) == 0 {
		return fullShard, nil
	}
	if err := validateDiscoveryExactCandidateMode(cfg.ExactCandidates, cfg.LedgerPath, cfg.FilterTargets, false); err != nil {
		return nil, err
	}
	known := make(map[string]discoveryCandidate, len(all))
	for _, candidate := range all {
		known[candidate.exactKey()] = candidate
	}
	requested := make(map[string]bool, len(cfg.ExactCandidates))
	for _, key := range cfg.ExactCandidates {
		if err := validateDiscoveryExactCandidateKey(key); err != nil {
			return nil, err
		}
		if requested[key] {
			return nil, fmt.Errorf("duplicate exact discovery candidate %q", key)
		}
		candidate, ok := known[key]
		if !ok {
			return nil, fmt.Errorf("exact discovery candidate %q is not a current ledger match", key)
		}
		if shard := discoveryCandidateShard(candidate, cfg.ShardCount); shard != cfg.ShardIndex {
			return nil, fmt.Errorf("exact discovery candidate %q belongs to shard %d/%d, not %d", key, shard, cfg.ShardCount, cfg.ShardIndex)
		}
		requested[key] = true
	}
	selected := make([]discoveryCandidate, 0, len(requested))
	for _, candidate := range fullShard {
		if requested[candidate.exactKey()] {
			selected = append(selected, candidate)
		}
	}
	if len(selected) != len(requested) {
		return nil, fmt.Errorf("exact discovery execution inventory differs from its complete shard")
	}
	return selected, nil
}
