package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// These are reviewed, exact historical module versions whose upstream project
// has a newer scanned version. They are not successful assembly translations.
type discoverySupersededSkip struct {
	Module             string   `json:"module"`
	Version            string   `json:"version"`
	ReplacementModule  string   `json:"replacement_module"`
	ReplacementVersion string   `json:"replacement_version"`
	Reason             string   `json:"reason"`
	EvidenceURLs       []string `json:"evidence_urls"`
}

type discoverySupersededManifest struct {
	SchemaVersion int                       `json:"schema_version"`
	Skips         []discoverySupersededSkip `json:"skips"`
}

func loadSupersededSkips(repoRoot, ledgerPath string) (map[string]discoverySupersededSkip, error) {
	manifestPath := filepath.Join(repoRoot, "testdata", "corpus", "superseded-modules.json")
	data, err := os.ReadFile(manifestPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var manifest discoverySupersededManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("decode superseded-module manifest: %w", err)
	}
	if manifest.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported superseded-module manifest schema %d", manifest.SchemaVersion)
	}

	oldVersions := make(map[string]bool, len(manifest.Skips))
	replacements := make(map[string]bool, len(manifest.Skips))
	for _, skip := range manifest.Skips {
		oldVersions[skip.Module+"@"+skip.Version] = true
		replacements[skip.ReplacementModule+"@"+skip.ReplacementVersion] = true
	}
	matched, scanned, err := discoveryVersionKeysFor(ledgerPath, oldVersions, replacements)
	if err != nil {
		return nil, err
	}

	skips := make(map[string]discoverySupersededSkip, len(manifest.Skips))
	for _, skip := range manifest.Skips {
		key := skip.Module + "@" + skip.Version
		replacement := skip.ReplacementModule + "@" + skip.ReplacementVersion
		if _, ok := skips[key]; ok {
			return nil, fmt.Errorf("duplicate superseded-module skip %s", key)
		}
		if err := module.CheckPath(skip.Module); err != nil {
			return nil, fmt.Errorf("invalid superseded module %q: %w", skip.Module, err)
		}
		if err := module.CheckPath(skip.ReplacementModule); err != nil {
			return nil, fmt.Errorf("invalid replacement module %q: %w", skip.ReplacementModule, err)
		}
		if !semver.IsValid(skip.Version) || !semver.IsValid(skip.ReplacementVersion) ||
			semver.Compare(skip.ReplacementVersion, skip.Version) <= 0 {
			return nil, fmt.Errorf("%s: replacement %s is not a newer Go module version", key, replacement)
		}
		if !matched[key] || !scanned[replacement] {
			return nil, fmt.Errorf("%s: old assembly or replacement %s is absent from the scan ledger", key, replacement)
		}
		if strings.TrimSpace(skip.Reason) == "" || len(skip.EvidenceURLs) == 0 {
			return nil, fmt.Errorf("%s: supersession lacks reason or evidence", key)
		}
		for _, rawURL := range skip.EvidenceURLs {
			parsed, err := url.Parse(rawURL)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
				return nil, fmt.Errorf("%s: invalid supersession evidence URL %q", key, rawURL)
			}
		}
		skips[key] = skip
	}
	return skips, nil
}

// The full-key helper remains available for reference checks. Normal exception
// loading passes a nonnil set of exact replacement interests instead.
func scannedDiscoveryVersionKeys(ledgerPath string) (map[string]bool, error) {
	return scannedDiscoveryVersionKeysFor(ledgerPath, nil)
}

func scannedDiscoveryVersionKeysFor(ledgerPath string, requested map[string]bool) (map[string]bool, error) {
	_, scanned, err := discoveryVersionKeysFor(ledgerPath, nil, requested)
	return scanned, err
}

// Only requested old matched keys are retained. Nil scanned interests preserve
// the full reference helper; normal exception loading passes two nonnil sets.
func discoveryVersionKeysFor(ledgerPath string, matchedRequested, scannedRequested map[string]bool) (map[string]bool, map[string]bool, error) {
	matched, scanned := map[string]bool{}, map[string]bool{}
	err := walkDiscoveryRecords(ledgerPath, func(record discoveryRecord) error {
		if record.Kind != "scanned" && record.Kind != "matched" {
			return nil
		}
		key := record.Module + "@" + record.Version
		if record.Kind == "matched" && matchedRequested[key] {
			matched[key] = true
		}
		if scannedRequested == nil || scannedRequested[key] {
			scanned[key] = true
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return matched, scanned, nil
}

func supersededSkipMatchesResult(skip discoverySupersededSkip, result discoveryCorpusResult) bool {
	if result.Superseded == nil || skip.Module == "" {
		return false
	}
	actual, err := json.Marshal(result.Superseded)
	if err != nil {
		return false
	}
	want, err := json.Marshal(skip)
	return err == nil && bytes.Equal(actual, want)
}
