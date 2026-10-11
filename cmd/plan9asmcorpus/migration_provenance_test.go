package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestIndependentHarnessAndTranslatorRevisions(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "records.jsonl")
	writeTestFile(t, ledger, "{}\n")
	p := fixtureDiscoveryProvenance(t, ledger)
	p.Source.Revision = strings.Repeat("e", 40)
	if err := validateDiscoveryProvenance(p, p.Source, p.LedgerSHA256); err != nil {
		t.Fatalf("independent harness revision rejected: %v", err)
	}
}

func TestIndependentTranslatorProvenanceRejectsMissingOrChangedInputs(t *testing.T) {
	for name, mutate := range map[string]func(*discoveryCorpusProvenance){
		"missing source": func(p *discoveryCorpusProvenance) { p.TranslatorSource = discoverySourceIdentity{} },
		"wrong pin":      func(p *discoveryCorpusProvenance) { p.Source.TranslatorRevision = strings.Repeat("f", 40) },
		"wrong binary":   func(p *discoveryCorpusProvenance) { p.TranslatorRevision = strings.Repeat("f", 40) },
		"dirty checkout": func(p *discoveryCorpusProvenance) { p.TranslatorSource.Dirty = true },
	} {
		t.Run(name, func(t *testing.T) {
			ledger := filepath.Join(t.TempDir(), "records.jsonl")
			writeTestFile(t, ledger, "{}\n")
			p := fixtureDiscoveryProvenance(t, ledger)
			source := p.Source
			mutate(&p)
			if err := validateDiscoveryProvenance(p, source, p.LedgerSHA256); err == nil {
				t.Fatal("invalid independent translator proof accepted")
			}
		})
	}
}
