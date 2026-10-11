package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstrumentationForeignTypeBudgetAccountsBeforeCapture(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"one", "two"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(filepath.Join(root, dir, "original.data"))
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(9 << 20); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	budget := new(discoveryInstrumentationTypeBudget)
	if err := budget.check(root, filepath.Join(root, "one")); err != nil {
		t.Fatal(err)
	}
	before := budget.bytes
	if err := budget.check(root, filepath.Join(root, "one")); err != nil || budget.bytes != before {
		t.Fatal("repeated actual directory was counted twice")
	}
	if err := budget.check(root, filepath.Join(root, "two")); err == nil {
		t.Fatal("second foreign package received a fresh original-byte budget")
	}
	if err := new(discoveryInstrumentationTypeBudget).check(root, t.TempDir()); err == nil {
		t.Fatal("foreign directory escaped the actual exact module root")
	}
	if err := os.Symlink(filepath.Join(root, "one", "original.data"), filepath.Join(root, "linked.data")); err != nil {
		t.Fatal(err)
	}
	if err := new(discoveryInstrumentationTypeBudget).check(root, root); err == nil {
		t.Fatal("nonregular source member passed preallocation accounting")
	}
}

func TestInstrumentationTypeMarkerFullLedgerAndSemanticEntryPoints(t *testing.T) {
	progress := fixtureSemanticProgress(t)
	projected, err := semanticAssemblyLedgerProgress(progress)
	if err != nil || projected.Provenance.InstrumentationTypeSourceProtocol != progress.Provenance.InstrumentationTypeSourceProtocol {
		t.Fatal("cross-host semantic projection discarded the source-only protocol marker")
	}
	for _, marker := range []string{"", "actual_go_instrumentation_type_sources_v1"} {
		changed := progress
		provenance := *progress.Provenance
		provenance.InstrumentationTypeSourceProtocol = marker
		changed.Provenance = &provenance
		if err := writeAssemblyLedger(t.TempDir(), changed, progress.Source.SHA256); err == nil {
			t.Fatal("current full ledger writer accepted missing/historical type-source marker")
		}
		// The private projection is a comparison view, never a certificate.
		// Its public entry validates both original snapshots before projecting.
		if err := compareAssemblyLedgerProgress(progress, changed); err == nil {
			t.Fatal("semantic comparison entry accepted missing/historical type-source marker")
		}
		if err := compareAssemblyLedgerProgress(changed, progress); err == nil {
			t.Fatal("committed semantic comparison entry accepted missing/historical type-source marker")
		}
	}
}
