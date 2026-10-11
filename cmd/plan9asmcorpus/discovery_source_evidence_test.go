package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDiscoveryOpaquePackageFailureCannotBecomeSourceNA(t *testing.T) {
	for _, diagnostic := range []string{
		"current Go compiler rejected the exact package",
		"exit status 1",
		"could not compile package",
		"missing dependency without a source diagnostic",
	} {
		t.Run(diagnostic, func(t *testing.T) {
			failure := errors.New(diagnostic)
			groups := []discoveryPackageGroup{{Pattern: "example.invalid/module/pkg"}}
			results, err := runDiscoveryPackageChecks(groups, func([]string) error {
				return failure
			})
			if !errors.Is(err, failure) || results != nil {
				t.Fatalf("opaque failure became source exclusion: results=%v err=%v", results, err)
			}
		})
	}
}

func TestDiscoveryAssemblerFooterAloneIsNotSourceEvidence(t *testing.T) {
	const file = "pkg/native_amd64.s"
	const output = "asm: assembly of " + file + " failed\n"
	if discoveryAssemblerSourceDiagnostic(file, output) {
		t.Fatal("an assembler failure footer without the actual diagnostic became source evidence")
	}
}

func TestDiscoverySourceNAReaderRejectsOpaqueDiagnostics(t *testing.T) {
	for _, kind := range []string{
		discoverySourceNotApplicableGoBuild,
		discoverySourceNotApplicableGoAssembler,
		discoverySourceNotApplicableAsmDecl,
		nativeLayoutGoAssemblerTarget,
	} {
		t.Run(kind, func(t *testing.T) {
			result := discoveryCorpusResult{
				DiscoveredAsmFiles: []string{"pkg/native_amd64.s"},
				SourceNotApplicableItems: []discoverySourceNotApplicableItem{{
					AsmFile: "pkg/native_amd64.s",
					Targets: []string{"linux/amd64"},
					Kind:    kind,
					Reason:  "current Go compiler rejected the exact package",
				}},
			}
			if err := validateDiscoverySourceNotApplicableEvidence(result); err == nil {
				t.Fatal("reason-only source exclusion was accepted without a source diagnostic")
			}
		})
	}
}

func TestDiscoveryPackageChecksPreservesConcreteSourceDiagnostics(t *testing.T) {
	for _, diagnostic := range []string{
		"# example.invalid/module/pkg\npkg/decl.go:3:14: undefined: missingDeclaration",
		"pkg/native_amd64.s:4: unrecognized instruction \"NOT_AN_OPCODE\"",
		"pkg/native_amd64.s:8:1: [amd64] Raw: wrong argument size 8; expected $...-16",
		"asm: illegal combination: ADDQ AX, X0 (pkg/native_amd64.s:8)",
	} {
		t.Run(diagnostic, func(t *testing.T) {
			failure := errors.New(diagnostic)
			groups := []discoveryPackageGroup{{Pattern: "example.invalid/module/pkg"}}
			results, err := runDiscoveryPackageChecks(groups, func([]string) error {
				return failure
			})
			if err != nil || len(results) != 1 || !errors.Is(results[0], failure) {
				t.Fatalf("concrete source diagnostic was lost: results=%v err=%v", results, err)
			}
		})
	}
}

func TestDiscoverySourceDiagnosticWitnessIsPortableAndBoundToReport(t *testing.T) {
	const diagnostic = "# example.invalid/module/pkg\n/private/runner/cache/pkg/decl.go:3:14: undefined: missingDeclaration"
	witness := captureDiscoverySourceDiagnostic(diagnostic)
	if err := validateDiscoverySourceDiagnostic(witness); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(witness)
	if err != nil || strings.Contains(string(data), "/private/") || strings.Contains(string(data), "missingDeclaration") {
		t.Fatalf("compact witness retained private paths or arbitrary text: %s %v", data, err)
	}
	if len(witness.Locations) != 1 || witness.Locations[0].File != "decl.go" || witness.Locations[0].Line != 3 || witness.Locations[0].Column != 14 {
		t.Fatalf("wrong source location: %+v", witness.Locations)
	}
	item := discoverySourceNotApplicableItem{
		Kind: discoverySourceNotApplicableGoBuild, Reason: diagnostic, Diagnostic: witness,
	}
	if err := validateDiscoverySourceRejectionDiagnostic(item, false); err != nil {
		t.Fatal(err)
	}
	item.Reason = discoverySourceSkipReason(item.Kind)
	if err := validateDiscoverySourceRejectionDiagnostic(item, true); err != nil {
		t.Fatal("compact ledger lost the validated source diagnostic:", err)
	}
	if err := validateDiscoverySourceRejectionDiagnostic(item, false); err == nil {
		t.Fatal("a raw report used a compact witness instead of its actual diagnostic")
	}
	item.Diagnostic = nil
	if err := validateDiscoverySourceRejectionDiagnostic(item, true); err == nil {
		t.Fatal("an old reason-only ledger was upgraded without source evidence")
	}
	item.Reason, item.Diagnostic = diagnostic+" changed", witness
	if err := validateDiscoverySourceRejectionDiagnostic(item, false); err == nil {
		t.Fatal("changed report bytes retained the earlier diagnostic witness")
	}
}

func TestDiscoverySourceDiagnosticWitnessRejectsInvalidShapeAndMixedInfrastructure(t *testing.T) {
	for _, diagnostic := range []string{
		"decl.go:3: undefined: missing\nchecksum mismatch: SECURITY ERROR",
		"decl.go:3: undefined: missing\nsource proof failure: changed header",
		"decl.go:3: undefined: missing\nsignal: killed",
		"decl.go:4294967296: invalid source location",
		"decl.go:0: invalid source location",
		"decl.go:3:",
	} {
		if witness := captureDiscoverySourceDiagnostic(diagnostic); witness != nil {
			t.Errorf("unproved source diagnostic became a witness: %q", diagnostic)
		}
	}
	valid := captureDiscoverySourceDiagnostic("b.go:4: undefined: b\na.go:3: undefined: a\na.go:3: undefined: a")
	if valid == nil || len(valid.Locations) != 2 || valid.Locations[0].File != "a.go" {
		t.Fatal("positions were not canonically deduplicated and sorted")
	}
	for _, mutate := range []func(*discoverySourceDiagnosticWitness){
		func(w *discoverySourceDiagnosticWitness) { w.Protocol = "unknown" },
		func(w *discoverySourceDiagnosticWitness) { w.SHA256 = "not-a-digest" },
		func(w *discoverySourceDiagnosticWitness) { w.Locations[0].File = "private/runner/a.go" },
		func(w *discoverySourceDiagnosticWitness) { w.Locations[0].Line = 0 },
		func(w *discoverySourceDiagnosticWitness) {
			w.Locations[0], w.Locations[1] = w.Locations[1], w.Locations[0]
		},
	} {
		copy := *valid
		copy.Locations = append([]discoverySourceDiagnosticLocation(nil), valid.Locations...)
		mutate(&copy)
		if err := validateDiscoverySourceDiagnostic(&copy); err == nil {
			t.Fatal("invalid compact source-diagnostic witness accepted")
		}
	}
}
