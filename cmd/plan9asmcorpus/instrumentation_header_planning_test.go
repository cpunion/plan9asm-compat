package main

import (
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestInstrumentationNativeHeaderOutputCoverageBindsUnitCorrespondence(t *testing.T) {
	// Production coverage is currently local to one ASM/Go pair. Explicit
	// unit identity also protects a future consumer from reducing a unit/output
	// correspondence to an unordered set of output digests.
	outputs := map[string]string{"first.s": "MOVD $1,R0\n", "second.s": "MOVD $2,R0\n"}
	keys := func(swapped bool) map[string]bool {
		result := make(map[string]bool)
		for file, output := range outputs {
			if swapped {
				other := "first.s"
				if file == other {
					other = "second.s"
				}
				output = outputs[other]
			}
			result[discoveryCPPExpandedOutputCoverageKey(file, output)] = true
		}
		return result
	}
	if reflect.DeepEqual(keys(false), keys(true)) {
		t.Fatal("different ASM/output correspondence retained the same coverage identity")
	}
	output := outputs["first.s"]
	if discoveryCPPExpandedOutputCoverageKey("first.s", output) == discoveryCPPExpandedOutputCoverageKey("second.s", output) {
		t.Fatal("same expanded bytes lost their original unit identity")
	}
}

func TestInstrumentationNativeHeaderCompactPreservesSelectionProjection(t *testing.T) {
	text := "//go:build arm64.v8.1\n\npackage model\nconst Words = 2\n"
	header, err := gotoolprofile.TestSelectionHeader("model/wide.go", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	digest := discoveryFeatureBytesSHA256([]byte(text))
	if discoveryFeatureBytesSHA256([]byte(header)) == digest {
		t.Fatal("fixture did not distinguish the selection projection from complete source bytes")
	}
	proof := &gotoolprofile.InstrumentationTypeSourceProof{
		Dependencies: []gotoolprofile.InstrumentationTypeSourcePackage{{
			Dependency: gotoolprofile.InstrumentationDependencyExport{Source: gotoolprofile.ImportExport{
				PackagePath: "example.invalid/layout/model", GoSHA256: map[string]string{"wide.go": digest},
			}},
			Contents: map[string]string{"wide.go": text},
		}},
		SourceModules: []gotoolprofile.TestModuleSource{{
			SourceModule: "example.invalid/layout", SourceVersion: "v1.0.0",
			Sources: map[string]string{"model/wide.go": digest},
			Headers: map[string]string{"model/wide.go": header},
		}},
	}
	role := &discoveryInstrumentationHeaderPlanning{Contents: make(map[string]string)}
	compact, err := compactInstrumentationHeaderTypes(role, proof)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := restoreInstrumentationHeaderTypes(role, compact)
	if err != nil || !reflect.DeepEqual(restored, proof) {
		t.Fatalf("complete-file deduplication changed the existing selection projection: %v", err)
	}
	if len(role.Contents) != 1 || role.Contents[digest] != text {
		t.Fatal("complete selected source was not shared exactly once")
	}
	compact.Proof.SourceModules[0].Headers["model/wide.go"] = "package model\n"
	if _, err := restoreInstrumentationHeaderTypes(role, compact); err == nil {
		t.Fatal("selection projection was separated from available complete original bytes")
	}
	compact.Proof.SourceModules[0].Headers["model/wide.go"] = header
	compact.Proof.Dependencies[0].Dependency.Source.GoSHA256["wide.go"] = discoveryFeatureBytesSHA256([]byte("changed"))
	if _, err := restoreInstrumentationHeaderTypes(role, compact); err == nil {
		t.Fatal("complete source reference lost its independent full-file hash")
	}
	if !reflect.DeepEqual(proof.SourceModules[0].Headers, map[string]string{"model/wide.go": header}) {
		t.Fatal("compact transport mutated the original proof")
	}
}
