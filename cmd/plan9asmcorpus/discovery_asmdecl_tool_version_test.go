package main

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestDiscoveryAsmDeclToolVersionExperimentGrammar(t *testing.T) {
	const prefix = "vet version go1.27.1"
	names := []string{"loopvar", "simd", "newinliner"}
	for _, experiments := range []string{"", "simd", "nosimd", "loopvar,nosimd,newinliner"} {
		t.Run("accept "+experiments, func(t *testing.T) {
			version := prefix
			if experiments != "" {
				version += " X:" + experiments
			}
			got, err := directAsmDeclToolVersionExperiments(version, "vet", "go1.27.1", names)
			if err != nil || got != experiments {
				t.Fatalf("canonical version = %q, %v", got, err)
			}
		})
	}
	for _, version := range []string{
		"compile version go1.27.1",
		"vet version go1.27.0",
		prefix + "extra",
		prefix + " X:",
		prefix + " X:none",
		prefix + " X:all",
		prefix + " X:unknown",
		prefix + " X:simd,simd",
		prefix + " X:simd,nosimd",
		prefix + " X:simd,loopvar",
		prefix + " X:simd,",
		prefix + " X:SIMD",
		prefix + " X:simd newinliner",
		prefix + " X:simd buildID=unregistered",
		prefix + "  X:simd",
		prefix + " X:simd\nunknown diagnostic",
		prefix + " X:simd ",
	} {
		t.Run("reject "+version, func(t *testing.T) {
			if _, err := directAsmDeclToolVersionExperiments(version, "vet", "go1.27.1", names); err == nil {
				t.Fatal("accepted foreign, unknown or noncanonical tool experiment identity")
			}
		})
	}
}

func TestDiscoveryAsmDeclToolVersionExperimentOriginalFieldOrder(t *testing.T) {
	file := filepath.Join(t.TempDir(), "flags.go")
	writeTestFile(t, file, "package goexperiment\ntype Flags struct { LoopVar bool; SIMD bool; NewInliner bool }\n")
	order, err := directAsmDeclExperimentOrder(file)
	if err != nil || !reflect.DeepEqual(order, []string{"loopvar", "simd", "newinliner"}) {
		t.Fatalf("original field order = %v, %v", order, err)
	}
	for _, source := range []string{
		"package goexperiment\ntype Other struct { SIMD bool }\n",
		"package goexperiment\ntype Flags struct{}\n",
		"package goexperiment\ntype Flags = struct { SIMD bool }\n",
		"package goexperiment\ntype Flags bool\n",
		"package goexperiment\ntype Flags struct { SIMD, Other bool }\n",
		"package goexperiment\ntype Flags struct { SIMD string }\n",
		"package goexperiment\ntype Flags struct { SIMD bool `json:\"simd\"` }\n",
		"package goexperiment\ntype Flags struct { SIMD bool; Simd bool }\n",
		"package goexperiment\ntype Flags struct{}\ntype Flags struct { SIMD bool }\n",
	} {
		writeTestFile(t, file, source)
		if _, err := directAsmDeclExperimentOrder(file); err == nil {
			t.Fatalf("accepted malformed original Flags role: %s", source)
		}
	}
}
