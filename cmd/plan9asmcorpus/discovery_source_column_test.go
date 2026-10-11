package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoverySourceDiagnosticColumnCannotFallBackToMessage(t *testing.T) {
	bulk := strings.Repeat("other.go:3: undefined: missing\n", 600)
	for _, column := range []string{
		"0", "-1", "-0", "+1", "+0", "--1", "++1", "-+1", "+-1", "+", "-", "01", "0001",
		"4294967296", "18446744073709551616", "",
	} {
		invalid := "native.s:42:" + column + ": invalid instruction\n"
		t.Run("column="+column, func(t *testing.T) {
			for _, invalid := range []string{invalid, "asm: invalid instruction (native.s:42:" + column + ")\tMOVQ AX, X0\n"} {
				if discoveryAssemblerSourceDiagnostic("native.s", invalid) {
					t.Errorf("invalid assembler column field became a line-only source message: %q", invalid)
				}
				for _, diagnostic := range []string{invalid, invalid + bulk, bulk + invalid} {
					if captureDiscoverySourceDiagnostic(diagnostic) != nil {
						t.Errorf("invalid column field became a line-only source message: %q", invalid)
					}
				}
			}
		})
	}
	for _, diagnostic := range []string{"native.s:42:1:", "native.s:42:1: \t\r\n", "native.s:42:0:"} {
		if captureDiscoverySourceDiagnostic(diagnostic) != nil {
			t.Errorf("empty source message became concrete evidence: %q", diagnostic)
		}
	}
}

func TestDiscoverySourceDiagnosticColumnRetainsGoFormats(t *testing.T) {
	for _, test := range []struct {
		diagnostic string
		column     uint32
	}{
		{"native.s:42: invalid instruction", 0},
		{"native.s:42: invalid: instruction", 0},
		{"native.s:42: 0: invalid operand", 0},
		{"native.s:42:1: invalid instruction", 1},
		{"native.s:42:4294967295: invalid instruction", 4294967295},
		{"asm: illegal combination: ADDQ AX, X0 (native.s:42)", 0},
		{"asm: illegal combination: ADDQ AX, X0 (native.s:42:3)", 3},
	} {
		witness := captureDiscoverySourceDiagnostic(test.diagnostic)
		if witness == nil || len(witness.Locations) != 1 || witness.Locations[0].Column != test.column {
			t.Errorf("valid Go source format lost: diagnostic=%q witness=%+v", test.diagnostic, witness)
		}
		if !discoveryAssemblerSourceDiagnostic("native.s", test.diagnostic) {
			t.Errorf("valid Go assembler source format lost: %q", test.diagnostic)
		}
	}
}

func TestDiscoverySourceDiagnosticColumnActualGoOracle(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env := replaceEnv(os.Environ(), map[string]string{"GOTOOLCHAIN": "local", "GOWORK": "off", "GOENV": "off", "GOFLAGS": ""})
	for _, pragma := range []string{"", "//line altered.go:42:0\n", "//line altered.go:42:-1\n"} {
		file := filepath.Join(dir, "decl.go")
		writeTestFile(t, file, "package sourceoracle\n"+pragma+"var _ = missingDeclaration\n")
		_, err := runCapturedCommandOutput(ctx, dir, env, "go", "tool", "compile", "-o", filepath.Join(dir, "decl.o"), file)
		diagnostic := discoveryCommandDiagnostic(err)
		witness := captureDiscoverySourceDiagnostic(diagnostic)
		if err == nil || witness == nil || len(witness.Locations) == 0 || witness.Locations[0].Column == 0 {
			t.Fatalf("actual compiler's positive source columns lost: pragma=%q error=%v witness=%+v", pragma, err, witness)
		}
	}
	file := filepath.Join(dir, "native.s")
	writeTestFile(t, file, "TEXT ·Probe(SB),$0-0\nNOT_A_GO_OPCODE\nRET\n")
	_, err := runCapturedCommandOutput(ctx, dir, env, "go", "tool", "asm", "-o", filepath.Join(dir, "native.o"), file)
	witness := captureDiscoverySourceDiagnostic(discoveryCommandDiagnostic(err))
	if err == nil || witness == nil || len(witness.Locations) != 1 || witness.Locations[0].Column != 0 {
		t.Fatalf("actual assembler's omitted-column source rejection lost: error=%v witness=%+v", err, witness)
	}
}
