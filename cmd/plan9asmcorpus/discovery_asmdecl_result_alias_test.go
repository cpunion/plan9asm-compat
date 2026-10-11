package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func discoveryAsmDeclResultAliasFixture(t *testing.T, declaration, assembly string) (string, []string) {
	t.Helper()
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.invalid/result-alias\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(root, "decl.go"), "package alias\n"+declaration+"\n")
	writeTestFile(t, filepath.Join(root, "decl_amd64.s"), assembly)
	// This proof deliberately does not parse GOFLAGS. Keep its ordinary CPP
	// fixture context explicit; process concurrency is bounded by the caller.
	return root, replaceEnv(discoveryAsmDeclDirectFixtureEnv(t, root), map[string]string{
		"GOFLAGS": "", "GOEXPERIMENT": "",
	})
}

func TestDiscoveryAsmDeclResultAliasActualOriginalGo(t *testing.T) {
	for _, fixture := range []struct {
		name, declaration, assembly string
	}{
		{"ret0", "func Value() uint64", "TEXT ·Value(SB),4,$0-8\nMOVQ $7,ret0+0(FP)\nRET\n"},
		{"r", "func Value(x float64) float64", "TEXT ·Value(SB),4,$0-16\nMOVSD x+0(FP),X0\nMOVSD X0,r+8(FP)\nRET\n"},
		{"all branches", "func Value(x uint64) uint64", "TEXT ·Value(SB),4,$0-16\nMOVQ x+0(FP),AX\nCMPQ AX,$0\nJE alternate\nMOVQ $7,ret0+8(FP)\nRET\nalternate:\nMOVQ $9,ret0+8(FP)\nRET\n"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root, env := discoveryAsmDeclResultAliasFixture(t, fixture.declaration, fixture.assembly)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			plan, err := captureDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"."}, "")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := plan.close(); err != nil {
					t.Error(err)
				}
			}()
			if len(plan.Units) != 1 {
				t.Fatalf("missing actual compilation unit: %d", len(plan.Units))
			}
			_, original := runCapturedCommandOutput(ctx, root, env, plan.GoBinary, "tool", "vet", "-asmdecl", plan.Units[0].Filename)
			if original == nil || !strings.Contains(discoveryCommandDiagnostic(original), "RET without writing") {
				t.Fatalf("unchanged stock analyzer did not expose textual alias warning: %v", original)
			}
			t.Logf("ORIGINAL_ANALYZER_EXIT: %v", original)
			if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); err != nil {
				t.Fatalf("fully initialized alias should continue to ordinary translation: %v", err)
			}
		})
	}
}

func TestDiscoveryAsmDeclResultAliasKeepsOriginalFailures(t *testing.T) {
	for name, fixture := range map[string]struct {
		declaration, body string
	}{
		"bare RET":          {"func Value() uint64", "RET"},
		"partial result":    {"func Value() uint64", "MOVL $1,ret0+0(FP)\nRET"},
		"unwritten branch":  {"func Value(x uint64) uint64", "MOVQ x+0(FP),AX\nCMPQ AX,$0\nJE end\nMOVQ $1,ret0+8(FP)\nend:\nRET"},
		"unknown call":      {"func Value() uint64\nfunc other()", "MOVQ $1,ret0+0(FP)\nCALL ·other(SB)\nRET"},
		"unknown GP":        {"func Value() uint64", "MOVQ AX,ret0+0(FP)\nRET"},
		"read result first": {"func Value() uint64", "MOVQ ret0+0(FP),AX\nMOVQ AX,ret0+0(FP)\nRET"},
		"wrong typed width": {"func Value() uint32", "MOVQ $1,ret0+0(FP)\nRET"},
		"wrong FP offset":   {"func Value() uint64", "MOVQ $1,ret0+1(FP)\nRET"},
		"mixed diagnostic":  {"func Value() uint64", "MOVQ $1,ret0+0(FP)\nMOVQ $1,alien+99(FP)\nRET"},
	} {
		t.Run(name, func(t *testing.T) {
			args := "8"
			if strings.Contains(fixture.declaration, "x uint64") {
				args = "16"
			}
			assembly := "TEXT ·Value(SB),4,$0-" + args + "\n" + fixture.body + "\n"
			if name == "unknown call" {
				assembly += "TEXT ·other(SB),4,$0-0\nRET\n"
			}
			root, env := discoveryAsmDeclResultAliasFixture(t, fixture.declaration, assembly)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); err == nil {
				t.Fatal("unproved result or another diagnostic was silently accepted")
			} else {
				t.Logf("RETAINED_ORIGINAL_FAILURE: %v", err)
			}
		})
	}
}

func TestDiscoveryAsmDeclResultAliasActualTestVariant(t *testing.T) {
	root, env := discoveryAsmDeclResultAliasFixture(t, "type ValueType uint64", "TEXT ·Value(SB),4,$0-8\nMOVQ $7,ret0+0(FP)\nRET\n")
	writeTestFile(t, filepath.Join(root, "decl_test.go"), "package alias\nfunc Value() ValueType\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); err != nil {
		t.Fatalf("actual selected in-package test declaration failed: %v", err)
	}
	writeTestFile(t, filepath.Join(root, "decl_test.go"), "package alias\ntype Narrow uint32\nfunc Value() Narrow\n")
	directErr := runDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"."}, "")
	if directErr == nil || !discoveryAsmDeclHasUnprovedResultWarning(directErr) ||
		!strings.Contains(discoveryCommandDiagnostic(directErr), "RET without writing to 4-byte ret+0(FP)") {
		t.Fatalf("changed actual typed test unit lost its result obligation: %v", directErr)
	}
	t.Logf("CHANGED_TEST_VARIANT_DIRECT: %v", directErr)
	retryErr := runDiscoveryAsmDeclWithTestlessModuleCopies(ctx, root, env, nil, nil, []string{"."})
	if retryErr == nil || !strings.Contains(discoveryCommandDiagnostic(retryErr), "Value missing Go declaration") {
		t.Fatalf("actual testless retry did not expose the removed declaration: %v", retryErr)
	}
	t.Logf("CHANGED_TEST_VARIANT_TESTLESS: %v", retryErr)
	if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); err == nil {
		t.Fatal("changed actual test-variant width acquired the old result proof")
	} else if _, observed := discoveryAsmDeclObservedFailure(err); !observed || !discoveryAsmDeclHasUnprovedResultWarning(err) {
		t.Fatalf("wrapper did not preserve the actual plain unit failure: %v", err)
	} else {
		t.Logf("RETAINED_TEST_VARIANT_FAILURE: %v", err)
	}
}

func TestDiscoveryAsmDeclResultAliasUnclosedGeneratedHeader(t *testing.T) {
	root, env := discoveryAsmDeclResultAliasFixture(t, "const ValueBits = 7\nfunc Value() uint64", "#include \"go_asm.h\"\nTEXT ·Value(SB),4,$0-8\nMOVQ $const_ValueBits,ret0+0(FP)\nRET\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if _, err := runCapturedCommandOutput(ctx, root, env, "go", "list", "-export", "."); err != nil {
		t.Fatalf("original stock-Go generated header should compile: %v", err)
	}
	if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); err == nil {
		t.Fatal("unbound generated-header bytes were replaced with an empty or guessed header")
	}
}

func TestDiscoveryAsmDeclResultAliasCPPOriginalInputs(t *testing.T) {
	root, env := discoveryAsmDeclResultAliasFixture(t, "func Value() uint64", "#include \"store.h\"\nTEXT ·Value(SB),4,$0-8\nSTORE\nRET\n")
	writeTestFile(t, filepath.Join(root, "store.h"), "#ifdef GOOS_linux\n#define STORE MOVQ $7,ret0+0(FP)\n#else\n#define STORE MOVL $7,ret0+0(FP)\n#endif\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); err != nil {
		t.Fatalf("actual bound CPP result store failed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "store.h"))
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "store.h"), strings.Replace(string(data), "MOVQ $7", "MOVL $7", 1))
	if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); err == nil {
		t.Fatal("changed CPP width acquired the prior result proof")
	}
}

func TestDiscoveryAsmDeclResultAliasActualReceiptAndMutations(t *testing.T) {
	root, env := discoveryAsmDeclResultAliasFixture(t, "func Value() uint64", "#include \"store.h\"\nTEXT ·Value(SB),4,$0-8\nSTORE\nRET\n")
	writeTestFile(t, filepath.Join(root, "store.h"), "#define STORE MOVQ $7,ret0+0(FP)\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	plan, err := captureDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"."}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := plan.close(); err != nil {
			t.Error(err)
		}
	}()
	unit := plan.Units[0]
	_, original := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", unit.Filename)
	failure, observed := discoveryAsmDeclObservedFailure(original)
	if !observed || !strings.Contains(failure.output, "RET without writing") {
		t.Fatalf("missing actual original Exit1: %v", original)
	}
	raw := failure.output
	if filtered := plan.filterResultAliasWarnings(unit, original); filtered != nil {
		t.Fatalf("fully bound original CPP alias warning remains: %v", filtered)
	}
	if len(plan.resultAliasRawFailures) != 1 || plan.resultAliasRawFailures[0] != failure || failure.output != raw {
		t.Fatal("filter rewrote or discarded the original observed unit receipt")
	}
	t.Logf("PRESERVED_RAW_UNIT_EXIT: %v", plan.resultAliasRawFailures[0])
	for name, mutate := range map[string]func(*discoveryCapturedCommandError){
		"wrong command": func(e *discoveryCapturedCommandError) { e.command += " -fake" },
		"wrong CWD":     func(e *discoveryCapturedCommandError) { e.directory = filepath.Dir(root) },
		"foreign source": func(e *discoveryCapturedCommandError) {
			e.output = strings.Replace(e.output, "decl_amd64.s", "foreign.s", 1)
		},
		"wrong line":  func(e *discoveryCapturedCommandError) { e.output = strings.Replace(e.output, ".s:4:", ".s:3:", 1) },
		"wrong width": func(e *discoveryCapturedCommandError) { e.output = strings.Replace(e.output, "8-byte", "4-byte", 1) },
		"wrong offset": func(e *discoveryCapturedCommandError) {
			e.output = strings.Replace(e.output, "ret+0(FP)", "ret+1(FP)", 1)
		},
		"wrong target":   func(e *discoveryCapturedCommandError) { e.output = strings.Replace(e.output, "[amd64]", "[386]", 1) },
		"wrong function": func(e *discoveryCapturedCommandError) { e.output = strings.Replace(e.output, "Value:", "Other:", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *failure
			mutate(&changed)
			if err := plan.filterResultAliasWarnings(unit, &changed); err == nil {
				t.Fatal("changed actual diagnostic identity acquired result proof")
			}
		})
	}
	if err := plan.filterResultAliasWarnings(unit, errors.Join(original, errors.New("another failure"))); err == nil {
		t.Fatal("mixed outer error acquired plain observed analysis authority")
	}
	mixed := *failure
	mixed.output += "\nunknown analysis warning"
	filtered := plan.filterResultAliasWarnings(unit, &mixed)
	if filtered == nil || !strings.Contains(discoveryCommandDiagnostic(filtered), "unknown analysis warning") ||
		strings.Contains(discoveryCommandDiagnostic(filtered), "RET without writing") {
		t.Fatalf("precise RET filtering hid another diagnostic or did not filter its own line: %v", filtered)
	}
	for _, name := range []string{"decl.go", "decl_amd64.s", "store.h"} {
		t.Run("original bytes "+name, func(t *testing.T) {
			path := filepath.Join(root, name)
			originalBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, path, string(originalBytes)+"\n")
			if err := plan.filterResultAliasWarnings(unit, original); err == nil {
				t.Fatal("changed original input retained result proof")
			}
			writeTestFile(t, path, string(originalBytes))
		})
	}
	changedUnit := unit
	changedUnit.Config.ImportMap = map[string]string{"invented": "another"}
	if reflect.DeepEqual(changedUnit, unit) || plan.filterResultAliasWarnings(changedUnit, original) == nil {
		t.Fatal("unsealed caller Config acquired the original result proof")
	}
	oldTarget := plan.SDK["GOARCH"]
	plan.SDK["GOARCH"] = "386"
	if err := plan.run(ctx); err == nil {
		t.Fatal("changed actual tool/target plan reached diagnostic acceptance")
	}
	plan.SDK["GOARCH"] = oldTarget
	if err := plan.run(ctx); err != nil {
		t.Fatalf("restored, same-source actual CPP result alias did not close: %v", err)
	}
}
