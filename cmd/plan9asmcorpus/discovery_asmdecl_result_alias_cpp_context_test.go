package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclResultAliasOriginalAssemblerFlagContext(t *testing.T) {
	// The actual compiler receives EXPLICIT and stores the unbound incoming
	// AX. Reconstructing CPP with builtin defines only selects the other,
	// constant-store branch and would wrongly remove the real RET obligation.
	source := "#ifdef EXPLICIT\n#define STORE MOVQ AX,ret0+0(FP)\n#else\n#define STORE MOVQ $7,ret0+0(FP)\n#endif\nTEXT ·Value(SB),4,$0-8\nSTORE\nRET\n"
	root, env := discoveryAsmDeclResultAliasFixture(t, "func Value() uint64", source)
	env = replaceEnv(env, map[string]string{"GOFLAGS": "-asmflags=-D=EXPLICIT"})
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
	if plan.SDK["GOFLAGS"] != "-asmflags=-D=EXPLICIT" || len(plan.Units) != 1 {
		t.Fatalf("actual assembler flag/unit context was not observed: %#v", plan.SDK)
	}
	// Go list's export archive is not the complete link archive on every SDK.
	// Compile the unchanged package to an owned archive, never an executable.
	objectDir := discoveryAsmDeclRetryPhysicalTemp(t)
	archive := filepath.Join(objectDir, "original.a")
	build, err := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "build", "-x", "-o", archive, ".")
	if err != nil {
		t.Fatalf("original Go archive failed: %v\n%s", err, build)
	}
	members, err := runCapturedCommandOutput(ctx, objectDir, plan.Env, plan.GoBinary, "tool", "pack", "t", archive)
	if err != nil || !strings.Contains(string(members), "decl_amd64.o") {
		t.Fatalf("original Go archive lacks the actual assembly member: %v\n%s", err, members)
	}
	if _, err := runCapturedCommandOutput(ctx, objectDir, plan.Env, plan.GoBinary, "tool", "pack", "x", archive, "decl_amd64.o"); err != nil {
		t.Fatal(err)
	}
	object, err := runCapturedCommandOutput(ctx, objectDir, plan.Env, plan.GoBinary, "tool", "objdump", "-s", "Value", filepath.Join(objectDir, "decl_amd64.o"))
	if err != nil || !strings.Contains(string(object), "4889442408") {
		t.Fatalf("original Go object did not select MOVQ AX,8(SP): %v\n%s", err, object)
	}
	t.Logf("ORIGINAL_EXPLICIT_ASSEMBLER_OBJECT:\n%s", object)
	_, original := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", plan.Units[0].Filename)
	if _, observed := discoveryAsmDeclObservedFailure(original); !observed || !discoveryAsmDeclHasUnprovedResultWarning(original) {
		t.Fatalf("actual original analyzer did not finish with RET Exit1: %v", original)
	}
	t.Logf("ORIGINAL_EXPLICIT_ASSEMBLER_CONTEXT: %v", original)
	if filtered := plan.filterResultAliasWarnings(plan.Units[0], original); filtered == nil {
		t.Fatal("unclosed explicit assembler define borrowed the builtin-only CPP result proof")
	}
	if err := plan.run(ctx); err == nil || !strings.Contains(discoveryCommandDiagnostic(err), "RET without writing") {
		t.Fatalf("actual direct analysis lost its original flag-dependent RET failure: %v", err)
	}
}

func TestDiscoveryAsmDeclResultAliasUnclosedFlagRoutingKeepsReceipt(t *testing.T) {
	for _, routing := range []struct {
		name, key, value string
	}{
		{"parallel flag is not guessed harmless", "GOFLAGS", "-p=2"},
		{"assembler include", "GOFLAGS", "-asmflags=-I=."},
		{"assembler trimpath", "GOFLAGS", "-asmflags=-trimpath=unrelated"},
		{"explicit experiment context", "GOEXPERIMENT", "none"},
	} {
		t.Run(routing.name, func(t *testing.T) {
			root, env := discoveryAsmDeclResultAliasFixture(t, "func Value() uint64", "TEXT ·Value(SB),4,$0-8\nMOVQ $7,ret0+0(FP)\nRET\n")
			env = replaceEnv(env, map[string]string{routing.key: routing.value})
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
			if plan.SDK[routing.key] != routing.value || len(plan.Units) != 1 {
				t.Fatalf("actual original routing is not bound: %#v", plan.SDK)
			}
			_, original := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", plan.Units[0].Filename)
			if !discoveryAsmDeclHasUnprovedResultWarning(original) {
				t.Fatalf("actual analyzer did not produce the alias RET receipt: %v", original)
			}
			if got := plan.filterResultAliasWarnings(plan.Units[0], original); got != original {
				t.Fatalf("unclosed routing changed or cleared the actual receipt: %v", got)
			}
			if err := plan.run(ctx); !discoveryAsmDeclHasUnprovedResultWarning(err) {
				t.Fatalf("unclosed routing became a completed pass: %v", err)
			}
		})
	}
}

func TestDiscoveryAsmDeclResultAliasCompletedTypedABIMismatchCannotLoseDeclaration(t *testing.T) {
	for _, role := range []string{"ordinary", "test-only"} {
		for _, kind := range []string{"input", "result"} {
			t.Run(role+" "+kind, func(t *testing.T) {
				declaration := "func Value(x uint32)"
				body := "MOVQ x+0(FP),AX"
				if kind == "result" {
					declaration = "func Value() uint32"
					body = "MOVQ $7,ret0+0(FP)"
				}
				root, env := discoveryAsmDeclResultAliasFixture(t, "type Word uint32", "TEXT ·Value(SB),4,$0-8\n"+body+"\nRET\n")
				file := "decl.go"
				if role == "test-only" {
					file = "decl_test.go"
				}
				writeTestFile(t, filepath.Join(root, file), "package alias\n"+declaration+"\n")
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				direct := runDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"."}, "")
				wanted := "invalid MOVQ"
				if kind == "result" {
					wanted = "RET without writing to 4-byte ret+0(FP)"
				}
				if _, observed := discoveryAsmDeclObservedFailures(direct); !observed ||
					!strings.Contains(discoveryCommandDiagnostic(direct), wanted) {
					t.Fatalf("actual typed original unit did not expose its complete ABI width failure: %v", direct)
				}
				t.Logf("ORIGINAL_TYPED_UNIT_DIRECT: %v", direct)
				if !discoveryAsmDeclHasCompletedABIObligation(direct) {
					t.Fatal("completed positioned typed diagnostic lacks failure-only retention")
				}
				retry := runDiscoveryAsmDeclWithTestlessModuleCopies(ctx, root, env, nil, nil, []string{"."})
				t.Logf("ORIGINAL_TYPED_UNIT_TESTLESS: %v", retry)
				if role == "test-only" && (retry == nil || !strings.Contains(discoveryCommandDiagnostic(retry), "Value missing Go declaration")) {
					t.Fatalf("actual testless retry did not bind the declaration removal: %v", retry)
				}
				wrapped := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."})
				t.Logf("ORIGINAL_TYPED_UNIT_WRAPPER: %v", wrapped)
				if _, observed := discoveryAsmDeclObservedFailures(wrapped); !observed ||
					!strings.Contains(discoveryCommandDiagnostic(wrapped), wanted) {
					t.Fatalf("completed typed ABI width failure lost its original declaration/receipt: %v", wrapped)
				}
			})
		}
	}
}

func TestDiscoveryAsmDeclResultAliasCompletedObligationRequiresActualReceipt(t *testing.T) {
	root, env := discoveryAsmDeclResultAliasFixture(t, "func Value(x uint32)", "TEXT ·Value(SB),4,$0-8\nMOVQ x+0(FP),AX\nRET\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	original := runDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"."}, "")
	failure, observed := discoveryAsmDeclObservedFailure(original)
	if !observed || !discoveryAsmDeclHasCompletedABIObligation(original) {
		t.Fatalf("actual typed fixture did not complete: %v", original)
	}
	for name, mutate := range map[string]func(*discoveryCapturedCommandError){
		"no position": func(e *discoveryCapturedCommandError) { e.output = "invalid MOVQ of x+0(FP); uint32 is 4-byte value" },
		"missing declaration": func(e *discoveryCapturedCommandError) {
			e.output = filepath.Join(root, "decl_amd64.s") + ":1:1: [amd64] Value: function Value missing Go declaration"
		},
		"equal width kind": func(e *discoveryCapturedCommandError) {
			e.output = filepath.Join(root, "decl_amd64.s") + ":2:1: [amd64] Value: invalid MOVOU of x+0(FP); [2]uint64 is 16-byte value"
		},
		"unobserved status": func(e *discoveryCapturedCommandError) { e.cause = errors.New("exit status 1") },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *failure
			mutate(&changed)
			if discoveryAsmDeclHasCompletedABIObligation(&changed) {
				t.Fatal("unclosed diagnostic acquired the completed ABI failure hook")
			}
		})
	}
	if discoveryAsmDeclHasCompletedABIObligation(errors.Join(original, errors.New("unknown failure"))) {
		t.Fatal("unknown outer failure acquired completed unit authority")
	}
}

func TestDiscoveryAsmDeclResultAliasRequiresUniqueActualOrdinaryPackage(t *testing.T) {
	root, env := discoveryAsmDeclResultAliasFixture(t, "func Value() uint64", "#define STORE MOVQ $7,ret0+0(FP)\nTEXT ·Value(SB),4,$0-8\nSTORE\nRET\n")
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
	var actual directAsmDeclPackage
	for _, pkg := range plan.Packages {
		if pkg.ImportPath == unit.PackageID {
			actual = pkg
		}
	}
	if actual.ImportPath == "" || actual.Standard || actual.Module == nil {
		t.Fatalf("stock Go did not observe the ordinary external module: %#v", actual)
	}
	_, original := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", unit.Filename)
	if !discoveryAsmDeclHasUnprovedResultWarning(original) || plan.filterResultAliasWarnings(unit, original) != nil {
		t.Fatalf("actual ordinary empty-flags fixture is not proved: %v", original)
	}
	packages := plan.Packages
	standard := actual
	standard.Standard = true
	withoutModule := actual
	withoutModule.Module = nil
	for name, changed := range map[string][]directAsmDeclPackage{
		"missing actual package":       nil,
		"actual standard role":         {standard},
		"unclosed module role":         {withoutModule},
		"duplicate actual package":     {actual, actual},
		"standard then ordinary alias": {standard, actual},
		"ordinary then standard alias": {actual, standard},
	} {
		t.Run(name, func(t *testing.T) {
			plan.Packages = changed
			defer func() { plan.Packages = packages }()
			if got := plan.filterResultAliasWarnings(unit, original); got != original {
				t.Fatal("nonunique/missing/standard actual package role borrowed ordinary CPP")
			}
		})
	}
	if err := plan.verify(ctx); err != nil {
		t.Fatalf("restored actual metadata source guard failed: %v", err)
	}
}
