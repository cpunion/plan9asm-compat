package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
)

func TestDiscoveryAsmDeclFPAliasActual386Components(t *testing.T) {
	for _, fixture := range []struct{ name, declaration, body, args string }{
		{"scalar", "func Value(x, y uint32) uint32", "MOVL x+4(FP),AX\nMOVL AX,ret+8(FP)", "12"},
		{"slice", "func Value(x []uint32) uint32", "MOVL x+4(FP),AX\nMOVL AX,ret+12(FP)", "16"},
		{"lo hi", "func Value(x uint64) uint32", "MOVL x_lo+4(FP),AX\nMOVL AX,ret+8(FP)", "12"},
		{"unnamed", "func Value(uint32, uint32) uint32", "MOVL arg+4(FP),AX\nMOVL AX,ret+8(FP)", "12"},
		{"unicode", "func Value(α, β uint32) uint32", "MOVL α+4(FP),AX\nMOVL AX,ret+8(FP)", "12"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root, env := discoveryAsmDeclResultAliasFixture(t, fixture.declaration, "TEXT ·Value(SB),4,$0-"+fixture.args+"\n"+fixture.body+"\nRET\n")
			if err := os.Rename(filepath.Join(root, "decl_amd64.s"), filepath.Join(root, "decl_386.s")); err != nil {
				t.Fatal(err)
			}
			env = replaceEnv(env, map[string]string{"GOARCH": "386"})
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
			if _, observed := discoveryAsmDeclObservedFailure(original); !observed || !strings.Contains(discoveryCommandDiagnostic(original), "[386]") {
				t.Fatalf("actual 386 object/analyzer name rule missing: %v", original)
			}
			t.Logf("ORIGINAL_386_COMPONENT_DIAGNOSTIC (compile only): %v", original)
			if err := plan.filterResultAliasWarnings(unit, original); err != nil {
				t.Fatalf("actual 386 component alias: %v", err)
			}
		})
	}
}

func TestDiscoveryAsmDeclFPAliasActualReceiptMutations(t *testing.T) {
	root, env := discoveryAsmDeclResultAliasFixture(t, "func Value(x []uint64) uint64", "TEXT ·Value(SB),4,$0-32\nMOVQ x+8(FP),AX\nMOVQ AX,ret+24(FP)\nRET\n")
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
	if !observed || plan.filterResultAliasWarnings(unit, original) != nil {
		t.Fatalf("actual bound component receipt: %v", original)
	}
	raw := failure.output
	// These are explicitly synthetic mutations of a real Exit1 receipt, not
	// additional stock Go diagnostics or external-package certificates.
	for name, mutate := range map[string]func(*discoveryCapturedCommandError){
		"wrong source": func(e *discoveryCapturedCommandError) {
			e.output = strings.Replace(e.output, "decl_amd64.s", "foreign.s", 1)
		},
		"wrong line": func(e *discoveryCapturedCommandError) { e.output = strings.Replace(e.output, ".s:2:", ".s:3:", 1) },
		"wrong name": func(e *discoveryCapturedCommandError) {
			e.output = strings.Replace(e.output, "offset x+8", "offset x_base+8", 1)
		},
		"wrong physical offset": func(e *discoveryCapturedCommandError) {
			e.output = strings.Replace(e.output, "offset x+8", "offset x+16", 1)
		},
		"wrong expected offset": func(e *discoveryCapturedCommandError) {
			e.output = strings.Replace(e.output, "expected x+0", "expected x+1", 1)
		},
		"invented component": func(e *discoveryCapturedCommandError) {
			e.output = strings.Replace(e.output, "x_cap+16", "alien+16", 1)
		},
		"wrong architecture": func(e *discoveryCapturedCommandError) { e.output = strings.Replace(e.output, "[amd64]", "[386]", 1) },
		"wrong function":     func(e *discoveryCapturedCommandError) { e.output = strings.Replace(e.output, "Value:", "Other:", 1) },
		"unknown heading":    func(e *discoveryCapturedCommandError) { e.output = "# unrelated.invalid/package\n" + e.output },
		"unknown suffix":     func(e *discoveryCapturedCommandError) { e.output += "\nunknown diagnostic" },
		"wrong command":      func(e *discoveryCapturedCommandError) { e.command += " -invented" },
		"wrong directory":    func(e *discoveryCapturedCommandError) { e.directory = filepath.Dir(root) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *failure
			mutate(&changed)
			if err := plan.filterResultAliasWarnings(unit, &changed); err == nil {
				t.Fatal("mutation borrowed actual component identity")
			}
		})
	}
	if err := plan.filterResultAliasWarnings(unit, errors.Join(original, errors.New("unknown cleanup failure"))); err == nil {
		t.Fatal("joined cause borrowed plain exit authority")
	}
	for _, name := range []string{"decl.go", "decl_amd64.s"} {
		path := filepath.Join(root, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, path, string(data)+"\n")
		if err := plan.filterResultAliasWarnings(unit, original); err == nil {
			t.Fatalf("changed %s borrowed captured source", name)
		}
		writeTestFile(t, path, string(data))
	}
	if failure.output != raw {
		t.Fatal("filter mutated raw native analyzer evidence")
	}
}

func TestDiscoveryAsmDeclFPAliasActualNamedOffsets(t *testing.T) {
	for _, fixture := range []struct {
		name, declaration, body, args string
	}{
		{"byte", "func Value(x, y uint8) uint8", "MOVB x+1(FP),AX\nMOVB AX,y+8(FP)", "9"},
		{"word", "func Value(x, y uint16) uint16", "MOVW x+2(FP),AX\nMOVW AX,y+8(FP)", "10"},
		{"long", "func Value(x, y uint32) uint32", "MOVL x+4(FP),AX\nMOVL AX,y+8(FP)", "12"},
		{"quad", "func Value(x, y uint64) uint64", "MOVQ x+8(FP),AX\nMOVQ AX,y+16(FP)", "24"},
		{"float", "func Value(x, y float32) float32", "MOVSS x+4(FP),X0\nMOVSS X0,y+8(FP)", "12"},
		{"double", "func Value(x, y float64) float64", "MOVSD x+8(FP),X0\nMOVSD X0,y+16(FP)", "24"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			assembly := "TEXT ·Value(SB),4,$0-" + fixture.args + "\n" + fixture.body + "\nRET\n"
			root, env := discoveryAsmDeclResultAliasFixture(t, fixture.declaration, assembly)
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
				t.Fatalf("actual units: %d", len(plan.Units))
			}
			unit := plan.Units[0]
			_, original := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", unit.Filename)
			if _, observed := discoveryAsmDeclObservedFailure(original); !observed ||
				!strings.Contains(discoveryCommandDiagnostic(original), "invalid offset x+") ||
				!strings.Contains(discoveryCommandDiagnostic(original), "RET without writing") {
				t.Fatalf("actual original offset/name diagnostics missing: %v", original)
			}
			t.Logf("ORIGINAL_FP_NAME_DIAGNOSTIC: %v", original)
			if err := plan.filterResultAliasWarnings(unit, original); err != nil {
				t.Fatalf("exact owned FP bytes with complete typed result were rejected: %v", err)
			}
			if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); err != nil {
				t.Fatalf("full actual producer still rejected semantic FP aliases: %v", err)
			}
		})
	}
}

func TestDiscoveryAsmDeclFPAliasActualParameterComponents(t *testing.T) {
	for _, fixture := range []struct {
		name, declaration, read, result, args string
	}{
		{"scalar no RET alias", "func Value(x, y uint64) uint64", "MOVQ x+8(FP),AX", "16", "24"},
		{"slice", "func Value(x []uint64) uint64", "MOVQ x+8(FP),AX", "24", "32"},
		{"slice component", "func Value(x []uint64) uint64", "MOVQ x_base+8(FP),AX", "24", "32"},
		{"string", "func Value(x string) uint64", "MOVQ x+8(FP),AX", "16", "24"},
		{"struct", "type S struct { A, B uint64 }; func Value(x S) uint64", "MOVQ x_A+8(FP),AX", "16", "24"},
		{"array", "func Value(x [2]uint64) uint64", "MOVQ x_0+8(FP),AX", "16", "24"},
		{"interface", "func Value(x interface{}) uint64", "MOVQ x_type+8(FP),AX", "16", "24"},
		{"complex", "func Value(x complex128) uint64", "MOVQ x_real+8(FP),AX", "16", "24"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			assembly := "TEXT ·Value(SB),4,$0-" + fixture.args + "\n" + fixture.read + "\nMOVQ AX,ret+" + fixture.result + "(FP)\nRET\n"
			root, env := discoveryAsmDeclResultAliasFixture(t, fixture.declaration, assembly)
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
			if _, observed := discoveryAsmDeclObservedFailure(original); !observed ||
				!strings.Contains(discoveryCommandDiagnostic(original), "invalid offset") ||
				strings.Contains(discoveryCommandDiagnostic(original), "RET without writing") {
				t.Fatalf("actual standalone parameter alias diagnostic missing: %v", original)
			}
			t.Logf("ORIGINAL_COMPONENT_NAME_DIAGNOSTIC: %v", original)
			if err := plan.filterResultAliasWarnings(unit, original); err != nil {
				t.Fatalf("physical typed component should not require a calculation/RET proof: %v", err)
			}
			if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); err != nil {
				t.Fatalf("full producer rejected exact component width: %v", err)
			}
		})
	}
}

func TestDiscoveryAsmDeclFPAliasActualPackedComponent(t *testing.T) {
	for _, row := range []struct{ name, declaration, instruction, args string }{
		{"legacy", "func Value(x, y [16]byte)", "MOVOU x+16(FP),X0", "32"},
		{"vex", "func Value(x, y [32]byte)", "VMOVDQU x+32(FP),Y0", "64"},
	} {
		t.Run(row.name, func(t *testing.T) {
			root, env := discoveryAsmDeclResultAliasFixture(t, row.declaration, "TEXT ·Value(SB),4,$0-"+row.args+"\n"+row.instruction+"\nRET\n")
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
			if _, observed := discoveryAsmDeclObservedFailure(original); !observed || !strings.Contains(discoveryCommandDiagnostic(original), "invalid offset") {
				t.Fatalf("actual complete packed component warning missing: %v", original)
			}
			t.Logf("ORIGINAL_PACKED_COMPONENT_NAME_DIAGNOSTIC (compile only): %v", original)
			if err := plan.filterResultAliasWarnings(unit, original); err != nil {
				t.Fatalf("whole occupied component needs no calculation authority: %v", err)
			}
		})
	}
}

func TestDiscoveryAsmDeclFPAliasRetainsUnprovedBytes(t *testing.T) {
	for name, fixture := range map[string]struct{ declaration, body, args string }{
		"outside frame":                   {"func Value(x, y uint64) uint64", "MOVQ x+32(FP),AX\nMOVQ AX,ret+16(FP)\nRET", "24"},
		"padding gap":                     {"func Value(x, y uint8) uint8", "MOVB x+4(FP),AX\nMOVB AX,ret+8(FP)\nRET", "9"},
		"partial component":               {"func Value(x, y uint64) uint64", "MOVL x+8(FP),AX\nMOVQ AX,ret+16(FP)\nRET", "24"},
		"cross component":                 {"func Value(x, y uint32) uint32", "MOVQ x+4(FP),AX\nMOVL AX,ret+8(FP)\nRET", "12"},
		"partial result":                  {"func Value(x, y uint64) uint64", "MOVQ x+8(FP),AX\nMOVL AX,y+16(FP)\nRET", "24"},
		"unwritten result branch":         {"func Value(x, y uint64) uint64", "MOVQ x+8(FP),AX\nCMPQ AX,$0\nJE end\nMOVQ AX,y+16(FP)\nend:\nRET", "24"},
		"unknown input":                   {"func Value(x, y uint64) uint64", "MOVQ x+8(FP),AX\nMOVQ BX,y+16(FP)\nRET", "24"},
		"read result before definition":   {"func Value(x, y uint64) uint64", "MOVQ y+16(FP),AX\nMOVQ AX,ret+16(FP)\nRET", "24"},
		"ret name hides unwritten result": {"func Value(x, y uint64) uint64", "MOVQ ret+0(FP),AX\nRET", "24"},
		"parameter store":                 {"func Value(x, y uint64) uint64", "MOVQ $7,x+8(FP)\nMOVQ $9,ret+16(FP)\nRET", "24"},
		"uninitialized RMW result alias":  {"func Value(x, y uint64) uint64", "ADDQ x+8(FP),AX\nMOVQ AX,y+16(FP)\nRET", "24"},
		"FP address":                      {"func Value(x, y uint64) uint64", "LEAQ x+8(FP),AX\nMOVQ AX,ret+16(FP)\nRET", "24"},
		"unknown call effect":             {"func Value(x, y uint64) uint64\nfunc Other()", "MOVQ x+8(FP),AX\nMOVQ AX,y+16(FP)\nCALL ·Other(SB)\nRET\nTEXT ·Other(SB),4,$0-0\nRET", "24"},
		"CPP instruction rewrite":         {"func Value(x, y uint64) uint64", "MOVQ x+8(FP),AX\nMOVQ AX,ret+16(FP)\nRET", "24"},
		"packed padding":                  {"type S struct { A uint8; B uint64 }; func Value(x, y S)", "MOVOU x+16(FP),X0\nRET", "32"},
	} {
		t.Run(name, func(t *testing.T) {
			assembly := "TEXT ·Value(SB),4,$0-" + fixture.args + "\n" + fixture.body + "\n"
			if name == "CPP instruction rewrite" {
				assembly = "#define MOVQ MOVL\n" + assembly
			}
			root, env := discoveryAsmDeclResultAliasFixture(t, fixture.declaration, assembly)
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
			if _, observed := discoveryAsmDeclObservedFailure(original); !observed {
				t.Fatalf("actual original analyzer failure missing: %v", original)
			}
			if err := plan.filterResultAliasWarnings(unit, original); err == nil {
				t.Fatal("a name annotation supplied unproved native width, byte or result authority")
			} else {
				t.Logf("RETAINED_REAL_FAILURE: %v", err)
			}
		})
	}
}

// Native access shape closes only the parameter-name diagnostic. A canonical
// ret spelling does not ask that filter to prove ADDQ's old AX input; the
// separate public result checker still must. A result alias does ask for that
// whole proof, and cannot use the parameter's occupied bytes to initialize AX.
func TestDiscoveryAsmDeclFPAliasTypedRMWLayoutIsNotResultAuthority(t *testing.T) {
	for _, name := range []string{"x", "alias"} {
		for _, result := range []string{"ret", "y"} {
			for _, initialized := range []bool{false, true} {
				t.Run(name+"/"+result+fmt.Sprintf("/initialized=%t", initialized), func(t *testing.T) {
					body := ""
					if initialized {
						body = "MOVQ $0,AX\n"
					}
					body += "ADDQ " + name + "+8(FP),AX\nMOVQ AX," + result + "+16(FP)\nRET\n"
					assembly := "TEXT ·Value(SB),4,$0-24\n" + body
					root, env := discoveryAsmDeclResultAliasFixture(t, "func Value(x, y uint64) uint64", assembly)
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
						t.Fatalf("actual selected units: %d", len(plan.Units))
					}
					unit := plan.Units[0]
					_, original := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", unit.Filename)
					failure, observed := discoveryAsmDeclObservedFailure(original)
					nameDiagnostic := "invalid offset x+8(FP)"
					if name == "alias" {
						nameDiagnostic = "unknown variable alias; offset 8 is y+8(FP)"
					}
					if !observed || !strings.Contains(failure.output, nameDiagnostic) ||
						strings.Contains(failure.output, "RET without writing") != (result == "y") {
						t.Fatalf("actual original name/result obligations missing: %v", original)
					}
					declarations, err := plan.resultAliasDeclarations(unit)
					if err != nil {
						t.Fatal(err)
					}
					declaration, declared := declarations["Value"]
					if !declared {
						t.Fatal("actual typed declaration missing")
					}
					file, err := plan9asm.Parse(plan9asm.ArchAMD64, assembly)
					if err != nil || len(file.Funcs) != 1 {
						t.Fatalf("independent original source: %v", err)
					}
					proof := plan9asm.CheckX86ABI0ResultInitialization(file.Funcs[0], declaration.sig, "amd64")
					if initialized && proof != nil || !initialized && !errors.Is(proof, plan9asm.ErrProbeNeedsContext) {
						t.Fatalf("result proof confused registered FP width with old AX initialization: %v", proof)
					}
					filtered := plan.filterResultAliasWarnings(unit, original)
					if result == "ret" || initialized {
						if filtered != nil || len(plan.resultAliasRawFailures) == 0 || plan.resultAliasRawFailures[len(plan.resultAliasRawFailures)-1] != failure {
							t.Fatalf("closed name/result diagnostic lost its original raw receipt: %v", filtered)
						}
						if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); err != nil {
							t.Fatalf("separate layout/name consumer rejected its closed obligation: %v", err)
						}
					} else if !errors.Is(filtered, errDiscoveryAsmDeclSourceProof) || !errors.Is(filtered, original) ||
						!strings.Contains(discoveryCommandDiagnostic(filtered), failure.output) {
						t.Fatalf("result alias erased the uninitialized old AX obligation: %v", filtered)
					}
					t.Logf("ORIGINAL_TYPED_RMW_DIAGNOSTIC: %v; independent result initialization: %v", original, proof)
				})
			}
		}
	}
}

func TestDiscoveryAsmDeclFPAliasActualObjectNames(t *testing.T) {
	declaration := "func Value(x, y uint64) uint64"
	alias := "TEXT ·Value(SB),4,$0-24\nMOVQ x+8(FP),AX\nMOVQ AX,y+16(FP)\nRET\n"
	canonical := "TEXT ·Value(SB),4,$0-24\nMOVQ y+8(FP),AX\nMOVQ AX,ret+16(FP)\nRET\n"
	root, env := discoveryAsmDeclResultAliasFixture(t, declaration, alias)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	writeTestFile(t, filepath.Join(root, "canonical.s"), canonical)
	var listings []string
	for _, name := range []string{"decl_amd64.s", "canonical.s"} {
		output, err := runCapturedCommandOutput(ctx, root, env, "go", "tool", "asm", "-S", "-p", "example.invalid/result-alias", "-o", filepath.Join(root, name+".o"), name)
		if err != nil {
			t.Fatal(err)
		}
		var bytes []string
		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(line, "\t0x") && !strings.Contains(line, "(") {
				bytes = append(bytes, line)
			}
		}
		if len(bytes) == 0 {
			t.Fatalf("actual original Go assembler has no object bytes: %s", output)
		}
		listings = append(listings, strings.Join(bytes, "\n"))
		t.Logf("ORIGINAL_GO_OBJECT %s:\n%s", name, output)
	}
	if listings[0] != listings[1] {
		t.Fatalf("names affected actual Go machine bytes:\nalias %s\ncanonical %s", listings[0], listings[1])
	}
}

func TestDiscoveryAsmDeclFPAliasUnclosedContext(t *testing.T) {
	for name, body := range map[string]string{
		"known component unknown RMW input": "ADDQ x+8(FP),AX\nMOVQ AX,y+16(FP)",
		"dynamic FP index":                  "MOVQ x+8(FP)(SI*1),AX\nMOVQ AX,ret+16(FP)",
		"unknown name unknown RMW input":    "ADDQ alias+8(FP),AX\nMOVQ AX,y+16(FP)",
		"mixed unknown diagnostic":          "ADDQ alias+8(FP),AX\nMOVQ alien+99(FP),BX\nMOVQ AX,y+16(FP)",
		"unknown name wide read":            "MOVQ alias+4(FP),AX\nMOVQ AX,ret+16(FP)",
		"result alias unknown definition":   "MOVQ BX,y+16(FP)",
	} {
		t.Run(name, func(t *testing.T) {
			declaration := "func Value(x, y uint64) uint64"
			if name == "unknown name wide read" {
				declaration = "func Value(x uint32, y uint32, z uint64) uint64"
			}
			root, env := discoveryAsmDeclResultAliasFixture(t, declaration, "TEXT ·Value(SB),4,$0-24\n"+body+"\nRET\n")
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
			if !observed {
				t.Fatalf("actual original completed analyzer failure missing: %v", original)
			}
			filtered := plan.filterResultAliasWarnings(unit, original)
			if !errors.Is(filtered, errDiscoveryAsmDeclSourceProof) || !errors.Is(filtered, original) ||
				!strings.Contains(discoveryCommandDiagnostic(filtered), failure.output) {
				t.Fatalf("unclosed native bytes/result obligation must retain a Context receipt: %v", filtered)
			}
			if rejected, _ := classifyDiscoveryAsmDeclFailure(root, unit.Config.NonGoFiles, unit.Config.NonGoFiles, filtered); len(rejected) != 0 {
				t.Fatalf("unclosed alias obtained source-exclusion authority: %v", rejected)
			}
			if err := runDiscoveryAsmDecl(ctx, root, env, "linux/amd64", nil, []string{"."}); !errors.Is(err, errDiscoveryAsmDeclSourceProof) {
				t.Fatalf("testless retry washed away unclosed alias: %v", err)
			}
			t.Logf("RETAINED_UNCLOSED_ALIAS_CONTEXT: %v", filtered)
		})
	}
}
