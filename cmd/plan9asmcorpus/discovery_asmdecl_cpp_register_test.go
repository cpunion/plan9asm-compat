package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Bind the original analyzer's physical FP-name warning to the actual CPP
// register operand. Keep this independent of any external module or algorithm.
func TestDiscoveryAsmDeclFPAliasCPPRegisterMatrix(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, style := range []string{"direct", "transitive", "header"} {
			t.Run(arch+"/"+style, func(t *testing.T) {
				type transferRow struct {
					name, typ, op, reg string
					width              int
				}
				rows := []transferRow{
					{"GP", "uint32", "MOVL", "AX", 4},
					{"XLong", "uint32", "MOVL", "X0", 4},
					{"XQuad", "uint64", "MOVQ", "X0", 8},
					{"XDouble", "float64", "MOVSD", "X0", 8},
					{"VEXLong", "uint32", "VMOVD", "X0", 4},
					{"VEXQuad", "uint64", "VMOVQ", "X0", 8},
					{"MMXLong", "uint32", "MOVL", "M0", 4},
					{"MMXQuad", "uint64", "MOVQ", "M0", 8},
					{"PackedX", "[16]byte", "MOVOU", "X0", 16},
					{"PackedY", "[32]byte", "VMOVDQU", "Y0", 32},
				}
				if arch == "amd64" {
					rows = append(rows, transferRow{"GPQuad", "uint64", "MOVQ", "AX", 8})
				}
				var declarations, definitions, assembly strings.Builder
				for _, row := range rows {
					alias := "register" + row.name
					if style == "transitive" {
						fmt.Fprintf(&definitions, "#define %s nested%s\n#define nested%s %s\n", alias, row.name, row.name, row.reg)
					} else {
						fmt.Fprintf(&definitions, "#define %s %s\n", alias, row.reg)
					}
					fmt.Fprintf(&declarations, "func %s(x, y %s)\n", row.name, row.typ)
					fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-%d\n%s alias+%d(FP),%s\nRET\n", row.name, 2*row.width, row.op, row.width, alias)
				}
				prefix := definitions.String()
				if style == "header" {
					prefix = "#include \"registers.h\"\n"
				}
				root, env := discoveryAsmDeclResultAliasFixture(t, declarations.String(), prefix+assembly.String())
				if style == "header" {
					writeTestFile(t, filepath.Join(root, "registers.h"), definitions.String())
				}
				if arch == "386" {
					if err := os.Rename(filepath.Join(root, "decl_amd64.s"), filepath.Join(root, "decl_386.s")); err != nil {
						t.Fatal(err)
					}
					env = replaceEnv(env, map[string]string{"GOARCH": arch})
				}
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
					t.Fatalf("actual package has %d units", len(plan.Units))
				}
				unit := plan.Units[0]
				_, original := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", unit.Filename)
				failure, observed := discoveryAsmDeclObservedFailure(original)
				if !observed {
					t.Fatalf("actual Go did not expose the original FP-name warnings: %v", original)
				}
				for _, row := range rows {
					want := fmt.Sprintf("] %s: unknown variable alias; offset %d", row.name, row.width)
					if strings.Count(failure.output, want) != 1 {
						t.Fatalf("missing unique actual diagnostic %q: %s", want, failure.output)
					}
				}
				if err := plan.filterResultAliasWarnings(unit, original); err != nil {
					t.Fatalf("CPP register operands did not close their typed parameter reads: %v", err)
				}
				if err := plan.run(ctx); err != nil {
					t.Fatalf("full actual producer rejected register aliases: %v", err)
				}
			})
		}
	}
}

func TestDiscoveryAsmDeclFPAliasCPPRegisterBoundaries(t *testing.T) {
	for _, fixture := range []struct {
		name, definitions, declaration, body string
		args                                 int
	}{
		{"opcode rewrite", "#define MOVL MOVB\n#define register AX\n", "func Value(x, y uint32)", "MOVL alias+4(FP),register", 8},
		{"actual register rewrite", "#define AX X0\n", "func Value(x, y uint32)", "MOVL alias+4(FP),AX", 8},
		{"FP name rewrite", "#define alias y\n#define register AX\n", "func Value(x, y uint32)", "MOVL alias+4(FP),register", 8},
		{"FP base rewrite", "#define FP SP\n#define register AX\n", "func Value(x, y uint32)", "MOVL alias+4(FP),register", 8},
		{"extra statement", "#define register AX; MOVL $7,y+4(FP)\n", "func Value(x, y uint32)", "MOVL alias+4(FP),register", 8},
		{"partial component", "#define register AX\n", "func Value(x, y uint64)", "MOVL alias+8(FP),register", 16},
		{"parameter write", "#define register AX\n", "func Value(x, y uint32)", "MOVL register,alias+4(FP)", 8},
		{"type padding", "#define register X0\n", "type S struct { A uint8; B uint64 }; func Value(x, y S)", "MOVOU alias+16(FP),register", 32},
		{"uninitialized result", "#define register AX\n", "func Value() uint64", "MOVQ register,alias+0(FP)", 8},
		{"uninitialized RMW", "#define register AX\n", "func Value(x, y uint64) uint64", "ADDQ alias+8(FP),register\nMOVQ register,y+16(FP)", 24},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			assembly := fmt.Sprintf("%sTEXT ·Value(SB),4,$0-%d\n%s\nRET\n", fixture.definitions, fixture.args, fixture.body)
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
				t.Fatalf("actual original FP warning was not observed: %v", original)
			}
			if err := plan.filterResultAliasWarnings(unit, original); err == nil {
				t.Fatal("CPP register alias supplied an unclosed opcode, source-byte or result effect")
			}
		})
	}
}

func TestDiscoveryAsmDeclFPAliasCPPRegisterHeaderMutation(t *testing.T) {
	root, env := discoveryAsmDeclResultAliasFixture(t, "func Value(x, y uint32)", "#include \"registers.h\"\nTEXT ·Value(SB),4,$0-8\nMOVL alias+4(FP),register\nRET\n")
	header := filepath.Join(root, "registers.h")
	writeTestFile(t, header, "#define register AX\n")
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
	if _, observed := discoveryAsmDeclObservedFailure(original); !observed || plan.filterResultAliasWarnings(unit, original) != nil {
		t.Fatalf("original bound header fixture did not close: %v", original)
	}
	writeTestFile(t, header, "#define register X0\n")
	if err := plan.filterResultAliasWarnings(unit, original); err == nil {
		t.Fatal("changed included bytes borrowed the original analyzer receipt")
	}
}
