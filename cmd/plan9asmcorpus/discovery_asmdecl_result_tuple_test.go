//go:build go1.27

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

func discoveryAsmDeclResultTupleFixture(t *testing.T, arch, declaration, assembly string) (string, []string) {
	t.Helper()
	root, env := discoveryAsmDeclResultAliasFixture(t, declaration, assembly)
	if arch == "386" {
		if err := os.Rename(filepath.Join(root, "decl_amd64.s"), filepath.Join(root, "decl_386.s")); err != nil {
			t.Fatal(err)
		}
		env = replaceEnv(env, map[string]string{"GOARCH": arch})
	}
	return root, env
}

func TestDiscoveryAsmDeclResultTupleActualOriginalGo(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct{ name, declaration, assembly, diagnostic string }{
			{"double", "func Value(x float64) (float64, float64)",
				"TEXT ·Value(SB),4,$0-24\nMOVSD x+0(FP),X0\nMOVSD X0,ret+8(FP)\nMOVSD X0,ret+16(FP)\nRET\n", "invalid offset ret+16(FP)"},
			{"named", "func Value() (a, b uint32)",
				"TEXT ·Value(SB),4,$0-8\nMOVL $1,a+0(FP)\nMOVL $2,a+4(FP)\nRET\n", "invalid offset a+4(FP)"},
			{"padding", "func Value() (uint8, uint32, uint16)",
				"TEXT ·Value(SB),4,$0-10\nMOVB $1,ret+0(FP)\nMOVL $2,ret+4(FP)\nMOVW $3,ret+8(FP)\nRET\n", "invalid offset ret+8(FP)"},
			{"flattened numerical array", "func Value() (uint32, [2]uint32)",
				"TEXT ·Value(SB),4,$0-12\nMOVL $1,ret+0(FP)\nMOVL $2,ret+4(FP)\nMOVL $3,ret+8(FP)\nRET\n", "invalid offset ret+8(FP)"},
			{"flattened numerical struct", "func Value() (uint32, struct { A uint8; B uint32 })",
				"TEXT ·Value(SB),4,$0-12\nMOVL $1,ret+0(FP)\nMOVB $2,ret+4(FP)\nMOVL $3,ret+8(FP)\nRET\n", "invalid offset ret+8(FP)"},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				root, env := discoveryAsmDeclResultTupleFixture(t, arch, row.declaration, row.assembly)
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
				unit := plan.Units[0]
				_, original := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", unit.Filename)
				failure, observed := discoveryAsmDeclObservedFailure(original)
				if !observed || !strings.Contains(failure.output, row.diagnostic) {
					t.Fatalf("actual original tuple alias diagnostic missing: %v", original)
				}
				t.Logf("ORIGINAL_TUPLE_ALIAS_DIAGNOSTIC (compile only): %v", original)
				raw := failure.output
				if err := plan.filterResultAliasWarnings(unit, original); err != nil {
					t.Fatalf("fully initialized typed tuple remains rejected: %v", err)
				}
				if len(plan.resultAliasRawFailures) != 1 || plan.resultAliasRawFailures[0] != failure || failure.output != raw {
					t.Fatal("filter discarded or modified the actual original failure")
				}
				if err := runDiscoveryAsmDecl(ctx, root, env, "linux/"+arch, nil, []string{"."}); err != nil {
					t.Fatalf("full tuple alias producer: %v", err)
				}
				writeTestFile(t, filepath.Join(root, "decl_"+arch+".s"), row.assembly+"\n")
				if err := plan.filterResultAliasWarnings(unit, original); err == nil {
					t.Fatal("changed original tuple source reused an old proof")
				}
				if failure.output != raw {
					t.Fatal("source revocation rewrote the original diagnostic")
				}
			})
		}
	}
}

func TestDiscoveryAsmDeclResultTupleKeepsUnprovedFailures(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move := 8, "MOVQ"
		if arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range []struct {
			name, declaration, body string
			args                    int
		}{
			{"missing first", "func Value() (uint32, uint32)", "MOVL $2,ret+4(FP)\nRET", 8},
			{"partial first", "func Value() (uint32, uint32)", "MOVB $1,ret+0(FP)\nMOVL $2,ret+4(FP)\nRET", 8},
			{"branch missing first", "func Value() (uint32, uint32)", "MOVL $1,AX\nCMPL AX,$0\nJE end\nMOVL $1,ret+0(FP)\nend:\nMOVL $2,ret+4(FP)\nRET", 8},
			{"uninitialized second", "func Value() (uint32, uint32)", "MOVL $1,ret+0(FP)\nMOVL CX,ret+4(FP)\nRET", 8},
			{"read before write", "func Value() (uint32, uint32)", "MOVL ret+4(FP),AX\nMOVL $1,ret+0(FP)\nMOVL AX,ret+4(FP)\nRET", 8},
			{"dead raw", "func Value() (uint32, uint32)", "MOVL $1,ret+0(FP)\nMOVL $2,ret+4(FP)\nJMP end\nBYTE $0x90\nend:\nRET", 8},
			{"pointer result", "func Value() (uint32, *byte)", fmt.Sprintf("MOVL $1,ret+0(FP)\n%s $0,ret+%d(FP)\nRET", move, word), 2 * word},
			{"aggregate missing tail", "func Value() (uint32, [2]uint32)", "MOVL $1,ret+0(FP)\nMOVL $2,ret+4(FP)\nRET", 12},
			{"aggregate pointer result", "func Value() (uint32, [2]*byte)", fmt.Sprintf("MOVL $1,ret+0(FP)\n%s $0,ret+%d(FP)\n%s $0,ret+%d(FP)\nRET", move, word, move, 2*word), 3 * word},
			{"native read", "func Value(x *uint32) (uint32, uint32)", fmt.Sprintf("%s x+0(FP),AX\nMOVL (AX),CX\nMOVL CX,ret+%d(FP)\nMOVL $2,ret+%d(FP)\nRET", move, word, word+4), word + 8},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				assembly := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s\n", row.args, row.body)
				root, env := discoveryAsmDeclResultTupleFixture(t, arch, row.declaration, assembly)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				if _, err := runCapturedCommandOutput(ctx, root, env, "go", "list", "-export", "."); err != nil {
					t.Fatalf("original Go object must exist before alias verification: %v", err)
				}
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
				_, receipt := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", unit.Filename)
				if _, observed := discoveryAsmDeclObservedFailure(receipt); !observed {
					t.Fatalf("missing actual original tuple warning: %v", receipt)
				}
				t.Logf("ORIGINAL_UNPROVED_TUPLE_DIAGNOSTIC: %v", receipt)
				filtered := plan.filterResultAliasWarnings(unit, receipt)
				if !errors.Is(filtered, receipt) || !errors.Is(filtered, plan9asm.ErrProbeNeedsContext) || len(plan.resultAliasRawFailures) != 0 {
					t.Fatalf("unproved tuple was filtered or lost its original identity: %v", filtered)
				}
				err = runDiscoveryAsmDecl(ctx, root, env, "linux/"+arch, nil, []string{"."})
				// Unclosed proofs intentionally join the original Exit1 with a
				// failure-only Context cause. They must not regain plain-exit
				// authority for filtering or source-N/A classification.
				var original *discoveryCapturedCommandError
				if !errors.As(err, &original) ||
					!errors.Is(err, plan9asm.ErrProbeNeedsContext) || !errors.Is(err, errDiscoveryAsmDeclSourceProof) {
					t.Fatalf("unclosed tuple lost its actual failure-only proof obligation: %v", err)
				}
				if _, observed := discoveryAsmDeclObservedFailure(original); !observed ||
					!strings.Contains(original.output, "invalid offset ret+") {
					t.Fatalf("joined failure lost its actual original analyzer receipt: %v", err)
				}
				if _, plain := discoveryAsmDeclObservedFailure(err); plain {
					t.Fatal("unclosed result acquired plain-exit filtering authority")
				}
				t.Logf("RETAINED_TUPLE_FAILURE: %v", err)
			})
		}
	}
}
