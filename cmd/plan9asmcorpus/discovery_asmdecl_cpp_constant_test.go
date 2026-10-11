package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
)

// The instruction and result address remain literal. Only an integer operand
// comes from the actual bound CPP inputs; neither a macro spelling nor a Go
// assembler success alone proves that the return bytes are initialized.
func TestDiscoveryAsmDeclResultAliasCPPConstantsActualGo(t *testing.T) {
	t.Setenv("GOCACHE", t.TempDir())
	for _, arch := range []string{"386", "amd64"} {
		for _, fixture := range []struct {
			name, definitions, value string
		}{
			{"integer", "#define value 7\n", "value"},
			{"alias chain", "#define base 7\n#define value base\n", "value"},
			{"expression", "#define base 7\n", "(base << 2 | 3)"},
			{"negative", "#define base 7\n", "(-base)"},
			{"function macro", "#define value(x) ((x) + 3)\n", "value(4)"},
		} {
			t.Run(arch+"/"+fixture.name, func(t *testing.T) {
				assembly := "#include \"constants.h\"\nTEXT ·Value(SB),4,$0-4\nMOVL $" + fixture.value + ",AX\nMOVL AX,ret+0(FP)\nRET\n"
				root, env := discoveryAsmDeclResultAliasFixture(t, "func Value() (written uint32)", assembly)
				writeTestFile(t, filepath.Join(root, "constants.h"), fixture.definitions)
				if arch == "386" {
					if err := os.Rename(filepath.Join(root, "decl_amd64.s"), filepath.Join(root, "decl_386.s")); err != nil {
						t.Fatal(err)
					}
				}
				env = replaceEnv(env, map[string]string{"GOARCH": arch})
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
					t.Fatalf("actual unit count: %d", len(plan.Units))
				}
				unit := plan.Units[0]
				_, original := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", unit.Filename)
				failure, observed := discoveryAsmDeclObservedFailure(original)
				if !observed || !strings.Contains(failure.output, "unknown variable ret; offset 0 is written+0(FP)") {
					t.Fatalf("missing actual named-result alias diagnostic: %v", original)
				}
				t.Logf("ORIGINAL_CONSTANT_RESULT_DIAGNOSTIC: %v", original)
				if err := plan.filterResultAliasWarnings(unit, original); err != nil {
					t.Fatalf("bound integer CPP constant lost its complete result proof: %v", err)
				}
				if err := plan.run(ctx); err != nil {
					t.Fatalf("actual full producer rejected its constant result: %v", err)
				}
				header := filepath.Join(root, "constants.h")
				writeTestFile(t, header, fixture.definitions+"\n#define foreign 99\n")
				if err := plan.filterResultAliasWarnings(unit, original); err == nil {
					t.Fatal("changed CPP source borrowed the old result receipt")
				}
			})
		}
	}
}

func TestDiscoveryAsmDeclResultAliasCPPConstantOperandBoundary(t *testing.T) {
	resolved := plan9asm.Operand{Kind: plan9asm.OpImm, Imm: 7}
	for _, expression := range []string{"value", "value(4)", "value(base + 1)", "(base << 2 | 3)", "(-base)", "base &^ mask", "'a'"} {
		t.Run(expression, func(t *testing.T) {
			literal := plan9asm.Operand{Kind: plan9asm.OpSym, Sym: "$" + expression}
			if !resultAliasCPPConstantOperand(literal, resolved) {
				t.Fatal("integer CPP expression was not registered")
			}
			if literal.Sym != "$"+expression || resolved.Imm != 7 {
				t.Fatal("operand comparison mutated caller inputs")
			}
		})
	}
	for _, expression := range []string{"symbol(SB)", "value(FP)", "value(SP)", "value(PC)", "value<>(SB)", "(AX)(CX*2)", "&value", "*value", "value.field", "value[0]", "value()...", "value(args...)", "1.5", "\"text\"", "base == 7", "base && mask", "base +"} {
		t.Run("reject/"+expression, func(t *testing.T) {
			if resultAliasCPPConstantOperand(plan9asm.Operand{Kind: plan9asm.OpSym, Sym: "$" + expression}, resolved) {
				t.Fatal("noninteger or native-address syntax acquired constant authority")
			}
		})
	}
	for name, mutate := range map[string]func(*plan9asm.Operand){
		"floating":    func(o *plan9asm.Operand) { o.ImmIsFloat = true },
		"unresolved":  func(o *plan9asm.Operand) { o.ImmRaw = "$unknown" },
		"register":    func(o *plan9asm.Operand) { o.Reg = "AX" },
		"FP name":     func(o *plan9asm.Operand) { o.FPName = "result" },
		"FP offset":   func(o *plan9asm.Operand) { o.FPOffset = 8 },
		"memory base": func(o *plan9asm.Operand) { o.Mem.Base = "SP" },
		"symbol":      func(o *plan9asm.Operand) { o.Sym = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := resolved
			mutate(&changed)
			if resultAliasCPPConstantOperand(plan9asm.Operand{Kind: plan9asm.OpImm, ImmRaw: "$(value)"}, changed) {
				t.Fatal("changed operand metadata borrowed an integer expansion")
			}
		})
	}
}

func TestDiscoveryAsmDeclResultAliasCPPConstantsKeepOtherObligations(t *testing.T) {
	t.Setenv("GOCACHE", t.TempDir())
	for _, fixture := range []struct {
		name, definitions, body string
	}{
		{"uninitialized register", "#define value 7\n", "CMPL AX,$value\nMOVL AX,ret+0(FP)"},
		{"partial result", "#define value 7\n", "MOVL $value,AX\nMOVB AX,ret+0(FP)"},
		{"unwritten branch", "#define value 7\n", "MOVL $value,AX\nCMPL AX,$0\nJE end\nMOVL AX,ret+0(FP)\nend:"},
		{"actual register rewrite", "#define value 7\n#define AX BX\n", "MOVL $value,AX\nMOVL AX,ret+0(FP)"},
		{"opcode rewrite", "#define value 7\n#define MOVL MOVW\n", "MOVL $value,AX\nMOVL AX,ret+0(FP)"},
		{"label rewrite", "#define value 7\n#define end other\n", "MOVL $value,AX\nJMP end\nend:\nMOVL AX,ret+0(FP)"},
		{"extra statement", "#define value 7,AX; MOVL $9\n", "MOVL $value,AX\nMOVL AX,ret+0(FP)"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			assembly := fmt.Sprintf("%sTEXT ·Value(SB),4,$0-4\n%s\nRET\n", fixture.definitions, fixture.body)
			root, env := discoveryAsmDeclResultAliasFixture(t, "func Value() (written uint32)", assembly)
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
				t.Fatalf("missing actual original failure: %v", original)
			}
			if err := plan.filterResultAliasWarnings(unit, original); err == nil {
				t.Fatal("constant expansion erased another source/result obligation")
			}
		})
	}
}
