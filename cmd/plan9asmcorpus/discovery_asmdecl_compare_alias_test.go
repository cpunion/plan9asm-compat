package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclFPAliasScalarCompareActualGo(t *testing.T) {
	t.Setenv("GOCACHE", t.TempDir())
	for _, arch := range []string{"386", "amd64"} {
		for _, stem := range []string{"CMP", "TEST"} {
			for _, row := range []struct {
				suffix string
				width  int
			}{{"B", 1}, {"W", 2}, {"L", 4}, {"Q", 8}} {
				if arch == "386" && row.width == 8 {
					continue
				}
				t.Run(arch+"/"+stem+row.suffix, func(t *testing.T) {
					operands := fmt.Sprintf("x+%d(FP),$7", row.width)
					if stem == "TEST" {
						operands = fmt.Sprintf("$7,x+%d(FP)", row.width)
					}
					declaration := fmt.Sprintf("func Value(x, y uint%d)", row.width*8)
					assembly := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s%s %s\nRET\n", row.width*2, stem, row.suffix, operands)
					testDiscoveryAsmDeclReadOnlyFPAlias(t, arch, declaration, assembly)
				})
			}
		}
	}
}

func testDiscoveryAsmDeclReadOnlyFPAlias(t *testing.T, arch, declaration, assembly string) {
	t.Helper()
	root, env := discoveryAsmDeclResultAliasFixture(t, declaration, assembly)
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
	unit := plan.Units[0]
	_, original := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", unit.Filename)
	if _, observed := discoveryAsmDeclObservedFailure(original); !observed {
		t.Fatal("missing original assembler/analyzer alias counterexample", original)
	}
	t.Logf("ORIGINAL_READONLY_ALIAS_DIAGNOSTIC: %v", original)
	if err := plan.filterResultAliasWarnings(unit, original); err != nil {
		t.Fatal("complete Go grammar lost its FP read-only width", err)
	}
}
