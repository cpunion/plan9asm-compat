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

// Keep the language-type axis separate from the complete opcode/bank matrix.
// One actual Go package contains all declarations, so its compiler/export and
// asmdecl observations are shared without inventing per-function receipts.
func TestDiscoveryAsmDeclTransferOccupiedTypeMatrix(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var declarations, assembly strings.Builder
			declarations.WriteString("type Word32 uint32\ntype Word64 uint64\ntype Pair struct { A, B uint32 }\n")
			rows := []struct {
				name, typ, op string
				width         int
			}{
				{"Uint32", "uint32", "MOVL", 4},
				{"Int32", "int32", "VMOVD", 4},
				{"Float32", "float32", "MOVL", 4},
				{"Named32", "Word32", "VMOVD", 4},
				{"Bytes32", "[4]byte", "MOVL", 4},
				{"Uint64", "uint64", "MOVQ", 8},
				{"Int64", "int64", "MOVD", 8},
				{"Float64", "float64", "VMOVQ", 8},
				{"Named64", "Word64", "MOVQ", 8},
				{"Bytes64", "[8]byte", "MOVD", 8},
				{"Array64", "[2]uint32", "VMOVQ", 8},
				{"Struct64", "Pair", "MOVQ", 8},
				{"Complex64", "complex64", "MOVQ", 8},
			}
			for _, row := range rows {
				fmt.Fprintf(&declarations, "func %s(x, y %s)\n", row.name, row.typ)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-%d\n%s alias+%d(FP),X0\nRET\n",
					row.name, 2*row.width, row.op, row.width)
			}
			root, env := discoveryAsmDeclResultAliasFixture(t, declarations.String(), assembly.String())
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
				t.Fatalf("actual package has %d asmdecl units, want one", len(plan.Units))
			}
			unit := plan.Units[0]
			_, original := runCapturedCommandOutput(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", unit.Filename)
			failure, observed := discoveryAsmDeclObservedFailure(original)
			if !observed {
				t.Fatalf("original package did not produce its FP-name diagnostics: %v", original)
			}
			for _, row := range rows {
				want := fmt.Sprintf("%s: unknown variable alias; offset %d", row.name, row.width)
				if strings.Count(failure.output, want) != 1 {
					t.Fatalf("actual type row has no unique diagnostic %q: %s", want, failure.output)
				}
			}
			if err := plan.filterResultAliasWarnings(unit, original); err != nil {
				t.Fatalf("occupied parameter-type matrix rejected: %v", err)
			}
			if err := runDiscoveryAsmDecl(ctx, root, env, "linux/"+arch, nil, []string{"."}); err != nil {
				t.Fatalf("actual producer rejected occupied transfer types: %v", err)
			}
		})
	}
}
