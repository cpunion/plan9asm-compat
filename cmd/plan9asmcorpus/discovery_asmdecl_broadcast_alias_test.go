package main

import (
	"fmt"
	"testing"
)

func TestDiscoveryAsmDeclFPAliasBroadcastActualGo(t *testing.T) {
	t.Setenv("GOCACHE", t.TempDir())
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			op, bank string
			width    int
		}{
			{"VPBROADCASTB", "X", 1}, {"VPBROADCASTW", "X", 2},
			{"VPBROADCASTD", "Y", 4}, {"VPBROADCASTQ", "Y", 8},
			{"VBROADCASTSS", "Y", 4}, {"VBROADCASTSD", "Y", 8},
			{"VBROADCASTF128", "Y", 16}, {"VBROADCASTI32X8", "Z", 32},
		} {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				declaration := fmt.Sprintf("func Value(x, y [%d]byte)", row.width)
				assembly := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s x+%d(FP),%s0\nRET\n",
					row.width*2, row.op, row.width, row.bank)
				testDiscoveryAsmDeclReadOnlyFPAlias(t, arch, declaration, assembly)
			})
		}
	}
}
