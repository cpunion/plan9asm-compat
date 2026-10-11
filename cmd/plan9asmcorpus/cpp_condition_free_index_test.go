package main

import (
	"fmt"
	"testing"
)

func TestCPPConditionFreeIndexAvoidsRepeatedLexing(t *testing.T) {
	plan, _, _ := cppPlanningSourceIndexFixture(t, 1, 1)
	unit := plan.CPPInputs.Units[0]
	measure := func(index *discoveryCPPPlanningSourceIndex) float64 {
		return testing.AllocsPerRun(1, func() {
			free, err := discoveryCPPConditionFreeWithIndex(plan, unit, nil, index)
			if err != nil || !free {
				t.Fatalf("complete source query changed: free=%t error=%v", free, err)
			}
		})
	}
	uncached := measure(nil)
	warm := measure(&discoveryCPPPlanningSourceIndex{})
	t.Logf("complete condition-free query allocations: uncached=%g warm=%g", uncached, warm)
	// AllocsPerRun first warms the private index. Hashes, public projections
	// and graph relationships must still be checked, but repeated complete
	// lexical scans must not dominate that already-observed immutable text.
	if uncached == 0 || warm*4 >= uncached {
		t.Fatalf("warm source index still repeats lexical inspection: %g versus %g", warm, uncached)
	}
}

func TestCPPConditionFreeIndexKeysCompleteOriginalAndFilename(t *testing.T) {
	index := &discoveryCPPPlanningSourceIndex{}
	for _, test := range []struct {
		file, text string
		free       bool
	}{
		{"one.s", "MOVD $1,R0\n", true},
		{"two.s", "MOVD $1,R0\n", true},
		{"one.s", "MOVD $GOARM64_v8,R0\n", false},
		{"one.s", "// GOARM64_v8\nMOVD $1,R0\n", true},
		{"one.s", "#ifdef UNKNOWN\n#endif\n", false},
		{"<observed-go_asm.h>", "#define VALUE 1\n", true},
		{"<observed-go_asm.h>", "#define VALUE GOAMD64_v3\n", false},
	} {
		for repeat := 0; repeat < 2; repeat++ {
			if got := index.conditionFreeText(test.text, test.file); got != test.free {
				t.Fatalf("complete-input lexical answer changed: file=%s text=%q got=%t", test.file, test.text, got)
			}
		}
	}
	if len(index.lexical) != 7 {
		t.Fatal("complete text/filename keys were merged or repeated")
	}
}

func TestCPPConditionFreeIndexEvictionRetainsExactAnswers(t *testing.T) {
	for _, bound := range []string{"files", "bytes"} {
		t.Run(bound, func(t *testing.T) {
			index := &discoveryCPPPlanningSourceIndex{}
			const text = "MOVD $1,R0\n"
			for file := 0; file < 512; file++ {
				if !index.conditionFreeText(text, fmt.Sprintf("probe_%03d.s", file)) {
					t.Fatal("independent constant source became conditional")
				}
				if bound == "bytes" {
					index.lexicalBytes = discoveryReplayCPPGraphBytes
					break
				}
			}
			if !index.conditionFreeText(text, "next.s") || len(index.lexical) != 1 || index.lexicalBytes != len(text) {
				t.Fatalf("lexical index exceeded %s bound: entries=%d bytes=%d", bound, len(index.lexical), index.lexicalBytes)
			}
			if index.conditionFreeText("MOVD $GOARM64_v8,R0\n", "next.s") {
				t.Fatal("eviction granted a stale condition-free answer")
			}
		})
	}
}
