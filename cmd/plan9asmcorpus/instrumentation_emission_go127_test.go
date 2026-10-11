//go:build go1.27

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestInstrumentationEmissionRolesCompleteReportProgressAndLedger(t *testing.T) {
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	translator := filepath.Join(t.TempDir(), "plan9asmll")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, filepath.Join(root, "cmd", "plan9asmll"), os.Environ(), "go", "build", "-p=1", "-o", translator, ".")
	if err != nil || len(stdout)+len(stderr) != 0 {
		t.Fatalf("actual first-party translator build: %v; %s; %s", err, stdout, stderr)
	}
	for _, test := range []struct{ name, source string }{
		{"symbol-free", "// Nonzero original source without TEXT.\n"},
		{"macro-only", "#define UNUSED(X) MOVD X,R0\n"},
		{"DATA-only", "#include \"textflag.h\"\nDATA local<>+0(SB)/8,$41\nGLOBL local<>(SB),RODATA|NOPTR,$8\n"},
		{"TEXT-and-DATA", "#include \"textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-16\nMOVD x+0(FP),R0\nMOVD R0,ret+8(FP)\nRET\nDATA local<>+0(SB)/8,$41\nGLOBL local<>(SB),RODATA|NOPTR,$8\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			testInstrumentationCorpusOriginalSource(t, root, translator, "race", "1", "darwin/arm64", true, test.source)
		})
	}
}
