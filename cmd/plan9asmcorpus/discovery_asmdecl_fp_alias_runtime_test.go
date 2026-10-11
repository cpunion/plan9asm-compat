//go:build amd64 || (darwin && arm64)

package main

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclFPAliasActualTypedCaller(t *testing.T) {
	root, env := discoveryAsmDeclResultAliasFixture(t, "func Value(x, y uint64) uint64", "TEXT ·Value(SB),4,$0-24\nMOVQ x+8(FP),AX\nMOVQ AX,y+16(FP)\nRET\n")
	// This is the original alias source, never a canonical-name replacement.
	writeTestFile(t, filepath.Join(root, "caller_test.go"), `package alias
import "testing"
func TestOriginalFPAddress(t *testing.T) {
	values := []uint64{0, 1, 0x8000000000000000, 0xffffffffffffffff}
	for _, x := range values {
		for _, y := range values {
			got := Value(x, y)
			if got != y { t.Fatalf("x=%x y=%x result=%x", x, y, got) }
		}
	}
}
`)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	callerEnv := replaceEnv(env, map[string]string{"GOOS": runtime.GOOS, "GOARCH": "amd64"})
	output, err := runCapturedCommandOutput(ctx, root, callerEnv, "go", "test", "-vet=off", "-count=1", "-run", "^TestOriginalFPAddress$", ".")
	if err != nil {
		t.Fatalf("original unchanged assembly typed caller failed: %v", err)
	}
	t.Logf("ORIGINAL_TYPED_GO_CALLER host=%s/%s guest=%s/amd64 (Darwin ARM64 uses Rosetta): %s", runtime.GOOS, runtime.GOARCH, runtime.GOOS, output)
}
