package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoveryAsmDeclPackedBroadcastUsesScalarInputWidth(t *testing.T) {
	// Go's complete _yvpbroadcastb family reads m8/m16/m32/m64, not
	// the vector destination width or asmdecl's generic D == eight bytes.
	for _, form := range []struct {
		op    string
		bytes int
	}{
		{"VPBROADCASTB", 1}, {"VPBROADCASTW", 2},
		{"VPBROADCASTD", 4}, {"VPBROADCASTQ", 8},
	} {
		for _, suffix := range []string{"", ".Z"} {
			t.Run(form.op+suffix, func(t *testing.T) {
				diagnostic := fmt.Sprintf("vector_amd64.s:2:1: [amd64] Broadcast: invalid %s%s of x+0(FP); [1]uint%d is %d-byte value", form.op, suffix, form.bytes*8, form.bytes)
				if isDiscoveryAsmDeclABIMismatch(diagnostic) {
					t.Fatalf("known scalar input width became ABI N/A: %s", diagnostic)
				}
				for _, width := range []int{1, 2, 4, 8, 16, 32, 64} {
					if width == form.bytes {
						continue
					}
					diagnostic := fmt.Sprintf("vector_amd64.s:2:1: [amd64] Broadcast: invalid %s%s of x+0(FP); Value is %d-byte value", form.op, suffix, width)
					if !isDiscoveryAsmDeclABIMismatch(diagnostic) {
						t.Fatalf("unequal input width was hidden: %s", diagnostic)
					}
				}
			})
		}
	}
	for _, instruction := range []string{"VPBROADCASTD.BCST", "VPBROADCASTD.BAD", "VUNKNOWND"} {
		diagnostic := "vector_amd64.s:2:1: [amd64] Broadcast: invalid " + instruction + " of x+0(FP); uint32 is 4-byte value"
		if !isDiscoveryAsmDeclABIMismatch(diagnostic) {
			t.Fatalf("unknown opcode/suffix became a width exception: %s", diagnostic)
		}
	}
}

func TestRunDiscoveryAsmDeclPreservesGoAcceptedDwordBroadcast(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.com/broadcast\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(dir, "broadcast.go"), "package broadcast\n\nfunc Broadcast(x uint32, out *[4]uint32)\n")
	writeTestFile(t, filepath.Join(dir, "broadcast_amd64.s"), "TEXT ·Broadcast(SB),4,$0-16\nVPBROADCASTD x+0(FP),X0\nMOVQ out+8(FP),AX\nMOVOU X0,(AX)\nRET\n")
	env := replaceEnv(os.Environ(), map[string]string{
		"GOFLAGS": "-mod=mod", "GOWORK": "off", "CGO_ENABLED": "0",
		"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1",
	})
	if err := runDiscoveryGoBuild(context.Background(), dir, env, "linux/amd64", nil, "example.com/broadcast"); err != nil {
		t.Fatalf("Go's own assembler rejected the independent m32 broadcast: %v", err)
	}
	_, raw := runCapturedCommandOutput(context.Background(), dir, env, "go", "vet", "-asmdecl", "example.com/broadcast")
	if raw == nil || !strings.Contains(discoveryCommandDiagnostic(raw), "invalid VPBROADCASTD") ||
		!strings.Contains(discoveryCommandDiagnostic(raw), "uint32 is 4-byte value") {
		t.Fatalf("actual Go asmdecl width false positive was not reproduced: %v", raw)
	}
	if err := runDiscoveryAsmDecl(context.Background(), dir, env, "linux/amd64", nil, []string{"example.com/broadcast"}); err != nil {
		t.Fatalf("Go-accepted m32 broadcast was excluded before translation: %v", err)
	}
}

func TestDiscoveryAsmDeclWordWidthBelongsToItsArchitecture(t *testing.T) {
	for _, arch := range []string{"386", "amd64", "arm", "arm64"} {
		for _, bytes := range []int{2, 4} {
			diagnostic := fmt.Sprintf("move.s:2:1: [%s] Move: invalid MOVW of x+0(FP); [1]uint%d is %d-byte value", arch, bytes*8, bytes)
			want := 2
			if arch == "arm" || arch == "arm64" {
				want = 4
			}
			if mismatch := isDiscoveryAsmDeclABIMismatch(diagnostic); mismatch != (bytes != want) {
				t.Errorf("%s MOVW physical width=%d, declared=%d, got ABI mismatch=%t", arch, want, bytes, mismatch)
			}
		}
	}
}

func TestRunDiscoveryAsmDeclARMWordCannotUseX86WidthException(t *testing.T) {
	for _, bytes := range []int{2, 4} {
		t.Run(fmt.Sprint(bytes), func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, filepath.Join(dir, "go.mod"), "module example.com/armword\n\ngo 1.20\n")
			writeTestFile(t, filepath.Join(dir, "move.go"), fmt.Sprintf("package armword\n\nfunc Move(x [1]uint%d, out *uint32)\n", bytes*8))
			writeTestFile(t, filepath.Join(dir, "move_arm.s"), "TEXT ·Move(SB),4,$0-8\nMOVW x+0(FP),R0\nMOVW out+4(FP),R1\nMOVW R0,(R1)\nRET\n")
			env := replaceEnv(os.Environ(), map[string]string{
				"GOFLAGS": "-mod=mod", "GOWORK": "off", "CGO_ENABLED": "0",
				"GOOS": "linux", "GOARCH": "arm", "GOARM": "7",
			})
			if err := runDiscoveryGoBuild(context.Background(), dir, env, "linux/arm", nil, "example.com/armword"); err != nil {
				t.Fatal(err)
			}
			_, raw := runCapturedCommandOutput(context.Background(), dir, env, "go", "vet", "-asmdecl", "example.com/armword")
			if raw == nil || !strings.Contains(discoveryCommandDiagnostic(raw), "invalid MOVW") ||
				!strings.Contains(discoveryCommandDiagnostic(raw), fmt.Sprintf("%d-byte value", bytes)) {
				t.Fatalf("actual ARM word-width diagnostic not reproduced: %v", raw)
			}
			err := runDiscoveryAsmDecl(context.Background(), dir, env, "linux/arm", nil, []string{"example.com/armword"})
			if (err != nil) != (bytes != 4) {
				t.Fatalf("ARM MOVW reads four bytes; declared=%d, error=%v", bytes, err)
			}
		})
	}
}
