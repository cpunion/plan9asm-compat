package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCPPOriginalFormalIncludeDoesNotPrescanPhysicalOperands(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			for _, operand := range []string{"FILE", "FILE()", "`choice.h`"} {
				t.Run(operand, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					defer cancel()
					parts := strings.Split(target, "/")
					file := "pkg/native_" + parts[1] + ".s"
					source := "#define FILE \"choice.h\"\n#include " + operand +
						"\nTEXT ·Probe(SB),4,$0-0\nRET\n"
					plan, root, archive := fixtureCPPInputsForTarget(t, target, map[string]string{
						file: source, "pkg/choice.h": "GLOBL ·chosen(SB),$8\n",
					})
					object := filepath.Join(t.TempDir(), "original.o")
					env := replaceEnv(targetFeatureTestEnv(), map[string]string{
						"GOOS": parts[0], "GOARCH": parts[1], "CGO_ENABLED": "0",
					})
					args := []string{"tool", "asm", "-p", plan.Module + "/pkg", "-o", object,
						filepath.Join(root, filepath.FromSlash(file))}
					stdout, stderr, err := runDiscoveryMachineCommand(ctx, filepath.Join(root, "pkg"), env, goBinary, args...)
					var exit *exec.ExitError
					if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
						!strings.Contains(string(stderr), ":2: expected string after #include ; got ") || len(stdout) != 0 {
						t.Fatalf("actual original include rejection: %v\n%s\n%s", err, stdout, stderr)
					}
					if data, err := os.ReadFile(object); err == nil && len(data) != 0 {
						t.Fatal("rejected physical operand emitted an original object")
					}
					t.Logf("NONLITERAL_OPERAND_ACTUAL_REJECTION version=%s target=%s source_sha=%s args=%q stderr=%q",
						runtime.Version(), target, discoveryFeatureBytesSHA256([]byte(source)), args, stderr)
					inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{file}, ctx)
					if err != nil {
						t.Fatal(err)
					}
					if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
						t.Fatal(err)
					}
					if _, _, err := replayDiscoveryOriginalCPP(inputs, inputs.Units[0], nil, nil); err == nil {
						t.Fatal("original replay performed C-style include prescan or accepted a RawString")
					}
				})
			}
		})
	}
}
