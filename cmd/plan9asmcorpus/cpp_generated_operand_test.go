package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCPPOriginalReplayGeneratedOutsidePackageOperandFiveActualArchitectures(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), target, nil)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(target, "/")
			for _, style := range []string{"object", "alias", "function"} {
				t.Run(style, func(t *testing.T) {
					name, invocation := "SELECT", "SELECT"
					prefix := ""
					if style == "alias" {
						prefix = "#define INVOKE SELECT\n"
						invocation = "INVOKE"
					} else if style == "function" {
						name, invocation = "SELECT(P)", "SELECT(1)"
					}
					source := prefix + strings.Join([]string{
						"#define " + name + " \\",
						"#include \"../../src/runtime/go_tls.h\" \\",
						"",
						invocation,
						"TEXT ·Probe(SB),4,$0-0",
						"RET",
						"",
					}, "\n")
					file := "pkg/native_" + parts[1] + ".s"
					plan, root, archive := fixtureCPPInputsForTarget(t, target, map[string]string{file: source})
					profile := &discoveryAsmCommandProfile{
						Context: ctx, Observed: observed, GoBinary: goBinary,
						GoRoot: runtime.GOROOT(), PackagePath: plan.Module + "/pkg", Environment: targetFeatureTestEnv(),
					}
					binary, args, env, _, err := discoveryAssemblyProfileCommand(profile, parts[0], parts[1], runtime.GOROOT())
					if err != nil {
						t.Fatal(err)
					}
					object := filepath.Join(t.TempDir(), "original.o")
					args = append(args, "-I", filepath.Join(runtime.GOROOT(), "pkg/include"),
						"-o", object, filepath.Join(root, filepath.FromSlash(file)))
					var defines []string
					for index := 0; index+1 < len(args); index++ {
						if args[index] == "-D" {
							defines = append(defines, args[index+1])
							index++
						}
					}
					if stdout, stderr, err := runDiscoveryMachineCommand(ctx, filepath.Join(root, "pkg"), env, binary, args...); err != nil || len(stderr) != 0 {
						t.Fatalf("actual original generated operand failed: %v\n%s\n%s", err, stdout, stderr)
					}
					bytes, err := os.ReadFile(object)
					if err != nil || len(bytes) == 0 {
						t.Fatalf("missing actual original object: %v", err)
					}
					receipt, err := json.Marshal(struct {
						Version, Target, Style, Source, SourceSHA, ObjectSHA string
						Object                                               []byte
						Arguments                                            []string
					}{observed.GoVersion, target, style, source, discoveryFeatureBytesSHA256([]byte(source)),
						discoveryFeatureBytesSHA256(bytes), bytes, args})
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("GENERATED_OPERAND_ACTUAL_GO_RECEIPT %s", receipt)

					inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{file}, ctx)
					if err != nil {
						t.Fatalf("Go-accepted original expanded outside-package operand lacks replay binding: %v", err)
					}
					if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
						t.Fatal(err)
					}
					if _, _, err := replayDiscoveryOriginalCPP(inputs, inputs.Units[0], nil, defines); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}
