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

func TestCPPOriginalFormalIncludeOperandsFiveActualArchitectures(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			for _, style := range []string{"formal_string", "nested_formal", "alias_formal", "ordered_driver_alias", "recorded_string"} {
				t.Run(style, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					defer cancel()
					prefix := "#define INCLUDE(file) \\\n#include file \\\n\n"
					invocation := "INCLUDE(\"choice.h\")\n"
					if style == "nested_formal" {
						prefix += "#define APPLY(file) INCLUDE(file)\n"
						invocation = "APPLY(\"choice.h\")\n"
					} else if style == "alias_formal" {
						prefix += "#define APPLY INCLUDE\n"
						invocation = "APPLY(\"choice.h\")\n"
					} else if style == "ordered_driver_alias" {
						invocation = "APPLY(\"choice.h\")\n"
					} else if style == "recorded_string" {
						invocation = "INCLUDE(\"folder∕choice.h\")\n"
					}
					source := prefix + invocation + "TEXT ·Probe(SB),4,$0-0\nRET\n"
					parts := strings.Split(target, "/")
					file := "pkg/native_" + parts[1] + ".s"
					plan, root, archive := fixtureCPPInputsForTarget(t, target, map[string]string{
						file: source, "pkg/choice.h": "GLOBL ·chosen(SB),$8\n",
						"pkg/folder/choice.h": "GLOBL ·chosen(SB),$8\n",
						"pkg/folder∕choice.h": "GLOBL ·unchosen(SB),$8\n",
					})
					observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), target, nil)
					if err != nil {
						t.Fatal(err)
					}
					profile := &discoveryAsmCommandProfile{
						Context: ctx, Observed: observed, GoBinary: goBinary, GoRoot: runtime.GOROOT(),
						PackagePath: plan.Module + "/pkg", Environment: targetFeatureTestEnv(),
					}
					binary, args, env, _, err := discoveryAssemblyProfileCommand(profile, parts[0], parts[1], runtime.GOROOT())
					if err != nil {
						t.Fatal(err)
					}
					// These arbitrary first-party -D inputs are original-Go/replay
					// comparisons only, not permission to add custom CLI defines.
					if style == "ordered_driver_alias" {
						args = append(args, "-D", "APPLY=IGNORED", "-D", "APPLY=INCLUDE")
					}
					defines := []string{}
					for index := 0; index+1 < len(args); index++ {
						if args[index] == "-D" {
							index++
							defines = append(defines, args[index])
						}
					}
					object := filepath.Join(t.TempDir(), "original.o")
					args = append(args, "-S", "-o", object, filepath.Join(root, filepath.FromSlash(file)))
					stdout, stderr, err := runDiscoveryMachineCommand(ctx, filepath.Join(root, "pkg"), env, binary, args...)
					if err != nil || len(stderr) != 0 || !strings.Contains(string(stdout), "chosen") {
						t.Fatalf("actual original formal include: %v\n%s\n%s", err, stdout, stderr)
					}
					data, err := os.ReadFile(object)
					if err != nil || len(data) == 0 {
						t.Fatalf("missing actual original object: %v", err)
					}
					receipt, err := json.Marshal(struct {
						Version, Target, Style, Source, SourceSHA, ObjectSHA string
						Object                                               []byte
						Arguments, Defines                                   []string
					}{observed.GoVersion, target, style, source, discoveryFeatureBytesSHA256([]byte(source)),
						discoveryFeatureBytesSHA256(data), data, args, defines})
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("NONLITERAL_OPERAND_ACTUAL_GO_RECEIPT %s", receipt)

					inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{file}, ctx)
					if err != nil {
						t.Fatalf("Go-accepted formal String has no original graph: %v", err)
					}
					if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
						t.Fatal(err)
					}
					observation, used, err := replayDiscoveryOriginalCPP(inputs, inputs.Units[0], nil, defines)
					if err != nil || len(used) != 2 || !strings.Contains(observation.Output, "chosen") {
						t.Fatalf("formal String original replay: %v %v\n%s", err, used, observation.Output)
					}
					if style == "recorded_string" && strings.Contains(observation.Output, "unchosen") {
						t.Fatal("recorded argument String was treated as the physical spelling")
					}
				})
			}
		})
	}
}
