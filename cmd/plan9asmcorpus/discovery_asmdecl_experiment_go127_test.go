//go:build go1.27

package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAsmDeclDirectActualExperimentToolVersions(t *testing.T) {
	root := discoveryAsmDeclRetryPhysicalTemp(t)
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.invalid/direct-experiment\n\ngo 1.20\n")
	writeTestFile(t, filepath.Join(root, "decl.go"), "//go:build goexperiment.simd\n\npackage experiment\nfunc Bad() uint64\n")
	writeTestFile(t, filepath.Join(root, "decl_amd64.s"), "//go:build goexperiment.simd\n\nTEXT ·Bad(SB),4,$0-8\nMOVQ $2,ret+8(FP)\nRET\n")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, requested := range []string{"simd", "simd,simd"} {
		t.Run(requested, func(t *testing.T) {
			env := replaceEnv(discoveryAsmDeclDirectFixtureEnv(t, root), map[string]string{"GOEXPERIMENT": requested})
			goBinary, err := directAsmDeclGoBinary(env)
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(ctx, goBinary, "tool", "vet", "-V=full")
			command.Dir, command.Env = root, env
			version, err := command.CombinedOutput()
			if err != nil || !strings.HasSuffix(strings.TrimSpace(string(version)), " X:simd") {
				t.Fatalf("actual selected SDK did not reproduce its canonical experiment suffix: %v / %s", err, version)
			}
			plan, err := captureDiscoveryAsmDeclDirect(ctx, root, env, nil, []string{"."}, "")
			if err != nil {
				t.Fatalf("selected SDK's actual experiment tool identity was rejected: %v", err)
			}
			defer func() {
				if err := plan.close(); err != nil {
					t.Error(err)
				}
			}()
			for _, tool := range []string{"vet", "compile", "asm"} {
				if plan.ToolVersions[tool] != tool+" version "+plan.SDK["GOVERSION"]+" X:simd" {
					t.Fatalf("complete %s experiment identity was lost: %q", tool, plan.ToolVersions[tool])
				}
			}
			analysis := plan.run(ctx)
			if _, observed := discoveryAsmDeclObservedFailures(analysis); !observed ||
				!strings.Contains(discoveryCommandDiagnostic(analysis), "invalid offset ret+8(FP)") {
				t.Fatalf("experiment selected source did not receive its real official asmdecl analysis: %v", analysis)
			}
			plan.Env = replaceEnv(plan.Env, map[string]string{"GOEXPERIMENT": ""})
			if err := plan.verify(ctx); err == nil {
				t.Fatal("changing the experiment context retained direct analysis authority")
			}
		})
	}
}
