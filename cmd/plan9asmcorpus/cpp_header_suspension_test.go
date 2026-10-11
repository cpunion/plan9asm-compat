package main

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCPPProfilesGeneratedHeaderCandidateCannotHideUnrelatedCPPFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	const assembly = "pkg/probe_amd64.s"
	plan, root, archive := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		assembly: "#define RET(x) x\nTEXT ·Probe(SB),4,$0-0\nRET\n" +
			"DATA ·candidate(SB)/8,$\"go_asm.h\"\nGLOBL ·candidate(SB),$8\n",
	})
	plan.CPPInputs, err = captureDiscoveryDeferredCPPInputs(plan, root, runtime.GOROOT(), []string{assembly}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCPPModuleZIP(plan.CPPInputs, plan, archive); err != nil {
		t.Fatal(err)
	}
	profiles, err := captureDiscoveryFeatureProfiles(ctx, binary, t.TempDir(), targetFeatureTestEnv(), plan, []string{assembly})
	if err == nil || !strings.Contains(err.Error(), `function-like macro "RET" requires arguments`) || len(profiles) != 0 {
		t.Fatalf("registered inactive candidate swallowed unrelated full-source CPP failure: profiles=%d err=%v", len(profiles), err)
	}
}
