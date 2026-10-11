package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Registration is intentionally broader than active consumption. A String
// token in DATA must retain its candidate resource without manufacturing a
// generated-header dependency for every CPU proposal.
func TestCPPProfilesGeneratedHeaderCandidateKeepsOnlyActualBranches(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	const file = "pkg/native_amd64.s"
	plan, root, archive := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		file: "#include \"sub/outer.h\"\nTEXT ·Probe(SB),4,$0-0\nRET\n" +
			"DATA ·candidate(SB)/8,$\"go_asm.h\"\nGLOBL ·candidate(SB),$8\n",
		"pkg/sub/outer.h": "#ifdef unrelated\n#define UNUSED 1\n#endif\n" +
			"#ifdef GOAMD64_v3\nGLOBL ·cpuMarker(SB),$8\n#endif\n",
	})
	inputs, err := captureDiscoveryDeferredCPPInputs(plan, root, runtime.GOROOT(), []string{file}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
		t.Fatal(err)
	}
	unit := inputs.Units[0]
	found := false
	for _, kind := range unit.DeferredIncludes {
		found = found || kind == "generated_go_asm"
	}
	if !found || inputs.Protocol != discoveryReplayCPPInputsProtocol {
		t.Fatal("fixture lost its full original candidate registration")
	}
	plan.CPPInputs = inputs
	profiles, err := captureDiscoveryFeatureProfiles(ctx, binary, t.TempDir(), targetFeatureTestEnv(), plan, []string{file})
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("inactive generated-header candidate became an active CPU dependency: profiles=%d want=2", len(profiles))
	}
	for index, profile := range profiles {
		macros, err := captureDiscoveryAssemblerMacros(runtime.GOROOT(), profile.Observed, plan.Module+"/pkg")
		if err != nil {
			t.Fatal(err)
		}
		_, used, err := replayDiscoveryOriginalCPP(inputs, unit, nil, macros.Defines)
		if err != nil {
			t.Fatal(err)
		}
		for input := range used {
			if input == "generated/"+plan.Module+"/pkg/go_asm.h" {
				t.Fatal("DATA candidate was opened as an active generated header")
			}
		}
		command := &discoveryAsmCommandProfile{Context: ctx, Observed: profile.Observed, GoBinary: binary,
			GoRoot: runtime.GOROOT(), PackagePath: plan.Module + "/pkg", Environment: targetFeatureTestEnv()}
		goCommand, args, env, toolSources, err := discoveryAssemblyProfileCommand(command, "linux", "amd64", runtime.GOROOT())
		if err != nil {
			t.Fatal(err)
		}
		object := filepath.Join(t.TempDir(), "native.o")
		args = append(args, "-o", object, filepath.Join(root, filepath.FromSlash(file)))
		stdout, stderr, err := runDiscoveryMachineCommand(ctx, filepath.Join(root, "pkg"), env, goCommand, args...)
		if err != nil || len(stdout) != 0 || len(stderr) != 0 {
			t.Fatalf("actual original candidate-only ASM %d: %v\n%s\n%s", index, err, stdout, stderr)
		}
		if err := verifyDiscoveryAssemblyProfileTools(command, toolSources); err != nil {
			t.Fatal(err)
		}
		objectSHA, err := discoveryFeatureFileSHA256(object)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("actual SDK=%s profile=%s original_object=%s", plan.GoVersion, profile.ID, objectSHA)
	}
}
