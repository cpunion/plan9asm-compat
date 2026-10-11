//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// The archive and actual Go package selection are independent of the transport
// being tested. These are first-party originals, not external corpus passes.
func cppPackageTransportFixture(t *testing.T, targets, files []string, sources map[string]string) (*discoveryOrdinarySelectionPlan, []discoveryFeatureProfile, string) {
	t.Helper()
	plan, root, archive := fixtureCPPInputsForTarget(t, targets[0], sources)
	plan.Targets = append([]string(nil), targets...)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	profiles, err := captureDiscoveryFeatureProfiles(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), plan, files)
	if err != nil {
		t.Fatal(err)
	}
	decisions, _, err := replayOrdinarySelectionForProfiles(plan, files, profiles)
	if err != nil {
		t.Fatal(err)
	}
	plan.ProfileDecisions = decisions
	for _, profile := range profiles {
		output, stderr, err := runDiscoveryMachineCommand(ctx, filepath.Join(root, "pkg"),
			replaceEnv(targetFeatureTestEnv(), profile.Observed.Environment), goBinary,
			"list", "-p=2", "-mod=readonly", "-export", "-json", ".")
		if err != nil || len(stderr) != 0 {
			t.Fatalf("actual original %s package selection/export: %v\n%s\n%s", profile.Observed.Target, err, output, stderr)
		}
		var selected struct {
			SFiles []string
			Export string
		}
		if err := json.Unmarshal(output, &selected); err != nil {
			t.Fatal(err)
		}
		var expected []string
		for _, decision := range decisions {
			if decision.ProfileID == profile.ID && decision.Kind == nativeLayoutSelected {
				for _, file := range decision.AsmFiles {
					expected = append(expected, filepath.Base(file))
				}
			}
		}
		sort.Strings(expected)
		sort.Strings(selected.SFiles)
		if !reflect.DeepEqual(selected.SFiles, expected) || selected.Export == "" {
			t.Fatalf("actual package did not select the complete original ASM set: %v != %v", selected.SFiles, expected)
		}
		if _, err := discoveryFeatureFileSHA256(selected.Export); err != nil {
			t.Fatal(err)
		}
	}
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), files, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
		t.Fatal(err)
	}
	plan.CPPInputs = inputs
	return plan, profiles, root
}

func TestCPPTransportOmitsOtherTargetOriginalBodies(t *testing.T) {
	padding := strings.Repeat("// Harmless original body padding, after TEXT and RET.\n", (18<<20)/53)
	body := "TEXT ·Probe(SB),4,$0-0\nRET\n" + padding
	files := []string{"pkg/native_amd64.s", "pkg/native_arm64.s"}
	plan, profiles, root := cppPackageTransportFixture(t,
		[]string{"linux/amd64", "linux/arm64"}, files, map[string]string{
			"pkg/decl.go":        "package fixture\nfunc Probe()\n",
			"pkg/native_amd64.s": body,
			"pkg/native_arm64.s": body,
		})
	for _, profile := range profiles {
		selected := ordinaryProfilePackageAssembly(plan, profile, files, nil)
		if len(selected) != 1 {
			t.Fatalf("actual target did not select one original: %v", selected)
		}
		input := ordinaryProfileConsumerInput(plan, profile, plan.Module, root, selected)
		data, err := gotoolprofile.MarshalConsumerInput(input)
		if err != nil {
			t.Fatalf("one bounded target transported unrelated original bodies: %v", err)
		}
		decoded, err := gotoolprofile.DecodeConsumerInput(strings.NewReader(string(data)))
		if err != nil || gotoolprofile.ValidateCPPOriginalInputs(decoded) != nil {
			t.Fatalf("actual selected original did not survive private transport: %v", err)
		}
		if len(decoded.CPPOriginals.Units) != 1 || len(decoded.CPPOriginals.Sources) != 1 {
			t.Fatal("unselected target bodies remain in the invocation graph")
		}
		for _, file := range files {
			if decoded.Sources[file] != input.Sources[file] || decoded.Sources[file] == "" {
				t.Fatal("transport removed complete original membership/hash metadata", file)
			}
		}
		t.Logf("actual %s private packet=%d bytes, original=%d bytes", profile.Observed.Target, len(data), len(body))
	}
}

func TestCPPTransportRequiresSourceOnlySelectedSibling(t *testing.T) {
	files := []string{"pkg/companion_amd64.s", "pkg/native_amd64.s"}
	plan, profiles, root := cppPackageTransportFixture(t, []string{"linux/amd64"}, files, map[string]string{
		"pkg/decl.go":           "package fixture\nfunc Probe()\nfunc Companion()\n",
		"pkg/native_amd64.s":    "TEXT ·Probe(SB),4,$0-0\nRET\n",
		"pkg/companion_amd64.s": "#include \"sub/outer.h\"\nTEXT ·Companion(SB),4,$0-0\nRET\n",
	})
	for _, profile := range profiles {
		input := ordinaryProfileConsumerInput(plan, profile, plan.Module, root, []string{"pkg/native_amd64.s"})
		if !equalDiscoveryStrings(input.RegisteredAsmFiles, files) || len(input.CPPOriginals.Units) != 2 ||
			input.CPPOriginals.Sources["module/pkg/choice.h"] == "" {
			t.Fatal("object-scope projection concealed selected source-only companion or nested include")
		}
		delete(input.CPPOriginals.Units, "pkg/companion_amd64.s")
		if err := gotoolprofile.ValidateCPPOriginalInputs(input); err == nil {
			t.Fatal("missing source-only selected unit was accepted by mandatory consumer validation")
		}
	}
}

func TestCPPTransportRetainsInactiveClosureAndIndependentQueries(t *testing.T) {
	files := []string{"pkg/native_amd64.s", "pkg/native_arm64.s"}
	plan, profiles, root := cppPackageTransportFixture(t, []string{"linux/amd64"}, files, map[string]string{
		"pkg/decl.go": "package fixture\nfunc Probe()\n",
		"pkg/native_amd64.s": "#include \"textflag.h\"\n#include \"sub/outer.h\"\n" +
			"TEXT ·Probe(SB),NOSPLIT,$0-0\nRET\n",
		"pkg/native_arm64.s": "TEXT ·Probe(SB),4,$0-0\nRET\n",
		"pkg/sub/outer.h": "#ifdef GOAMD64_v3\n#include \"choice.h\"\n" +
			"#else\n#include \"alternate.h\"\n#endif\n",
		"pkg/alternate.h": "#define ALTERNATE 1\n",
	})
	profile := profiles[0]
	selected := []string{"pkg/native_amd64.s"}
	construct := func() *gotoolprofile.ConsumerInput {
		return ordinaryProfileConsumerInput(plan, profile, plan.Module, root, selected)
	}
	input := construct()
	for _, id := range []string{"module/pkg/native_amd64.s", "module/pkg/sub/outer.h",
		"module/pkg/choice.h", "module/pkg/alternate.h", "tool/pkg/include/textflag.h"} {
		if input.CPPOriginals.Sources[id] == "" {
			t.Fatal("projection dropped an inactive/transitive or SDK source", id)
		}
	}
	if _, present := input.CPPOriginals.Sources["module/pkg/native_arm64.s"]; present {
		t.Fatal("unselected other-target body was transported")
	}
	if len(plan.CPPInputs.Units) != 2 || len(plan.CPPInputs.Sources) != 6 {
		t.Fatal("per-invocation projection mutated the captured module graph")
	}
	for name, mutate := range map[string]func(*gotoolprofile.ConsumerInput){
		"selected_unit": func(in *gotoolprofile.ConsumerInput) {
			delete(in.CPPOriginals.Units, selected[0])
		},
		"inactive_include": func(in *gotoolprofile.ConsumerInput) {
			delete(in.CPPOriginals.Sources, "module/pkg/alternate.h")
		},
		"tool_bytes": func(in *gotoolprofile.ConsumerInput) {
			in.CPPOriginals.Sources["tool/pkg/include/textflag.h"] += "changed"
		},
		"original_hash": func(in *gotoolprofile.ConsumerInput) {
			in.Sources["pkg/sub/outer.h"] = strings.Repeat("0", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := construct()
			mutate(changed)
			if err := gotoolprofile.ValidateCPPOriginalInputs(changed); err == nil {
				t.Fatal("changed projected original closure was accepted")
			}
			fresh := construct()
			if err := gotoolprofile.ValidateCPPOriginalInputs(fresh); err != nil {
				t.Fatalf("one private query mutated another invocation or source graph: %v", err)
			}
		})
	}
	// Even an unselected original remains part of the independently validated
	// module graph. Projection cannot rescue changed captured source bytes.
	other := plan.CPPInputs.Sources["module/pkg/native_arm64.s"]
	changed := *other.Original + "changed"
	other.Original = &changed
	plan.CPPInputs.Sources["module/pkg/native_arm64.s"] = other
	if got := construct(); got.CPPSourceProtocol == "" || got.CPPOriginals != nil {
		t.Fatal("projection skipped full-module validation before transport")
	}
}
