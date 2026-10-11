//go:build go1.27

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestCPPGeneratedHeaderFullDefaultProfileProjection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := parseDiscoveryTargets("darwin/amd64,darwin/arm64,linux/386,linux/amd64,linux/arm,linux/arm64,windows/386,windows/amd64,windows/arm64,js/wasm,wasip1/wasm")
	if err != nil {
		t.Fatal(err)
	}
	baselines := []*discoveryTargetFeatures{}
	for _, target := range targets {
		observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), target, nil)
		if err != nil {
			t.Fatal(err)
		}
		baselines = append(baselines, observed)
	}

	for _, role := range []string{"without_header", "active_header", "candidate_only"} {
		t.Run(role, func(t *testing.T) {
			candidate := discoveryCandidate{Module: "example.invalid/ordinary-formal-includes", Version: "v1.0.0", AsmFiles: []string{"probe.s"}}
			source := "#include \"macros.h\"\n" +
				"INCLUDE(\"formal.h\")\nAPPLY(\"nested.h\")\nALIAS(\"alias.h\")\n"
			if role == "active_header" {
				source += "INCLUDE(\"go_asm.h\")\nGLOBL ·recordMarker(SB),$Record__size\n"
			}
			source += "INCLUDE(\"../../src/runtime/go_tls.h\")\n" +
				"TEXT ·Probe(SB),4,$0-0\nRET\nDATA ·unused(SB)/8,$\"nofile.h\"\nGLOBL ·unused(SB),$8\n"
			if role == "candidate_only" {
				source += "DATA ·headerName(SB)/8,$\"go_asm.h\"\nGLOBL ·headerName(SB),$8\n"
			}
			if role == "active_header" && discoveryFeatureBytesSHA256([]byte(source)) != "8fdcb78334423b2e71ebd8360a3d2853a18199088e7f4726da45946efca6452b" {
				t.Fatal("the exact retained full11 source changed")
			}
			sources := map[string]string{
				"go.mod":   "module example.invalid/ordinary-formal-includes\n\ngo 1.20\n",
				"probe.go": "package fixture\nfunc Probe()\n",
				"cpu.s":    "// Original nonempty selected sibling, not a discovered file.\n",
				"probe.s":  source,
				"macros.h": "#define INCLUDE(file) \\\n#include file \\\n\n#define APPLY(file) INCLUDE(file)\n#define ALIAS INCLUDE\n",
				"formal.h": "GLOBL ·formalMarker(SB),$8\n",
				"nested.h": "GLOBL ·nestedMarker(SB),$8\n",
				"alias.h":  "GLOBL ·aliasMarker(SB),$8\n",
			}
			if role == "active_header" {
				sources["probe.go"] = "package fixture\ntype Record struct { Value uint64 }\nfunc Probe()\n"
			}
			download := fixtureProfileModuleDownload(t, candidate, sources)
			for _, target := range targets {
				goos, goarch, _ := strings.Cut(target, "/")
				env := replaceEnv(os.Environ(), map[string]string{"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0"})
				stdout, stderr, err := runDiscoveryMachineCommand(ctx, download.Dir, env, goBinary,
					"list", "-p=2", "-mod=readonly", "-export", "-json", ".")
				if err != nil || len(stderr) != 0 {
					t.Fatalf("actual original export %s: %v\n%s\n%s", target, err, stdout, stderr)
				}
				var selected struct {
					GoFiles, SFiles []string
					Export          string
				}
				if err := json.Unmarshal(stdout, &selected); err != nil || selected.Export == "" ||
					!equalDiscoveryStrings(selected.GoFiles, []string{"probe.go"}) ||
					!equalDiscoveryStrings(selected.SFiles, []string{"cpu.s", "probe.s"}) {
					t.Fatalf("actual original file/export scope: %+v %v", selected, err)
				}
				digest, err := discoveryFeatureFileSHA256(selected.Export)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("GENERATED_PROFILE_ORIGINAL_EXPORT target=%s source_sha=%s export_sha=%s", target,
					discoveryFeatureBytesSHA256([]byte(source)), digest)
			}
			plan, err := captureOrdinarySelectionInputs(candidate, download.Dir, targets)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyOrdinarySelectionZIP(plan, download.Zip, candidate.Module, candidate.Version, download.Sum); err != nil {
				t.Fatal(err)
			}
			plan.CPPInputs, err = captureDiscoveryDeferredCPPInputs(plan, download.Dir, runtime.GOROOT(), candidate.AsmFiles, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyDiscoveryCPPModuleZIP(plan.CPPInputs, plan, download.Zip); err != nil {
				t.Fatal(err)
			}

			projection := map[string][]discoveryFeatureProfileRequest{}
			unique := make(map[string]bool)
			for _, baseline := range baselines {
				model, err := discoveryContextForFeatureProfile(baseline)
				if err != nil {
					t.Fatal(err)
				}
				model.OpenFile = func(file string) (io.ReadCloser, error) {
					data, found := sources[filepath.ToSlash(file)]
					if !found {
						return nil, fmt.Errorf("uncaptured original %s", file)
					}
					return io.NopCloser(bytes.NewBufferString(data)), nil
				}
				initial, found, err := planDiscoveryFeaturePair(model, baseline, "probe.s", "probe.go")
				if err != nil || !found {
					t.Fatalf("initial source pair: %v %t", err, found)
				}
				proposals, err := planDiscoveryCPPFeaturePair(plan, model, baseline, "probe.s", "probe.go", initial)
				if err != nil {
					t.Fatal(err)
				}
				byKey := make(map[string]discoveryFeatureProfileRequest)
				for _, request := range append(proposals, initial, discoveryFeatureProfileRequest{Target: baseline.Target, Baseline: true}) {
					key := discoveryFeatureRequestKey(request)
					byKey[key], unique[key] = request, true
				}
				keys := make([]string, 0, len(byKey))
				for key := range byKey {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					projection[baseline.Target] = append(projection[baseline.Target], byKey[key])
				}
				input, err := discoveryCPPOriginalConsumerInput(plan.CPPInputs)
				if err != nil {
					t.Fatal(err)
				}
				var firstBranches map[string]bool
				var firstDefinitions map[string]string
				for _, key := range keys {
					request := byKey[key]
					environment := cloneDiscoveryCPPEnvironment(baseline.Environment)
					for name, value := range request.Overrides {
						environment[name] = value
					}
					defines, err := plan9asm.GoAssemblerDefinesForEnvironment(model.GOOS, model.GOARCH, environment)
					if err != nil {
						t.Fatal(err)
					}
					var nativeHeader []byte
					if role == "active_header" {
						out := t.TempDir()
						header, object := filepath.Join(out, "native.h"), filepath.Join(out, "native.o")
						args := []string{"tool", "compile", "-p", candidate.Module, "-lang", "go1.20",
							"-goversion", baseline.GoVersion, "-asmhdr", header, "-o", object, "probe.go"}
						stdout, stderr, err := runDiscoveryMachineCommand(ctx, download.Dir,
							replaceEnv(os.Environ(), environment), goBinary, args...)
						if err != nil || len(stdout) != 0 || len(stderr) != 0 {
							t.Fatalf("actual original compiler header %s: %v\n%s\n%s", key, err, stdout, stderr)
						}
						nativeHeader, err = os.ReadFile(header)
						if err != nil {
							t.Fatal(err)
						}
						definitions, err := gotoolprofile.HeaderDefinitions(nativeHeader)
						if err != nil || definitions["Record__size"] != "8" || definitions["Record_Value"] != "0" {
							t.Fatalf("actual Record native header: %v %v", definitions, err)
						}
						if firstDefinitions == nil {
							firstDefinitions = definitions
						} else if !reflect.DeepEqual(firstDefinitions, definitions) {
							t.Fatal("actual native-header definitions vary across proposed CPU environments")
						}
						objectSHA, err := discoveryFeatureFileSHA256(object)
						if err != nil {
							t.Fatal(err)
						}
						t.Logf("GENERATED_PROFILE_ACTUAL_HEADER key=%s header_sha=%s object_sha=%s definitions=%v",
							key, discoveryFeatureBytesSHA256(nativeHeader), objectSHA, definitions)
					}
					observation, used, _, err := gotoolprofile.ReplayCPPOriginal(input, "probe.s", candidate.Module, defines, nativeHeader)
					if err != nil {
						t.Fatalf("actual original header/candidate replay %s: %v", key, err)
					}
					_, activeHeader := used["generated/"+candidate.Module+"/go_asm.h"]
					if activeHeader != (role == "active_header") {
						t.Fatalf("candidate vs active native header: %v", used)
					}
					branches, err := discoveryCPPBranchCoverage(observation)
					if err != nil {
						t.Fatal(err)
					}
					if firstBranches == nil {
						firstBranches = branches
					} else if !reflect.DeepEqual(firstBranches, branches) {
						t.Fatal("actual same-source branch coverage varies across proposed CPU environments")
					}
				}
				t.Logf("GENERATED_PROFILE_ACTUAL_REPLAY_EQUIVALENCE target=%s proposals=%d branches=%d active_header=%t",
					baseline.Target, len(keys), len(firstBranches), role == "active_header")
			}
			data, err := json.Marshal(struct {
				Role, SourceSHA, GoVersion string
				UniqueProposals            int
				Projection                 map[string][]discoveryFeatureProfileRequest
			}{role, discoveryFeatureBytesSHA256([]byte(source)), plan.GoVersion, len(unique), projection})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("GENERATED_PROFILE_PROPOSAL_PROJECTION %s", data)
			requests, err := planDiscoveryFeatureProfiles(plan, candidate.AsmFiles, baselines)
			if role == "active_header" {
				// This independently measured header equality is not a portable
				// planning authority. Preserve every proposal within each actual
				// target's budget, without header-dependent pruning. These are
				// requests, not driver observations or compiled-object evidence.
				if err != nil || len(unique) != 123 || len(requests) != len(unique) {
					t.Fatalf("unbound active header acquired a fabricated reduced scope: proposals=%d requests=%d err=%v", len(unique), len(requests), err)
				}

				seen := make(map[string]bool)
				counts := make(map[string]int)
				for _, request := range requests {
					key := discoveryFeatureRequestKey(request)
					if !unique[key] || seen[key] {
						t.Fatalf("missing, invented or duplicate original proposal %s", key)
					}
					seen[key] = true
					counts[request.Target]++
				}
				for _, target := range targets {
					if counts[target] != len(projection[target]) || counts[target] == 0 || counts[target] > 64 {
						t.Fatalf("incomplete or unbounded actual target %s: got %d, original proposals %d",
							target, counts[target], len(projection[target]))
					}
				}
				t.Logf("GENERATED_PROFILE_UNRESOLVED_ACTIVE_HEADER proposals=%d targets=%d", len(requests), len(counts))
				return
			}
			if err != nil || len(requests) != len(targets) {
				t.Fatalf("CPU-independent original full11 scope must not expand to every CPU: unique_proposals=%d complete_planner_profiles=%d err=%v", len(unique), len(requests), err)
			}
		})
	}
}
