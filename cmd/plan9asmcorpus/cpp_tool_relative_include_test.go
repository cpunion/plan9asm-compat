package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestCPPInputsCanonicalToolRelativeIncludeFiveArchitectures(t *testing.T) {
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			parts := strings.Split(target, "/")
			file := "pkg/native_" + parts[1] + ".s"
			_, root, archive := fixtureCPPInputsForTarget(t, target, map[string]string{
				file:          "#include \"../../src/runtime/go_tls.h\"\nTEXT ·Probe(SB),$0-0\nRET\n",
				"pkg/decl.go": "package fixture\nfunc Probe()\n",
			})
			candidate := discoveryCandidate{Module: "example.invalid/cpp-inputs", Version: "v1.0.0", AsmFiles: []string{file}}
			plan, err := captureOrdinarySelectionInputs(candidate, root, []string{target})
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyOrdinarySelectionZIP(plan, archive, candidate.Module, candidate.Version, ""); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("go", "tool", "asm", "-D", "GOOS_"+parts[0], "-D", "GOARCH_"+parts[1],
				"-I", filepath.Join(runtime.GOROOT(), "pkg/include"), "-o", filepath.Join(t.TempDir(), "go.o"), filepath.Join(root, filepath.FromSlash(file)))
			command.Dir = filepath.Join(root, "pkg")
			command.Env = append(os.Environ(), "GOOS="+parts[0], "GOARCH="+parts[1])
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("actual original Go tool-relative include: %v\n%s", err, out)
			}
			for _, deferred := range []bool{false, true} {
				inputs, err := captureDiscoveryCPPInputsMode(plan, root, runtime.GOROOT(), []string{file}, deferred)
				if err != nil {
					t.Errorf("canonical GOROOT fallback rejected (deferred=%t): %v", deferred, err)
					continue
				}
				if inputs.Units[0].Includes["module/"+file+"#0"] != "tool/src/runtime/go_tls.h" {
					t.Fatal("tool-relative include did not retain its canonical original origin")
				}
				if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(inputs)
				if err != nil {
					t.Fatal(err)
				}
				var replay discoveryCPPInputs
				if err := json.Unmarshal(data, &replay); err != nil {
					t.Fatal(err)
				}
				if err := validateDiscoveryCPPInputs(&replay, plan, []string{file}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCPPInputsToolFallbackRequiresExactAbsentPreferredSource(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		plan, root, archive := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
			"pkg/native_amd64.s": "#include \"../../src/runtime/go_tls.h\"\nTEXT ·Probe(SB),$0-0\nRET\n",
		})
		files := []string{"pkg/native_amd64.s"}
		inputs, err := captureDiscoveryCPPInputsMode(plan, root, runtime.GOROOT(), files, deferred)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := json.Marshal(inputs)
		if err != nil {
			t.Fatal(err)
		}
		for name, mutate := range map[string]func(*discoveryCPPInputs){
			"missing miss": func(p *discoveryCPPInputs) { p.Units[0].PackageSearchMisses = nil },
			"fake protocol": func(p *discoveryCPPInputs) {
				key := "module/pkg/native_amd64.s#0"
				miss := p.Units[0].PackageSearchMisses[key]
				miss.Protocol = "ENOENT"
				p.Units[0].PackageSearchMisses[key] = miss
			},
			"wrong origin": func(p *discoveryCPPInputs) {
				key := "module/pkg/native_amd64.s#0"
				miss := p.Units[0].PackageSearchMisses[key]
				miss.Source = "tool/src/runtime/go_tls.h"
				p.Units[0].PackageSearchMisses[key] = miss
			},
			"additional miss": func(p *discoveryCPPInputs) {
				p.Units[0].PackageSearchMisses["module/pkg/native_amd64.s#1"] = p.Units[0].PackageSearchMisses["module/pkg/native_amd64.s#0"]
			},
			"tool replacement": func(p *discoveryCPPInputs) {
				p.Units[0].Includes["module/pkg/native_amd64.s#0"] = "tool/pkg/include/textflag.h"
			},
		} {
			t.Run(name, func(t *testing.T) {
				var changed discoveryCPPInputs
				if err := json.Unmarshal(canonical, &changed); err != nil {
					t.Fatal(err)
				}
				mutate(&changed)
				if err := validateDiscoveryCPPInputs(&changed, plan, files); err == nil {
					t.Fatal("unbound fixed-search absence was accepted")
				}
			})
		}
		preferred := filepath.Join(root, "../src/runtime/go_tls.h")
		if err := os.MkdirAll(filepath.Dir(preferred), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(preferred, []byte("#define WRONG 1\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := verifyDiscoveryCPPInputsUnchanged(inputs, root, runtime.GOROOT()); err == nil {
			t.Fatal("late outside-module preferred header did not invalidate the source environment")
		}
		if _, err := captureDiscoveryCPPInputsMode(plan, root, runtime.GOROOT(), files, deferred); err == nil {
			t.Fatal("existing outside-module source was read or replaced by GOROOT fallback")
		}
		if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
			t.Fatal("unchanged archive witness unexpectedly changed: ", err)
		}
		if err := os.Remove(preferred); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCPPToolSearchCandidateFamilyRemainsBounded(t *testing.T) {
	for _, include := range []string{
		"../../src/runtime/go_tls.h", "./../../src/runtime/go_tls.h", "../../src/runtime/../runtime/go_tls.h",
	} {
		module, tool, err := gotoolprofile.CPPIncludeCandidates("pkg/native_amd64.s", include)
		if err != nil || module != "../src/runtime/go_tls.h" || tool != "src/runtime/go_tls.h" {
			t.Fatalf("canonical original fixed-search alias: %q %q %v", module, tool, err)
		}
	}
	for _, include := range []string{"../../../outside.h", "/tmp/outside.h", "..\\outside.h", "a\x00b"} {
		if _, _, err := gotoolprofile.CPPIncludeCandidates("pkg/native_amd64.s", include); err == nil {
			t.Fatalf("unknown or escaping include accepted: %q", include)
		}
	}
	toolRoot := t.TempDir()
	header := filepath.Join(toolRoot, "src/runtime/header.h")
	if err := os.MkdirAll(filepath.Dir(header), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing.h"), header); err != nil {
		t.Fatal(err)
	}
	if _, err := gotoolprofile.CPPRegularSource(toolRoot, "src/runtime/header.h"); err == nil {
		t.Fatal("redirected tool source became an authenticated header")
	}
}

func TestCPPToolLegacyPrefixFallbackRetainsMandatorySearchMiss(t *testing.T) {
	plan, root, archive := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		"pkg/native_amd64.s": "#include \"../../pkg/include/textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-0\nRET\n",
	})
	files := []string{"pkg/native_amd64.s"}
	inputs, err := captureDiscoveryDeferredCPPInputs(plan, root, runtime.GOROOT(), files)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
		t.Fatal(err)
	}
	if len(inputs.Units[0].PackageSearchMisses) != 1 {
		t.Fatal("legacy tool prefix erased the original outside-package search")
	}
	inputs.Units[0].PackageSearchMisses = nil
	if err := validateDiscoveryCPPInputs(inputs, plan, files); err == nil {
		t.Fatal("plan reader accepted deleting an outside-package miss with a legacy tool prefix")
	}
}
