//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestOrdinaryPreCPPRejectsUnconditionalUnsupportedDirective(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.invalid/foreign-asm", Version: "v1.0.0", AsmFiles: []string{"docs/mips.s"}}
	sources := map[string]string{
		"go.mod":          "module example.invalid/foreign-asm\n\ngo 1.20\n",
		"docs/example.go": "package main\nfunc main() {}\n",
		"docs/mips.s":     "# Original foreign assembly example\n.text\nmain:\nli $v0, 4\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	targets := []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	plan, profiles, configurations, rejected, root, err := captureDiscoveryOrdinaryProfiles(ctx, candidate, download, targets, t.TempDir(), os.Environ())
	if err != nil {
		t.Fatalf("actual same-source Go assembler rejection blocked before CPP: %v", err)
	}
	if len(configurations) != 0 || len(rejected) != len(targets) {
		t.Fatalf("foreign-source scopes became translation or disappeared: configurations=%v rejected=%v", configurations, rejected)
	}
	for _, item := range rejected {
		if item.Kind != nativeLayoutGoAssemblerTarget || item.ProfileID == "" || len(item.Targets) != 1 ||
			!equalDiscoveryStrings(item.AsmFiles, candidate.AsmFiles) || captureDiscoverySourceDiagnostic(item.Reason) == nil {
			t.Fatalf("rejection lacks its exact original file/target/profile/diagnostic: %+v", item)
		}
	}
	inventory := &discoveryFeatureInventory{}
	refs, err := registerDiscoveryFeatureProfiles(inventory, profiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusNotApplicable,
		DiscoveredAsmFiles: candidate.AsmFiles, OrdinarySelectionPlan: plan,
		FeatureProfiles: refs, SourceNotApplicableItems: rejected, featureInventory: inventory,
	}
	if err := validateOrdinaryProfileResult(result, targets, plan.GoVersion); err != nil {
		t.Fatalf("complete actual original-source rejection readback: %v", err)
	}
	compact := result
	compact.sourceDiagnosticsCompacted = true
	compact.SourceNotApplicableItems = append([]discoverySourceNotApplicableItem(nil), rejected...)
	for index := range compact.SourceNotApplicableItems {
		item := &compact.SourceNotApplicableItems[index]
		item.Diagnostic = captureDiscoverySourceDiagnostic(item.Reason)
		item.Reason = discoverySourceSkipReason(item.Kind)
	}
	if err := validateOrdinaryProfileResult(compact, targets, plan.GoVersion); err != nil {
		t.Fatalf("compact progress/ledger diagnostic readback lost exact scopes: %v", err)
	}
	compact.SourceNotApplicableItems[0].Diagnostic = captureDiscoverySourceDiagnostic("docs/mips.s:2: another source error")
	if err := validateOrdinaryProfileResult(compact, targets, plan.GoVersion); err == nil {
		t.Fatal("compact reader accepted an unrelated diagnostic witness")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*discoveryCorpusResult){
		"missing all proofs": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.PreCPPRejections = nil },
		"missing selected target": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.PreCPPRejections = r.OrdinarySelectionPlan.PreCPPRejections[1:]
		},
		"duplicate scope": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.PreCPPRejections = append(r.OrdinarySelectionPlan.PreCPPRejections, r.OrdinarySelectionPlan.PreCPPRejections[0])
		},
		"wrong original hash": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.PreCPPRejections[0].SHA256 = strings.Repeat("f", 64)
		},
		"wrong physical tool": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.PreCPPRejections[0].AsmToolSHA256 = strings.Repeat("f", 64)
		},
		"wrong position":        func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.PreCPPRejections[0].Line++ },
		"wrong directive":       func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.PreCPPRejections[0].Directive = "Elsewhere" },
		"missing source prefix": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.PreCPPRejections[0].ControlPrefix = "" },
		"conditional source prefix": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.PreCPPRejections[0].ControlPrefix = "#ifdef NEVER\n#Original example\n"
			r.OrdinarySelectionPlan.PreCPPRejections[0].Line = 2
			r.OrdinarySelectionPlan.PreCPPRejections[0].Reason = "docs/mips.s:2: unexpected token after '#': Original"
		},
		"allowed CPP control": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.PreCPPRejections[0].Directive = "include" },
		"foreign invocation file": func(r *discoveryCorpusResult) {
			p := &r.OrdinarySelectionPlan.PreCPPRejections[0]
			p.Invocation[len(p.Invocation)-1] = "module/other.s"
		},
		"fake main role": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.PreCPPRejections[0].Package.SourceRole = "main"
		},
		"wrong exact version": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.PreCPPRejections[0].Package.ModuleVersion = "v1.0.1"
		},
		"wrong selected source": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.PreCPPRejections[0].Package.GoFiles = nil },
		"wrong CPU macros": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.PreCPPRejections[0].Package.Macros.Defines = []string{"GOAMD64_v4"}
		},
		"missing diagnostic item": func(r *discoveryCorpusResult) { r.SourceNotApplicableItems = r.SourceNotApplicableItems[1:] },
		"excluded scope executed": func(r *discoveryCorpusResult) {
			p := r.OrdinarySelectionPlan.PreCPPRejections[0]
			r.BuildConfigurations = []discoveryBuildConfiguration{{ProfileID: p.ProfileID, Targets: []string{p.Target}, AsmFiles: []string{p.File}, BuildTags: p.BuildTags}}
		},
		"fake CPP object": func(r *discoveryCorpusResult) {
			r.FeatureConsumption = []*gotoolprofile.SelectionProof{{ProfileID: r.OrdinarySelectionPlan.PreCPPRejections[0].ProfileID}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed discoveryCorpusResult
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			changed.featureInventory = inventory
			mutate(&changed)
			if err := validateOrdinaryProfileResult(changed, targets, plan.GoVersion); err == nil {
				t.Fatal("forged pre-CPP scope/proof passed the strict reader")
			}
		})
	}
	if err := verifyDiscoveryOrdinaryCPP(plan, download.Dir, root, candidate); err != nil {
		t.Fatal(err)
	}
	plan.PreCPPRejections[0].ControlPrefix = "#Original forged original bytes\n"
	if err := verifyDiscoveryOrdinaryCPP(plan, download.Dir, root, candidate); err == nil {
		t.Fatal("forged prefix passed live binding to original source")
	}
	plan.PreCPPRejections[0].ControlPrefix = strings.SplitAfter(sources["docs/mips.s"], "\n")[0]
	writeTestFile(t, filepath.Join(download.Dir, "docs/mips.s"), "#Altered foreign example\n")
	if err := verifyDiscoveryOrdinaryCPP(plan, download.Dir, root, candidate); err == nil {
		t.Fatal("changed original directive/source escaped the whole original snapshot guard")
	}
}

func TestOrdinaryPreCPPRetainsEligibleSiblingCPUAndCustomTagScopes(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.invalid/mixed-cpp", Version: "v1.0.0", AsmFiles: []string{"mips.s", "probe_amd64.s", "extra_amd64.s"}}
	sources := map[string]string{
		"go.mod":        "module example.invalid/mixed-cpp\n\ngo 1.20\n",
		"probe.go":      "package mixed\nfunc Probe()\n",
		"extra.go":      "//go:build extra\n\npackage mixed\nfunc Extra()\n",
		"mips.s":        "#Original foreign example\n.text\n",
		"probe_amd64.s": "#ifdef GOAMD64_v3\nTEXT ·Probe(SB),$0-0\nRET\n#else\nTEXT ·Probe(SB),$0-0\nRET\n#endif\n",
		"extra_amd64.s": "//go:build extra\n\nTEXT ·Extra(SB),$0-0\nRET\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	plan, profiles, configurations, _, _, err := captureDiscoveryOrdinaryProfiles(ctx, candidate, download, []string{"linux/amd64"}, t.TempDir(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	_, eligible, err := replayOrdinarySelectionForProfiles(plan, candidate.AsmFiles, profiles)
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := validateDiscoveryPreCPPRejections(plan, profiles, eligible)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) < 2 || len(rejected) < 4 {
		t.Fatalf("CPU/custom-tag sibling scopes were not independently observed: profiles=%d rejected=%d", len(profiles), len(rejected))
	}
	keys, err := ordinaryProfileConfigurationKeys(configurations, preCPPRemainingScopes(eligible, rejected))
	if err != nil {
		t.Fatal(err)
	}
	for key := range eligible {
		if key.File == "mips.s" {
			if !rejected[key] || keys[key] {
				t.Fatal("rejected source lacks its exact scope or was compiled")
			}
		} else if !keys[key] || rejected[key] {
			t.Fatal("eligible sibling scope disappeared from the compile/CPP union")
		}
	}
	for _, unit := range plan.CPPInputs.Units {
		if unit.File == "mips.s" {
			t.Fatal("rejected foreign source became a registered CPP consumer")
		}
	}
	for _, proof := range plan.PreCPPRejections {
		if len(proof.BuildTags) != 0 {
			changed := *plan
			changed.PreCPPRejections = nil
			for _, retained := range plan.PreCPPRejections {
				if retained.scope() != proof.scope() {
					changed.PreCPPRejections = append(changed.PreCPPRejections, retained)
				}
			}
			if _, err := validateDiscoveryPreCPPRejections(&changed, profiles, eligible); err == nil {
				t.Fatal("missing custom-tag/CPU rejection proof was accepted")
			}
			return
		}
	}
	t.Fatal("no actual custom-tag rejection proof was captured")
}

func TestOrdinaryPreCPPDoesNotReinterpretConditionalOrUnboundInputs(t *testing.T) {
	for name, body := range map[string]string{
		"inactive unknown":          "#ifdef NEVER_DEFINED\n#Original foreign example\n#endif\nTEXT ·Probe(SB),4,$0-0\nRET\n",
		"missing generated include": "#include \"go_asm.h\"\n#Original foreign example\n",
		"missing module include":    "#include \"absent.h\"\n#Original foreign example\n",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := discoveryCandidate{Module: "example.invalid/unknown-cpp", Version: "v1.0.0", AsmFiles: []string{"probe.s"}}
			sources := map[string]string{"go.mod": "module example.invalid/unknown-cpp\n\ngo 1.20\n", "probe.go": "package probe\nfunc Probe()\n", "probe.s": body}
			download := fixtureProfileModuleDownload(t, candidate, sources)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			_, _, _, _, _, err := captureDiscoveryOrdinaryProfiles(ctx, candidate, download, []string{"linux/amd64"}, t.TempDir(), os.Environ())
			if err == nil {
				t.Fatal("Go-accepted or unbound original CPP became an unexplained source exclusion")
			}
		})
	}
}

func configurePreCPPFixtureProxy(t *testing.T, candidate discoveryCandidate, download moduleDownloadInfo, goMod string) {
	t.Helper()
	proxy := t.TempDir()
	versions := filepath.Join(proxy, candidate.Module, "@v")
	if err := os.MkdirAll(versions, 0755); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(download.Zip)
	if err != nil {
		t.Fatal(err)
	}
	for file, body := range map[string][]byte{
		"v1.0.0.mod":  []byte(goMod),
		"v1.0.0.info": []byte(`{"Version":"v1.0.0","Time":"2026-10-01T00:00:00Z"}`),
		"v1.0.0.zip":  archive,
	} {
		if err := os.WriteFile(filepath.Join(versions, file), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOPROXY", "file://"+proxy)
	t.Setenv("GOSUMDB", "off")
	cache := filepath.Join(t.TempDir(), "modules")
	t.Setenv("GOMODCACHE", cache)
	t.Cleanup(func() {
		// Go's extractor makes owned module directories read-only. Restore
		// directory permissions before testing's TempDir cleanup, not in any
		// borrowed cache or original source tree.
		if err := filepath.Walk(cache, func(file string, info os.FileInfo, err error) error {
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if info.IsDir() {
				return os.Chmod(file, 0700)
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
}
