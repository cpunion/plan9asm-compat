//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestOrdinaryFortranLoaderOriginalRoleAndStrictReplay(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.invalid/fortran-role", Version: "v1.0.0", AsmFiles: []string{"docs/probe.s", "docs/foreign.s"}}
	sources := map[string]string{
		"go.mod":               "module example.invalid/fortran-role\n\ngo 1.20\n",
		"docs/probe.go":        "package docs\nfunc Probe()\n",
		"docs/custom.go":       "//go:build custom\n\npackage docs\n",
		"docs/probe.s":         "#include \"textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-0\nRET\n",
		"docs/foreign.s":       "#Original foreign example\n.text\n",
		"docs/a.f":             "PROGRAM original\nEND\n",
		"docs/b.F":             "//go:build custom\n\nPROGRAM custom\nEND\n",
		"docs/c.for":           "// +build never\n\nPROGRAM never\nEND\n",
		"docs/d_linux.f90":     "PROGRAM linux\nEND\n",
		"docs/_ignored.f":      "PROGRAM hidden\nEND\n",
		"docs/.ignored.F":      "PROGRAM hidden\nEND\n",
		"docs/not-fortran.f95": "not a Go FF resource\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	targets := []string{"darwin/arm64", "linux/amd64"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	workDir := t.TempDir()
	plan, profiles, configs, rejected, root, err := captureDiscoveryOrdinaryProfiles(ctx, candidate, download, targets, workDir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) == 0 || len(rejected) == 0 || len(plan.PreCPPRejections) == 0 {
		t.Fatal("fixture lost independent pre-CPP exclusion or eligible sibling scopes")
	}
	byProfile := make(map[string]discoveryFeatureProfile)
	for _, profile := range profiles {
		byProfile[profile.ID] = profile
	}
	for _, config := range configs {
		profile := byProfile[config.ProfileID]
		groups := discoveryPackageGroupsForModule(discoveryCandidate{Module: candidate.Module, Version: candidate.Version, AsmFiles: config.AsmFiles}, candidate.Module)
		if len(groups) != 1 {
			t.Fatal("fixture requires exactly one original package")
		}
		group := groups[0]
		failure := runDiscoveryGoBuild(ctx, workDir, os.Environ(), config.Targets[0], config.BuildTags, group.Pattern)
		if failure == nil || !isPotentialFortranLoaderFailure(group.Pattern, failure) {
			t.Fatalf("original Go did not reproduce its no-position FF rejection: %v", failure)
		}
		if _, err := runDiscoveryPackageChecks(groups, func([]string) error { return failure }); err == nil {
			t.Fatal("generic source diagnostics incorrectly accepted a no-position loader refusal")
		}
		proof, err := captureFortranLoaderRejection(ctx, plan, profile, download.Dir, workDir, root, os.Environ(), group, config.BuildTags, failure)
		if err != nil {
			t.Fatalf("typed original loader evidence: %v", err)
		}
		plan.FortranRejections = append(plan.FortranRejections, proof)
		rejected = append(rejected, discoverySourceNotApplicableItem{
			ProfileID: proof.ProfileID, BuildTags: proof.BuildTags, AsmFiles: proof.AsmFiles,
			Targets: []string{proof.Target}, Kind: discoverySourceNotApplicableFortranLoader, Reason: proof.Stderr,
		})
	}
	inventory := newDiscoveryFeatureInventory()
	refs, err := registerDiscoveryFeatureProfiles(inventory, profiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusNotApplicable,
		DiscoveredAsmFiles: candidate.AsmFiles, OrdinarySelectionPlan: plan, FeatureProfiles: refs,
		SourceNotApplicableItems: rejected, featureInventory: inventory}
	if err := validateOrdinaryProfileResult(result, targets, plan.GoVersion); err != nil {
		t.Fatalf("complete original-role/CPP/loader replay: %v", err)
	}
	if err := validateOrdinarySelectionResult(result, targets, plan.GoVersion); err == nil {
		t.Fatal("legacy non-profile report reader accepted a current loader proof")
	}
	compact := result
	compact.sourceDiagnosticsCompacted = true
	compact.SourceNotApplicableItems = append([]discoverySourceNotApplicableItem(nil), result.SourceNotApplicableItems...)
	for index := range compact.SourceNotApplicableItems {
		item := &compact.SourceNotApplicableItems[index]
		if discoverySourceRejectionRequiresDiagnostic(item.Kind) {
			item.Diagnostic = captureDiscoverySourceDiagnostic(item.Reason)
		}
		item.Reason = discoverySourceSkipReason(item.Kind)
	}
	if err := validateOrdinaryProfileResult(compact, targets, plan.GoVersion); err != nil {
		t.Fatalf("compact progress/ledger replay: %v", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*discoveryCorpusResult){
		"deleted whole directory": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.Directories = nil },
		"deleted FF resource from directory": func(r *discoveryCorpusResult) {
			for index := range r.OrdinarySelectionPlan.Directories {
				dir := &r.OrdinarySelectionPlan.Directories[index]
				if dir.Directory == "docs" {
					for entry, original := range dir.Entries {
						if original.Name == "_ignored.f" {
							dir.Entries = append(dir.Entries[:entry], dir.Entries[entry+1:]...)
							return
						}
					}
				}
			}
		},
		"missing original directory digest": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.FortranRejections[0].DirectorySHA256 = "" },
		"missing profile references":        func(r *discoveryCorpusResult) { r.FeatureProfiles = nil },
		"legacy source protocol":            func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.Protocol = ordinarySelectionProtocol },
		"missing protocol":                  func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.FortranRejections[0].Protocol = "" },
		"missing all proofs":                func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.FortranRejections = nil },
		"missing sibling profile": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections = r.OrdinarySelectionPlan.FortranRejections[1:]
		},
		"duplicate proof": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections = append(r.OrdinarySelectionPlan.FortranRejections, r.OrdinarySelectionPlan.FortranRejections[0])
		},
		"missing complete FF inventory": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].Inputs = r.OrdinarySelectionPlan.FortranRejections[0].Inputs[1:]
		},
		"altered FF source hash": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].Inputs[0].SHA256 = strings.Repeat("f", 64)
		},
		"changed FF constraint": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].Inputs[0].Header = "//go:build never\n\n"
		},
		"wrong FF role": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].FFiles = []string{"not-fortran.f95"}
		},
		"CGO1": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.FortranRejections[0].CGOEnabled = "1" },
		"UsesCgo": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].CgoFiles = []string{"cgo.go"}
		},
		"UsesSwig": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].SwigFiles = []string{"native.swig"}
		},
		"UsesSwigCXX": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].SwigCXXFiles = []string{"native.swigcxx"}
		},
		"dependency error": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].DepsErrors = []string{"unavailable module"}
		},
		"missing actual role": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].Package = gotoolprofile.PackageProof{}
		},
		"foreign source version": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].Package.SourceVersion = "v1.0.1"
		},
		"wrong package name":        func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.FortranRejections[0].PackageName = "other" },
		"foreign package directory": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.FortranRejections[0].Directory = "elsewhere" },
		"wrong Go rules": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].Rules.SourceSHA256["src/go/build/build.go"] = strings.Repeat("f", 64)
		},
		"wrong physical driver": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].DriverSHA256 = strings.Repeat("f", 64)
		},
		"wrong target": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.FortranRejections[0].Target = "windows/arm64" },
		"wrong tags": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].BuildTags = []string{"foreign"}
		},
		"foreign invocation": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].Invocation = []string{"list", "-e", "example.invalid/other"}
		},
		"mixed raw diagnostic": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].Stderr += "other.go:3: undefined: x\n"
		},
		"wrong loader import stack": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].LoaderError.ImportStack = []string{"other.invalid"}
		},
		"missing scoped item": func(r *discoveryCorpusResult) {
			r.SourceNotApplicableItems = r.SourceNotApplicableItems[:len(r.SourceNotApplicableItems)-1]
		},
		"wrong typed item": func(r *discoveryCorpusResult) {
			r.SourceNotApplicableItems[len(r.SourceNotApplicableItems)-1].Kind = discoverySourceNotApplicableGoBuild
		},
		"swallow preCPP": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.FortranRejections[0].AsmFiles = append(r.OrdinarySelectionPlan.FortranRejections[0].AsmFiles, "docs/foreign.s")
		},
		"wrong original raw item": func(r *discoveryCorpusResult) {
			r.SourceNotApplicableItems[len(r.SourceNotApplicableItems)-1].Reason += "extra error\n"
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
				t.Fatal("forged or incomplete original Fortran loader exclusion passed")
			}
		})
	}
	for _, kind := range []string{"missing_module_header", "unknown_accepted_cpp"} {
		t.Run(kind, func(t *testing.T) {
			original := sources["docs/probe.s"]
			if kind == "missing_module_header" {
				sources["docs/probe.s"] = "#include \"absent.h\"\nTEXT ·Probe(SB),$0-0\nRET\n"
			} else {
				sources["docs/probe.s"] = "#define UNDEFINED_FUNCTION(x) x\n#UnknownLater rejected-or-accepted control\nTEXT ·Probe(SB),$0-0\nRET\n"
			}
			changedDownload := fixtureProfileModuleDownload(t, candidate, sources)
			configurePreCPPFixtureProxy(t, candidate, changedDownload, sources["go.mod"])
			changedWork := t.TempDir()
			changedPlan, changedProfiles, changedConfigs, _, changedRoot, err := captureDiscoveryOrdinaryProfiles(ctx, candidate, changedDownload, targets, changedWork, os.Environ())
			if err == nil {
				if len(changedConfigs) == 0 {
					t.Fatal("fixture lost the required deferred CPP scope")
				}
				config := changedConfigs[0]
				var profile discoveryFeatureProfile
				for _, actual := range changedProfiles {
					if actual.ID == config.ProfileID {
						profile = actual
					}
				}
				group := discoveryPackageGroupsForModule(discoveryCandidate{Module: candidate.Module, Version: candidate.Version, AsmFiles: config.AsmFiles}, candidate.Module)[0]
				failure := runDiscoveryGoBuild(ctx, changedWork, os.Environ(), config.Targets[0], config.BuildTags, group.Pattern)
				_, err = captureFortranLoaderRejection(ctx, changedPlan, profile, changedDownload.Dir, changedWork, changedRoot, os.Environ(), group, config.BuildTags, failure)
				if err == nil {
					t.Fatal("Fortran presence hid an unbound/unknown original CPP graph")
				}
			}
			sources["docs/probe.s"] = original
		})
	}
	if err := verifyDiscoveryOrdinaryCPP(plan, download.Dir, root, candidate); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(download.Dir, "docs/a.f"), "PROGRAM changed\nEND\n")
	var changed *discoverySourceProofError
	if err := verifyDiscoveryOrdinaryCPP(plan, download.Dir, root, candidate); !errors.As(err, &changed) {
		t.Fatalf("original FF mutation did not retain the source-proof hard failure: %v", err)
	}
}

func TestOrdinaryFortranProducerKeepsEligiblePackageObjects(t *testing.T) {
	compilerEnv := os.Environ()
	candidate := discoveryCandidate{Module: "example.invalid/fortran-mixed", Version: "v1.0.0",
		AsmFiles: []string{"bad/probe_amd64.s", "good/probe_amd64.s"}}
	sources := map[string]string{
		"go.mod":             "module example.invalid/fortran-mixed\n\ngo 1.20\n",
		"bad/probe.go":       "package bad\nfunc Probe()\n",
		"bad/probe_amd64.s":  "#include \"textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-0\nRET\n",
		"bad/original.f":     "PROGRAM original\nEND\n",
		"good/probe.go":      "package good\nfunc Probe() uint64\n",
		"good/probe_amd64.s": "#include \"textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-8\nMOVQ $7,ret+0(FP)\nRET\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "plan9asmll")
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", binary, ".")
	command.Dir, command.Env = filepath.Join(root, "cmd", "plan9asmll"), compilerEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build owned actual translator: %v\n%s", err, output)
	}
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal(err)
	}
	matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
		RepoRoot: root, Translator: binary, LLC: llc, Targets: []string{"linux/amd64"}, CandidateTimeout: 2 * time.Minute,
	}, candidate, filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	if matrix.Success != 1 || matrix.NotApplicable != 0 || len(matrix.FeatureConsumption) != 1 || len(configs) != 1 ||
		len(matrix.OrdinarySelectionPlan.FortranRejections) != 1 || len(matrix.SourceNotApplicableItems) != 1 {
		t.Fatalf("source rejection erased objects or manufactured a translation: %#v", matrix)
	}
	if !equalDiscoveryStrings(configs[0].AsmFiles, []string{"good/probe_amd64.s"}) ||
		!equalDiscoveryStrings(matrix.SourceNotApplicableItems[0].AsmFiles, []string{"bad/probe_amd64.s"}) {
		t.Fatal("loader proof crossed original package boundaries")
	}
	inventory := newDiscoveryFeatureInventory()
	refs, err := registerDiscoveryFeatureProfiles(inventory, matrix.FeatureProfiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: discoveryConfigurationAsmFiles(configs), BuildConfigurations: configs,
		Translations: matrix.Success, OrdinarySelectionPlan: matrix.OrdinarySelectionPlan, FeatureProfiles: refs,
		FeatureConsumption: matrix.FeatureConsumption, SourceNotApplicableItems: matrix.SourceNotApplicableItems, featureInventory: inventory}
	if err := validateOrdinaryProfileResult(result, []string{"linux/amd64"}, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
		t.Fatalf("actual package source N/A plus LLVM object readback: %v", err)
	}
}
