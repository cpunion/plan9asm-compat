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

func TestOrdinaryAlwaysDocumentationPrecedesInvalidCPP(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.invalid/documentation-role", Version: "v1.0.0", AsmFiles: []string{"docs/foreign.s"}}
	sources := map[string]string{
		"go.mod":         "module example.invalid/documentation-role\n\ngo 1.20\n",
		"docs/doc.go":    "package documentation\n",
		"docs/foreign.s": "#ifdef BOOT\n#endif BOOT\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// Match the production stage ordering: the authenticated original ZIP is
	// already downloaded before a role query, not fetched by go list itself.
	if _, _, err := runDiscoveryMachineCommand(ctx, t.TempDir(), os.Environ(), "go", "mod", "download", "-json", candidate.exactKey()); err != nil {
		t.Fatal(err)
	}
	plan, _, configs, rejected, _, err := captureDiscoveryOrdinaryProfiles(ctx, candidate, download,
		[]string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"}, t.TempDir(), os.Environ())
	if err != nil {
		t.Fatalf("actual Go documentation role must precede meaningless CPP registration: %v", err)
	}
	if len(configs) != 0 || len(rejected) != 5 || plan.CPPInputs != nil {
		t.Fatalf("documentation sources cannot be translated or disappear: configs=%v exclusions=%v", configs, rejected)
	}
}

func TestOrdinaryDocumentationActualDefaultTargetsAndStrictReaders(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.invalid/documentation-all-scopes", Version: "v1.0.0",
		Architectures: []string{"386", "amd64", "arm", "arm64", "wasm"},
		AsmFiles:      []string{"docs/foreign.s", "docs/custom.s", "docs/feature_amd64.s"}}
	candidate.AsmFiles = uniqueSortedDiscoveryStrings(candidate.AsmFiles)
	sources := map[string]string{
		"go.mod":                "module example.invalid/documentation-all-scopes\n\ngo 1.20\n",
		"docs/doc.go":           "package documentation\n",
		"docs/doc_amd64.go":     "//go:build amd64.v3\n\npackage documentation\n",
		"docs/custom.go":        "//go:build custom\n\npackage documentation\n",
		"docs/ordinary_test.go": "//go:build never\n\npackage docs\n",
		"docs/doc_test.go":      "package documentation\n",
		"docs/_hidden.go":       "package hidden\n",
		"docs/.hidden.go":       "package hidden\n",
		"docs/foreign.s":        "#ifdef BOOT\n#endif BOOT\n",
		"docs/custom.s":         "//go:build custom\n\n#Unknown custom source\n",
		"docs/feature_amd64.s":  "//go:build amd64.v3\n\n#Unknown feature source\n",
		"docs/empty.s":          "",
		"docs/lex.c":            "original foreign C source\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	targets := []string{"darwin/amd64", "darwin/arm64", "linux/386", "linux/amd64", "linux/arm", "linux/arm64",
		"windows/386", "windows/amd64", "windows/arm64", "js/wasm", "wasip1/wasm"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, _, err := runDiscoveryMachineCommand(ctx, t.TempDir(), os.Environ(), "go", "mod", "download", "-json", candidate.exactKey()); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	plan, profiles, configs, exclusions, root, err := captureDiscoveryOrdinaryProfiles(ctx, candidate, download, targets, work, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 0 || plan.CPPInputs != nil || len(plan.PreCPPRejections) != 0 || len(plan.DocumentationPackages) <= len(targets) {
		t.Fatalf("role lost feature/custom-tag scopes or became object coverage: configs=%v packages=%d", configs, len(plan.DocumentationPackages))
	}
	var custom, feature bool
	byProfile := make(map[string]discoveryFeatureProfile)
	for _, profile := range profiles {
		byProfile[profile.ID] = profile
		feature = feature || profile.Observed.Environment["GOAMD64"] == "v3"
	}
	for _, proof := range plan.DocumentationPackages {
		custom = custom || containsTargetFeature(proof.BuildTags, "custom")
		if !containsTargetFeature(proof.Package.SFiles, "docs/empty.s") || proof.LoaderErrorKind != "go/build.NoGoError" || len(proof.Package.GoFiles) != 0 {
			t.Fatalf("actual Go selection/typed role disappeared: %+v", proof)
		}
	}
	if !custom || !feature {
		t.Fatalf("actual source-required custom/profile queries absent: custom=%v feature=%v", custom, feature)
	}
	// Stock Go's non-indexed driver path must produce the same actual role,
	// not just an in-process guess about the module-index branch.
	first := plan.DocumentationPackages[0]
	_, fallback, err := captureRejectedPackageMetadata(ctx, plan, byProfile[first.ProfileID], work,
		replaceEnv(os.Environ(), map[string]string{"GODEBUG": "goindex=0"}),
		discoveryPreCPPRejection{File: first.AsmFiles[0], BuildTags: first.BuildTags})
	if err != nil || fallback.Error == nil || !strings.HasPrefix(fallback.Error.Err, "build constraints exclude all Go files in ") ||
		len(fallback.GoFiles)+len(fallback.CgoFiles)+len(fallback.DepsErrors) != 0 || fallback.selectionStderr != "" {
		t.Fatalf("actual stock Go non-indexed documentation rule differs: %+v %v", fallback, err)
	}
	inventory := newDiscoveryFeatureInventory()
	refs, err := registerDiscoveryFeatureProfiles(inventory, profiles)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusNotApplicable,
		DiscoveredAsmFiles: candidate.AsmFiles, OrdinarySelectionPlan: plan, FeatureProfiles: refs,
		SourceNotApplicableItems: exclusions, featureInventory: inventory,
		NotApplicableReason: ordinarySelectionReason(plan, exclusions, nil)}
	if err := validateOrdinaryProfileResult(result, targets, plan.GoVersion); err != nil {
		t.Fatal(err)
	}
	if err := validateOrdinarySelectionResult(result, targets, plan.GoVersion); err == nil {
		t.Fatal("historical reader accepted current documentation witness")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*discoveryCorpusResult){
		"delete protocol": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.DocumentationSourceProtocol = "" },
		"delete all new fields": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationSourceProtocol = ""
			r.OrdinarySelectionPlan.DocumentationPackages = nil
			r.OrdinarySelectionPlan.DocumentationRules = nil
		},
		"unknown protocol":        func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.DocumentationSourceProtocol = "unregistered" },
		"delete all scope proofs": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.DocumentationPackages = nil },
		"truncate required scopes": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages = r.OrdinarySelectionPlan.DocumentationPackages[1:]
		},
		"duplicate scope": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages = append(r.OrdinarySelectionPlan.DocumentationPackages, r.OrdinarySelectionPlan.DocumentationPackages[0])
		},
		"missing original Go source": func(r *discoveryCorpusResult) {
			for index, source := range r.OrdinarySelectionPlan.Sources {
				if source.File == "docs/doc.go" {
					r.OrdinarySelectionPlan.Sources = append(r.OrdinarySelectionPlan.Sources[:index], r.OrdinarySelectionPlan.Sources[index+1:]...)
					return
				}
			}
		},
		"relabel ordinary source": func(r *discoveryCorpusResult) {
			for index := range r.OrdinarySelectionPlan.Sources {
				source := &r.OrdinarySelectionPlan.Sources[index]
				if source.File == "docs/doc.go" {
					source.Header = "package ordinary\n"
					source.HeaderSHA256 = discoveryFeatureBytesSHA256([]byte(source.Header))
				}
			}
		},
		"wrong directory inventory": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages[0].DirectorySHA256 = strings.Repeat("f", 64)
		},
		"wrong source module identity": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages[0].Package.SourceVersion = "v1.0.1"
		},
		"fake ordinary Go role": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages[0].Package.GoFiles = []string{"docs/doc.go"}
		},
		"missing ignored file": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.DocumentationPackages[0].IgnoredGoFiles = nil },
		"delete source SHA": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages[0].Package.SourceSHA256 = nil
		},
		"drop real empty SFiles sibling": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.DocumentationPackages[0].Package.SFiles = nil },
		"wrong profile": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages[0].ProfileID = strings.Repeat("f", 64)
		},
		"wrong target": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages[0].Target = "unknown/arm64"
		},
		"wrong tags": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages[0].BuildTags = []string{"wrong"}
		},
		"wrong physical driver": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages[0].DriverSHA256 = strings.Repeat("f", 64)
		},
		"delete rule sources": func(r *discoveryCorpusResult) { r.OrdinarySelectionPlan.DocumentationRules = nil },
		"wrong module-index source": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationRules.SourceSHA256["src/cmd/go/internal/modindex/read.go"] = strings.Repeat("f", 64)
		},
		"wrong fallback source": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationRules.SourceSHA256["src/go/build/build.go"] = strings.Repeat("f", 64)
		},
		"wrong Go VERSION": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationRules.VersionSHA256 = strings.Repeat("f", 64)
		},
		"wrong invocation": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages[0].Invocation[0] = "build"
		},
		"untyped failure": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages[0].LoaderErrorKind = "syntax error"
		},
		"network failure": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages[0].LoaderError.Err = "module download timeout"
		},
		"source parser failure": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages[0].LoaderError.Pos = "doc.go:3:1"
		},
		"wrong import stack": func(r *discoveryCorpusResult) {
			r.OrdinarySelectionPlan.DocumentationPackages[0].LoaderError.ImportStack = []string{"foreign"}
		},
		"drop source exclusion": func(r *discoveryCorpusResult) { r.SourceNotApplicableItems = r.SourceNotApplicableItems[1:] },
		"relabel old no-Go role": func(r *discoveryCorpusResult) {
			r.SourceNotApplicableItems[0].Kind = discoverySourceNotApplicableNoGoPackage
		},
		"claim an LLVM object": func(r *discoveryCorpusResult) {
			p := r.OrdinarySelectionPlan.DocumentationPackages[0]
			r.Translations = 1
			r.BuildConfigurations = []discoveryBuildConfiguration{{ProfileID: p.ProfileID, Targets: []string{p.Target}, AsmFiles: p.AsmFiles, BuildTags: p.BuildTags}}
		},
		"claim compiler consumption": func(r *discoveryCorpusResult) {
			r.FeatureConsumption = []*gotoolprofile.SelectionProof{{ProfileID: first.ProfileID}}
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
				t.Fatal("forged documentation scope/source/role proof passed the independent reader")
			}
		})
	}
	if err := verifyDiscoveryOrdinaryCPP(plan, download.Dir, root, candidate); err != nil {
		t.Fatal(err)
	}
	assertDocumentationProgressReadback(t, candidate, targets, result, inventory)
	writeTestFile(t, filepath.Join(download.Dir, "docs/foreign.s"), "#Altered original source\n")
	if err := verifyDiscoveryOrdinaryCPP(plan, download.Dir, root, candidate); err == nil {
		t.Fatal("source-only role dropped the whole original assembly byte guard")
	}
}

func TestOrdinaryDocumentationDoesNotHideActualTestOnlyPackage(t *testing.T) {
	candidate := discoveryCandidate{Module: "example.invalid/documentation-test-only", Version: "v1.0.0", AsmFiles: []string{"foreign.s"}}
	sources := map[string]string{
		"go.mod":       "module example.invalid/documentation-test-only\n\ngo 1.20\n",
		"doc.go":       "package documentation\n",
		"decl_test.go": "package ordinary\nfunc Probe()\n",
		"foreign.s":    "#ifdef BOOT\n#endif BOOT\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, _, err := runDiscoveryMachineCommand(ctx, t.TempDir(), os.Environ(), "go", "mod", "download", "-json", candidate.exactKey()); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err := captureDiscoveryOrdinaryProfiles(ctx, candidate, download, []string{"linux/amd64"}, t.TempDir(), os.Environ()); err == nil || !strings.Contains(err.Error(), "only stock Go NoGoError") {
		t.Fatalf("actual Go test-only package became documentation N/A: %v", err)
	}
}

func TestOrdinaryDocumentationRejectsBadOrMixedOriginalGoSources(t *testing.T) {
	for name, changed := range map[string]map[string]string{
		"invalid import syntax":               {"doc.go": "package documentation\nimport (!)\n"},
		"invalid package clause sibling":      {"bad.go": "package !\n"},
		"ordinary source even with never tag": {"ordinary.go": "//go:build never\n\npackage ordinary\n"},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := discoveryCandidate{Module: "example.invalid/documentation-negative", Version: "v1.0.0", AsmFiles: []string{"foreign.s"}}
			sources := map[string]string{
				"go.mod":    "module example.invalid/documentation-negative\n\ngo 1.20\n",
				"doc.go":    "package documentation\n",
				"foreign.s": "#ifdef BOOT\n#endif BOOT\n",
			}
			for file, contents := range changed {
				sources[file] = contents
			}
			download := fixtureProfileModuleDownload(t, candidate, sources)
			configurePreCPPFixtureProxy(t, candidate, download, sources["go.mod"])
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if _, _, err := runDiscoveryMachineCommand(ctx, t.TempDir(), os.Environ(), "go", "mod", "download", "-json", candidate.exactKey()); err != nil {
				t.Fatal(err)
			}
			if _, _, _, _, _, err := captureDiscoveryOrdinaryProfiles(ctx, candidate, download, []string{"linux/amd64"}, t.TempDir(), os.Environ()); err == nil {
				t.Fatal("bad/mixed source became documentation exclusion instead of retaining its original failure")
			}
		})
	}
}

func assertDocumentationProgressReadback(t *testing.T, candidate discoveryCandidate, targets []string, result discoveryCorpusResult, inventory *discoveryFeatureInventory) {
	t.Helper()
	ledger := filepath.Join(t.TempDir(), "ledger.jsonl")
	record, err := json.Marshal(discoveryRecord{Kind: "matched", Module: candidate.Module, Version: candidate.Version,
		Architectures: candidate.Architectures, AsmFiles: candidate.AsmFiles})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, ledger, string(record)+"\n")
	provenance := fixtureDiscoveryProvenance(t, ledger)
	report := discoveryCorpusReport{SchemaVersion: discoveryReportSchema, Provenance: provenance, Targets: targets,
		CandidateTotal: 1, EligibleCandidates: 1, Selected: 1, NotApplicable: 1, ShardCount: 1,
		Results: []discoveryCorpusResult{result}, FeatureInventory: inventory}
	if err := validateDiscoveryCorpusAccounting(report); err != nil {
		t.Fatal(err)
	}
	reports := t.TempDir()
	file := filepath.Join(reports, "shard-0.json")
	if err := writeDiscoveryCorpusReport(file, report); err != nil {
		t.Fatal(err)
	}
	progress, err := collectDiscoveryProgress(ledger, reports, targets, provenance.Source, 1)
	if err != nil || progress.Translations != 0 || progress.Passed != 0 || progress.NotApplicable != 1 {
		t.Fatalf("documentation source exclusion became object/library pass: %+v %v", progress, err)
	}
	if err := validateAssemblyLedgerProgress(progress); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*discoveryCorpusReport){
		"delete current stamp": func(r *discoveryCorpusReport) { r.Provenance.DocumentationSourceProtocol = "" },
		"delete whole new mechanism": func(r *discoveryCorpusReport) {
			r.Provenance.DocumentationSourceProtocol = ""
			r.Results[0].OrdinarySelectionPlan.DocumentationSourceProtocol = ""
			r.Results[0].OrdinarySelectionPlan.DocumentationPackages = nil
			r.Results[0].OrdinarySelectionPlan.DocumentationRules = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed, err := readDiscoveryCorpusReport(file)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := writeDiscoveryCorpusReport(file, changed); err != nil {
				t.Fatal(err)
			}
			if _, err := collectDiscoveryProgress(ledger, reports, targets, provenance.Source, 1); err == nil {
				t.Fatal("deleted documentation protocol downgraded into historical progress")
			}
			if err := writeDiscoveryCorpusReport(file, report); err != nil {
				t.Fatal(err)
			}
		})
	}
}
