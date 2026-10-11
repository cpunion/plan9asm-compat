//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// A tag-selected Go body can be invalid on one architecture even though its
// assembly and complete generated-header properties are valid. Planning is
// only an optimization: this scope still needs the normal final Go check,
// and healthy target/tag siblings must remain eligible for their own objects.
func TestCPPHeaderPlanningDefersExactOriginalGoSourceRejection(t *testing.T) {
	compilerEnv := os.Environ()
	candidate := discoveryCandidate{
		Module: "example.invalid/header-rejection", Version: "v1.0.0",
		AsmFiles: []string{"probe_386.s", "probe_amd64.s"},
	}
	sources := map[string]string{
		"go.mod":        "module " + candidate.Module + "\ngo 1.20\n",
		"probe.go":      "package witness\nconst Answer=7\nfunc Probe()\n",
		"poison.go":     "//go:build durable && 386\n\npackage witness\nfunc unused() { _ = missingArchitectureValue }\n",
		"probe_386.s":   "#include \"go_asm.h\"\nTEXT ·Probe(SB),4,$0-0\nRET\n",
		"probe_amd64.s": "#include \"go_asm.h\"\nTEXT ·Probe(SB),4,$0-0\nRET\n",
	}
	seed := fixtureProfileModuleDownload(t, candidate, sources)
	installGeneratedFixtureProxy(t, candidate, seed, sources["go.mod"])
	cacheRoot := os.Getenv("GOMODCACHE")
	t.Cleanup(func() {
		if err := filepath.Walk(cacheRoot, func(file string, info os.FileInfo, err error) error {
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	translator := filepath.Join(t.TempDir(), "plan9asmll")
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", translator, ".")
	command.Dir, command.Env = filepath.Join(root, "cmd/plan9asmll"), compilerEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build first-party metadata query consumer: %v\n%s", err, output)
	}
	goBinary, err := resolveDiscoveryExecutable("go")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	data, _, err := runDiscoveryMachineCommand(ctx, dir, os.Environ(), goBinary, "mod", "download", "-json", candidate.exactKey())
	if err != nil {
		t.Fatal(err)
	}
	var download moduleDownloadInfo
	if err := json.Unmarshal(data, &download); err != nil || download.Dir == "" {
		t.Fatalf("actual first-party proxy download: %s; %v", data, err)
	}
	plan, err := captureOrdinarySelectionInputs(candidate, download.Dir, []string{"linux/386", "linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	plan.ModuleSum = download.Sum
	plan.ZipSHA256, err = discoveryFeatureFileSHA256(download.Zip)
	if err != nil {
		t.Fatal(err)
	}
	var events phaseFixtureWriter
	journal := newPhaseFixtureJournal(t, &events)
	t.Cleanup(func() {
		if err := journal.close(nil); err != nil {
			t.Error(err)
		}
	})
	if err := installDiscoveryHeaderPlanning(ctx, plan, candidate, download, dir, runtime.GOROOT(), goBinary,
		t.TempDir(), translator, os.Environ(), &discoveryFeatureObservationCache{}, journal); err != nil {
		t.Fatal(err)
	}
	badRequest := discoveryFeatureProfileRequest{Target: "linux/386", Baseline: true}
	header, err := plan.headerPlanningCapture(badRequest, "probe_386.s", []string{"durable"})
	var unsupported *discoveryHeaderPlanningUnsupported
	if header != nil || !errors.As(err, &unsupported) {
		t.Fatalf("original target/tag Go rejection must defer only planning, not abort the whole candidate: %v", err)
	}
	if plan.HeaderPlanning != nil || len(plan.headerPlanningInventory.Observations) != 0 {
		t.Fatal("failed planning query manufactured a successful header/profile witness")
	}
	for repeat := 0; repeat < 3; repeat++ {
		if _, err := plan.headerPlanningCapture(badRequest, "probe_386.s", []string{"durable"}); !errors.As(err, &unsupported) {
			t.Fatalf("repeated exact planning rejection %d changed: %v", repeat, err)
		}
	}
	for _, scope := range []struct {
		target, assembly string
		tags             []string
		bad              bool
	}{
		{"linux/386", "probe_386.s", []string{"durable"}, true},
		{"linux/386", "probe_386.s", nil, false},
		{"linux/amd64", "probe_amd64.s", []string{"durable"}, false},
	} {
		t.Run(scope.target+"/"+strings.Join(scope.tags, ","), func(t *testing.T) {
			groups := []discoveryPackageGroup{{Pattern: candidate.Module, AsmFiles: []string{scope.assembly}}}
			checks := 0
			outcomes, err := runDiscoveryPackageChecks(groups, func(patterns []string) error {
				checks++
				return runDiscoveryGoBuild(ctx, download.Dir, os.Environ(), scope.target, scope.tags, patterns...)
			})
			if err != nil || checks != 1 || len(outcomes) != 1 {
				t.Fatalf("mandatory final source check was not independently executed: checks=%d outcomes=%v error=%v", checks, outcomes, err)
			}
			if scope.bad {
				diagnostic := discoveryCommandDiagnostic(outcomes[0])
				if outcomes[0] == nil || !strings.Contains(diagnostic, "undefined: missingArchitectureValue") {
					t.Fatalf("exact original Go rejection disappeared: %v", outcomes[0])
				}
				item := discoverySourceNotApplicableItem{
					Kind: discoverySourceNotApplicableGoBuild, AsmFiles: groups[0].AsmFiles,
					Targets: []string{scope.target}, Reason: diagnostic,
					Diagnostic: captureDiscoverySourceDiagnostic(diagnostic),
				}
				if err := validateDiscoverySourceRejectionDiagnostic(item, false); err != nil {
					t.Fatalf("final rejection has no independently structured diagnostic: %v", err)
				}
				t.Logf("FINAL_ORIGINAL_SOURCE_REJECTION %s tags=%v diagnostic=%s", scope.target, scope.tags, item.Diagnostic.SHA256)
				return
			}
			if outcomes[0] != nil {
				t.Fatalf("healthy target/tag sibling was excluded: %v", outcomes[0])
			}
			request := discoveryFeatureProfileRequest{Target: scope.target, Baseline: true}
			if header, err := plan.headerPlanningCapture(request, scope.assembly, scope.tags); err != nil || header == nil {
				t.Fatalf("eligible sibling still needs its own actual header producer: %v", err)
			}
		})
	}
	if plan.HeaderPlanning == nil || len(plan.HeaderPlanning.Queries) != 2 {
		t.Fatal("only the two independently compiled healthy scopes may publish planning headers")
	}
	checks := 0
	for _, event := range phaseFixtureRecords(t, events.Bytes()) {
		if event.Kind == "span_start" && event.Phase == "ordinary_header_viability" {
			checks++
		}
	}
	if checks != 3 {
		t.Fatalf("four repeated failed queries and two healthy scopes performed %d package compiles, want 3 exact scopes", checks)
	}
	t.Log("ACTUAL_HEADER_VIABILITY queries=6 compiles=3 final_checks=3 network=local_fixture_proxy_only")

	t.Run("complete scoped producer and independent reader", func(t *testing.T) {
		llc, err := resolveDiscoveryExecutable("llc")
		if err != nil {
			t.Fatal(err)
		}
		targets := []string{"linux/386", "linux/amd64"}
		matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
			RepoRoot: root, Translator: translator, LLC: llc, Targets: targets, CandidateTimeout: 3 * time.Minute,
		}, candidate, filepath.Join(t.TempDir(), "candidate"))
		if err != nil || matrix.Success < 2 {
			t.Fatalf("healthy scopes on both architectures must survive a target/tag source failure: objects=%d error=%v", matrix.Success, err)
		}
		found := false
		for _, item := range matrix.SourceNotApplicableItems {
			if item.Kind != discoverySourceNotApplicableGoBuild {
				continue
			}
			if !equalDiscoveryStrings(item.Targets, []string{"linux/386"}) ||
				!equalDiscoveryStrings(item.BuildTags, []string{"durable"}) ||
				!strings.Contains(item.Reason, "undefined: missingArchitectureValue") {
				t.Fatalf("scoped original-Go refusal was broadened or lost its diagnostic: %+v", item)
			}
			found = true
		}
		if !found {
			t.Fatal("invalid target/tag vanished from the final coverage denominator")
		}
		inventory, refs := fixtureOrdinaryMatrixFeatureInventory(t, matrix)
		result := discoveryCorpusResult{
			Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
			DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: candidate.AsmFiles,
			BuildConfigurations: configs, Translations: matrix.Success,
			OrdinarySelectionPlan:    matrix.OrdinarySelectionPlan,
			SourceNotApplicableItems: matrix.SourceNotApplicableItems,
			FeatureProfiles:          refs, FeatureConsumption: matrix.FeatureConsumption, featureInventory: inventory,
		}
		if err := validateOrdinaryProfileResult(result, targets, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
			t.Fatalf("independent final Go/source/CPP/LLVM scope replay: %v", err)
		}
		t.Logf("COMPLETE_ORIGINAL_SOURCE_REJECTION objects=%d rejected_scopes=%d configurations=%+v", matrix.Success, len(matrix.SourceNotApplicableItems), configs)
		for index := range result.SourceNotApplicableItems {
			changed := result
			changed.SourceNotApplicableItems = append(append([]discoverySourceNotApplicableItem(nil), result.SourceNotApplicableItems[:index]...), result.SourceNotApplicableItems[index+1:]...)
			if err := validateOrdinaryProfileResult(changed, targets, matrix.OrdinarySelectionPlan.GoVersion); err == nil {
				t.Fatalf("reader accepted deletion of source rejection %d", index)
			}
		}
		for index := range result.FeatureConsumption {
			changed := result
			changed.FeatureConsumption = append(append([]*gotoolprofile.SelectionProof(nil), result.FeatureConsumption[:index]...), result.FeatureConsumption[index+1:]...)
			changed.Translations--
			if err := validateOrdinaryProfileResult(changed, targets, matrix.OrdinarySelectionPlan.GoVersion); err == nil {
				t.Fatalf("reader accepted deletion of executed object %d", index)
			}
		}
		var baselines []*discoveryTargetFeatures
		for _, profile := range matrix.FeatureProfiles {
			if profile.Request.Baseline {
				baselines = append(baselines, profile.Observed)
			}
		}
		original, err := planDiscoveryFeatureProfiles(matrix.OrdinarySelectionPlan, candidate.AsmFiles, baselines)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(matrix.OrdinarySelectionPlan)
		if err != nil {
			t.Fatal(err)
		}
		var changed discoveryOrdinarySelectionPlan
		if err := json.Unmarshal(encoded, &changed); err != nil {
			t.Fatal(err)
		}
		changed.headerPlanningInventory = inventory
		for index, query := range changed.HeaderPlanning.Queries {
			if query.Profile.Request.Target != "linux/amd64" {
				continue
			}
			changed.HeaderPlanning.Queries = append(changed.HeaderPlanning.Queries[:index:index], changed.HeaderPlanning.Queries[index+1:]...)
			break
		}
		conservative, err := planDiscoveryFeatureProfiles(&changed, candidate.AsmFiles, baselines)
		if err != nil {
			t.Fatalf("missing planning query did not retain conservative proposals: %v", err)
		}
		keys := make(map[string]bool)
		for _, proposal := range conservative {
			keys[discoveryFeatureRequestKey(proposal)] = true
		}
		for _, proposal := range original {
			if !keys[discoveryFeatureRequestKey(proposal)] {
				t.Fatal("deleting a planning receipt shrank the required profile denominator")
			}
		}
		if len(conservative) <= len(original) {
			t.Fatal("missing amd64 header failed to retain the full legal CPU proposals")
		}
		missing := result
		missing.OrdinarySelectionPlan = &changed
		if err := validateOrdinaryProfileResult(missing, targets, changed.GoVersion); err == nil {
			t.Fatal("missing planning query borrowed unexecuted expanded CPU objects")
		}
		query := &changed.HeaderPlanning.Queries[0]
		query.Metadata = nil
		if _, err := discoveryPlanningHeader(&changed, query.Profile.Request, query.Assembly, query.BuildTags); err == nil || errors.As(err, &unsupported) {
			t.Fatalf("corrupt existing query became a missing-query fallback: %v", err)
		}
	})

	t.Run("cached rejection cannot hide changed source", func(t *testing.T) {
		file := filepath.Join(download.Dir, "poison.go")
		if err := os.Chmod(file, 0600); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, file, sources["poison.go"]+"// changed after original check\n")
		t.Cleanup(func() { writeTestFile(t, file, sources["poison.go"]) })
		if _, err := plan.headerPlanningCapture(badRequest, "probe_386.s", []string{"durable"}); err == nil || errors.As(err, &unsupported) {
			t.Fatalf("changed original source was hidden by cached rejection: %v", err)
		}
	})
	t.Run("metadata diagnostics cannot impersonate original Go", func(t *testing.T) {
		broken := filepath.Join(t.TempDir(), "broken-query")
		writeTestFile(t, broken, "#!/bin/sh\nprintf '%s\\n' 'probe.go:1:1: metadata owner failure' >&2\nexit 1\n")
		if err := os.Chmod(broken, 0700); err != nil {
			t.Fatal(err)
		}
		fresh, err := captureOrdinarySelectionInputs(candidate, download.Dir, []string{"linux/386", "linux/amd64"})
		if err != nil {
			t.Fatal(err)
		}
		fresh.ModuleSum, fresh.ZipSHA256 = plan.ModuleSum, plan.ZipSHA256
		if err := installDiscoveryHeaderPlanning(ctx, fresh, candidate, download, t.TempDir(), runtime.GOROOT(), goBinary,
			t.TempDir(), broken, os.Environ(), &discoveryFeatureObservationCache{}); err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.headerPlanningCapture(badRequest, "probe_386.s", nil); err == nil || errors.As(err, &unsupported) ||
			!strings.Contains(err.Error(), "metadata owner failure") {
			t.Fatalf("non-Go metadata diagnostic was hidden or reclassified: %v", err)
		}
	})
}

// A malformed package clause cannot erase its filename/build-tag scope. Go's
// package loader may reject it even before tag selection, so both default and
// tagged scopes retain their actual diagnostics; a separate healthy package
// still needs its own LLVM object.
func TestCPPHeaderPlanningMalformedPartnerFinalSourceRejection(t *testing.T) {
	compilerEnv := os.Environ()
	root, err := fixtureTranslatorRoot()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	translator := filepath.Join(t.TempDir(), "plan9asmll")
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", translator, ".")
	command.Dir, command.Env = filepath.Join(root, "cmd/plan9asmll"), compilerEnv
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build first-party consumer: %v\n%s", err, output)
	}
	llc, err := resolveDiscoveryExecutable("llc")
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []struct {
		name, body, diagnostic string
	}{
		{"keyword", "packag witness\n", "expected 'package'"},
		{"identifier", "package 123\n", "expected 'IDENT'"},
	} {
		t.Run(source.name, func(t *testing.T) {
			candidate := discoveryCandidate{Module: "example.invalid/malformed-" + source.name, Version: "v1.0.0",
				AsmFiles: []string{"healthy/probe_amd64.s", "probe_amd64.s"}}
			sources := map[string]string{
				"go.mod":                "module " + candidate.Module + "\ngo 1.20\n",
				"probe.go":              "package witness\nfunc Probe()\n",
				"poison.go":             "//go:build broken\n\n" + source.body,
				"probe_amd64.s":         "TEXT ·Probe(SB),4,$0-0\nRET\n",
				"healthy/probe.go":      "package healthy\nfunc Probe()\n",
				"healthy/probe_amd64.s": "TEXT ·Probe(SB),4,$0-0\nRET\n",
			}
			seed := fixtureProfileModuleDownload(t, candidate, sources)
			installGeneratedFixtureProxy(t, candidate, seed, sources["go.mod"])
			targets := []string{"linux/amd64"}
			matrix, _, configs, err := runDiscoveryCandidate(discoveryCorpusConfig{
				RepoRoot: root, Translator: translator, LLC: llc, Targets: targets, CandidateTimeout: 3 * time.Minute,
			}, candidate, filepath.Join(t.TempDir(), "candidate"))
			if err != nil || matrix.Success != 1 {
				t.Fatalf("healthy assembly must compile independently of malformed tagged partner: objects=%d error=%v configurations=%+v source=%+v", matrix.Success, err, configs, matrix.SourceNotApplicableItems)
			}
			if len(matrix.SourceNotApplicableItems) != 2 {
				t.Fatalf("malformed partner vanished from final coverage: rejections=%+v", matrix.SourceNotApplicableItems)
			}
			foundTagged := false
			for _, item := range matrix.SourceNotApplicableItems {
				if item.Kind != discoverySourceNotApplicableGoBuild ||
					!equalDiscoveryStrings(item.AsmFiles, []string{"probe_amd64.s"}) ||
					!strings.Contains(item.Reason, source.diagnostic) {
					t.Fatalf("malformed partner lacks exact actual-Go source rejection: %+v", item)
				}
				foundTagged = foundTagged || equalDiscoveryStrings(item.BuildTags, []string{"broken"})
			}
			if !foundTagged {
				t.Fatal("malformed partner's exact tagged scope disappeared")
			}
			inventory, refs := fixtureOrdinaryMatrixFeatureInventory(t, matrix)
			result := discoveryCorpusResult{
				Module: candidate.Module, Version: candidate.Version, Status: discoveryStatusPassed,
				DiscoveredAsmFiles: candidate.AsmFiles, ApplicableAsmFiles: []string{"healthy/probe_amd64.s"},
				BuildConfigurations: configs, Translations: matrix.Success,
				OrdinarySelectionPlan: matrix.OrdinarySelectionPlan, SourceNotApplicableItems: matrix.SourceNotApplicableItems,
				FeatureProfiles: refs, FeatureConsumption: matrix.FeatureConsumption, featureInventory: inventory,
			}
			if err := validateOrdinaryProfileResult(result, targets, matrix.OrdinarySelectionPlan.GoVersion); err != nil {
				t.Fatalf("independent exact source/object reader: %v", err)
			}
			for index := range result.SourceNotApplicableItems {
				changed := result
				changed.SourceNotApplicableItems = append(append([]discoverySourceNotApplicableItem(nil), result.SourceNotApplicableItems[:index]...), result.SourceNotApplicableItems[index+1:]...)
				if err := validateOrdinaryProfileResult(changed, targets, matrix.OrdinarySelectionPlan.GoVersion); err == nil {
					t.Fatalf("reader accepted deletion of malformed partner's actual Go rejection %d", index)
				}
			}
			t.Log("MALFORMED_PARTNER actual_llvm_objects=1 actual_go_rejections=2")
		})
	}
}
