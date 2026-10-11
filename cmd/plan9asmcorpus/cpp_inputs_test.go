package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func fixtureCPPInputs(t *testing.T) (*discoveryOrdinarySelectionPlan, string, string) {
	return fixtureCPPInputsForTarget(t, "linux/amd64", nil)
}

func fixtureCPPInputsForTarget(t *testing.T, target string, overrides map[string]string) (*discoveryOrdinarySelectionPlan, string, string) {
	t.Helper()
	root := t.TempDir()
	asmFile := "pkg/native_" + strings.Split(target, "/")[1] + ".s"
	sources := map[string]string{
		"go.mod":           "module example.invalid/cpp-inputs\n\ngo 1.20\n",
		"pkg/decl.go":      "package fixture\n",
		asmFile:            "#include \"sub/outer.h\"\n#include \"textflag.h\"\nTEXT ·Probe(SB),$0-0\nRET\n",
		"pkg/sub/outer.h":  "#include \"choice.h\"\n#ifdef GOAMD64_v3\n#define V3 1\n#endif\n",
		"pkg/choice.h":     "#define CORRECT_GO_PACKAGE_DIR 1\n",
		"pkg/sub/choice.h": "#define WRONG_NESTED_HEADER_DIR 1\n",
	}
	for file, source := range overrides {
		sources[file] = source
	}
	for file, source := range sources {
		name := filepath.Join(root, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, name, source)
	}
	archivePath := filepath.Join(t.TempDir(), "module.zip")
	archive, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(archive)
	var files []string
	for file := range sources {
		files = append(files, file)
	}
	sort.Strings(files)
	for _, file := range files {
		entry, err := writer.Create("example.invalid/cpp-inputs@v1.0.0/" + file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(sources[file])); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	candidate := discoveryCandidate{Module: "example.invalid/cpp-inputs", Version: "v1.0.0", AsmFiles: []string{asmFile}}
	plan, err := captureOrdinarySelectionInputs(candidate, root, []string{target})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOrdinarySelectionZIP(plan, archivePath, candidate.Module, candidate.Version, ""); err != nil {
		t.Fatal(err)
	}
	return plan, root, archivePath
}

func TestCPPInputsResolveIncludesFromGoFixedPackageDirectory(t *testing.T) {
	plan, root, archive := fixtureCPPInputs(t)
	files := []string{"pkg/native_amd64.s"}
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), files)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs.Units) != 1 || len(inputs.Sources) != 4 || inputs.Units[0].Includes["module/pkg/sub/outer.h#0"] != "module/pkg/choice.h" {
		t.Fatalf("include inventory did not follow actual Go fixed -I/CWD search: %+v", inputs)
	}
	if _, wrong := inputs.Sources["module/pkg/sub/choice.h"]; wrong {
		t.Fatal("nested header Dir was incorrectly preferred over actual Go package Dir")
	}
	if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCPPInputsUnchanged(inputs, root, runtime.GOROOT()); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(inputs)
	if err != nil || len(canonical) > 16<<10 {
		t.Fatalf("compact CPP proof unexpectedly inflated: %d %v", len(canonical), err)
	}
	var replay discoveryCPPInputs
	if err := json.Unmarshal(canonical, &replay); err != nil {
		t.Fatal(err)
	}
	if err := validateDiscoveryCPPInputs(&replay, plan, files); err != nil {
		t.Fatal(err)
	}
}

func TestOrdinaryConsumerRetainsCPPResourceOutsidePackageMembership(t *testing.T) {
	plan, root, archive := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		"pkg/native_amd64.s": "#include \"../shared/choice.h\"\nTEXT ·Probe(SB),$0-0\nRET\n",
		"shared/choice.h":    "#define CHOICE 41\n",
	})
	files := []string{"pkg/native_amd64.s"}
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), files)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
		t.Fatal(err)
	}
	plan.CPPInputs = inputs
	profile := discoveryFeatureProfile{Observed: &discoveryTargetFeatures{Target: "linux/amd64", GoVersion: runtime.Version()}}
	input := ordinaryProfileConsumerInput(plan, profile, plan.Module, root, files)
	if input.Sources["shared/choice.h"] != inputs.Sources["module/shared/choice.h"].SHA256 {
		t.Fatal("registered exact CPP resource disappeared from the production consumer input")
	}
	if _, found := input.Directories["shared"]; found {
		t.Fatal("CPP resource invented Go package-directory membership")
	}
	conflict := inputs.Sources["module/pkg/native_amd64.s"]
	originalSHA256 := conflict.SHA256
	conflict.SHA256 = strings.Repeat("0", 64)
	inputs.Sources["module/pkg/native_amd64.s"] = conflict
	input = ordinaryProfileConsumerInput(plan, profile, plan.Module, root, files)
	if input.Sources["pkg/native_amd64.s"] != "" {
		t.Fatal("CPP registration overwrote conflicting original source bytes")
	}
	conflict.SHA256 = originalSHA256
	inputs.Sources["module/pkg/native_amd64.s"] = conflict
	plan.GeneratedGoSources = map[string]string{"pkg/native_amd64.s": strings.Repeat("0", 64)}
	input = ordinaryProfileConsumerInput(plan, profile, plan.Module, root, files)
	if input.Sources["pkg/native_amd64.s"] != "" {
		t.Fatal("CPP registration revived an earlier conflicting source snapshot")
	}
}

func TestCPPInputsActualZIPCrosscheckRejectsForgedPredicateWithUnchangedHashes(t *testing.T) {
	plan, root, archive := fixtureCPPInputs(t)
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{"pkg/native_amd64.s"})
	if err != nil {
		t.Fatal(err)
	}
	input, present := inputs.Sources["module/pkg/sub/outer.h"]
	if !present || len(input.Directives) < 2 {
		t.Fatal("real source condition was not captured")
	}
	input.Directives[1].Name = "GOAMD64_v4"
	inputs.Sources["module/pkg/sub/outer.h"] = input
	if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err == nil {
		t.Fatal("caller changed predicate while full source/ZIP hashes stayed unchanged")
	}
}

func TestCPPInputsUnknownIncludeAndSourceMutationCannotEstablishEmptyAssembly(t *testing.T) {
	plan, root, _ := fixtureCPPInputs(t)
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{"pkg/native_amd64.s"})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "pkg/choice.h"), "#define MODIFIED 1\n")
	if err := verifyDiscoveryCPPInputsUnchanged(inputs, root, runtime.GOROOT()); err == nil {
		t.Fatal("changed consumed header was accepted")
	}
	writeTestFile(t, filepath.Join(root, "pkg/choice.h"), "#include \"go_asm.h\"\n")
	if _, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{"pkg/native_amd64.s"}); err == nil {
		t.Fatal("unbound generated/include input could become default empty-object evidence")
	}
}

func TestCPPInputsDetectsNewPreferredHeaderWithoutChangingOldBytes(t *testing.T) {
	plan, root, _ := fixtureCPPInputs(t)
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{"pkg/native_amd64.s"})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "pkg/textflag.h"), "#define FORGED_PREFERRED_HEADER 1\n")
	if err := verifyDiscoveryCPPInputsUnchanged(inputs, root, runtime.GOROOT()); err == nil {
		t.Fatal("new preferred header changed actual include choice without invalidating original hashes")
	}
}

func TestDiscoveryCandidateGeneratedCPPNeedsActualMetadataToolNotSourceNA(t *testing.T) {
	_, err := runFixtureCPPProductionCandidate(t, "#include \"go_asm.h\"\nTEXT ·Probe(SB),$0-0\nRET\n")
	if err == nil || !strings.Contains(err.Error(), "actual absolute metadata consumer executable (not N/A)") {
		t.Fatalf("production candidate accepted a generated origin without its actual metadata tool or reduced it to N/A: %v", err)
	}
}

func runFixtureCPPProductionCandidate(t *testing.T, asm string) (matrixReport, error) {
	t.Helper()
	const module = "example.invalid/cpp-candidate"
	const version = "v1.0.0"
	const goMod = "module " + module + "\n\ngo 1.20\n"
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for file, source := range map[string]string{
		"go.mod": goMod, "decl.go": "package fixture\nfunc Probe()\n",
		"native_amd64.s": asm,
	} {
		entry, err := writer.Create(module + "@" + version + "/" + file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(source)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + module + "/@v/" + version + ".info":
			fmt.Fprintf(w, `{"Version":%q,"Time":"2026-01-01T00:00:00Z"}`, version)
		case "/" + module + "/@v/" + version + ".mod":
			fmt.Fprint(w, goMod)
		case "/" + module + "/@v/" + version + ".zip":
			_, _ = w.Write(archive.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GOPROXY", server.URL)
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GONOPROXY", "none")
	t.Setenv("GOMODCACHE", t.TempDir())
	result, _, _, err := runDiscoveryCandidate(discoveryCorpusConfig{CandidateTimeout: 30 * time.Second, Targets: []string{"linux/amd64"}},
		discoveryCandidate{Module: module, Version: version, AsmFiles: []string{"native_amd64.s"}}, filepath.Join(t.TempDir(), "candidate"))
	return result, err
}

func TestOrdinaryCPPGuardPreservesNativeErrorAndRejectsNestedHeaderMutation(t *testing.T) {
	plan, root, _ := fixtureCPPInputs(t)
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{"pkg/native_amd64.s"})
	if err != nil {
		t.Fatal(err)
	}
	plan.CPPInputs = inputs
	candidate := discoveryCandidate{Module: plan.Module, Version: plan.Version, AsmFiles: []string{"pkg/native_amd64.s"}}
	sourceFailure := errors.New("fixture.go:2: undefined: missing")
	_, err = runDiscoveryPackageChecks([]discoveryPackageGroup{{Pattern: plan.Module + "/pkg", AsmFiles: candidate.AsmFiles}}, func([]string) error {
		return runDiscoveryOrdinaryGuarded(plan, root, runtime.GOROOT(), candidate, func() error {
			writeTestFile(t, filepath.Join(root, "pkg/sub/outer.h"), "#define ALTERED_NESTED_HEADER 1\n")
			return sourceFailure
		})
	})
	if !errors.Is(err, sourceFailure) || !isDiscoveryInfrastructureFailure(err) || !strings.Contains(err.Error(), "consumed CPP source changed") {
		t.Fatalf("native source error swallowed changed-header evidence or became N/A: %v", err)
	}
	if err := verifyDiscoveryOrdinaryCPP(plan, root, runtime.GOROOT(), candidate); err == nil {
		t.Fatal("final source guard accepted the changed nested header")
	}
}

func TestCPPInputsOfflineRejectsImpossibleHeaderBinding(t *testing.T) {
	plan, root, _ := fixtureCPPInputs(t)
	files := []string{"pkg/native_amd64.s"}
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), files)
	if err != nil {
		t.Fatal(err)
	}
	inputs.Units[0].Includes["module/pkg/sub/outer.h#0"] = "tool/pkg/include/textflag.h"
	delete(inputs.Sources, "module/pkg/choice.h")
	if err := validateDiscoveryCPPInputs(inputs, plan, files); err == nil {
		t.Fatal("offline importer accepted a consumed header unrelated to the literal include")
	}
}

func TestOrdinaryResultRevalidatesStoredCPPProof(t *testing.T) {
	plan, root, _ := fixtureCPPInputsForTarget(t, "linux/amd64", map[string]string{
		"pkg/sub/outer.h": "#include \"choice.h\"\n#define FIXED_HEADER 1\n",
	})
	files := []string{"pkg/native_amd64.s"}
	inputs, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), files)
	if err != nil {
		t.Fatal(err)
	}
	plan.CPPInputs = inputs
	plan.Decisions, _, err = replayOrdinarySelection(plan, files)
	if err != nil {
		t.Fatal(err)
	}
	result := discoveryCorpusResult{
		Module: plan.Module, Version: plan.Version, Status: discoveryStatusPassed,
		DiscoveredAsmFiles: files, ApplicableAsmFiles: files, Translations: 1,
		OrdinarySelectionPlan: plan,
		BuildConfigurations:   []discoveryBuildConfiguration{{Targets: plan.Targets, AsmFiles: files}},
	}
	if err := validateOrdinarySelectionResult(result, plan.Targets, plan.GoVersion); err != nil {
		t.Fatalf("actual compact CPP producer proof rejected: %v", err)
	}
	inputs.Units[0].Includes["module/pkg/sub/outer.h#0"] = "tool/pkg/include/textflag.h"
	delete(inputs.Sources, "module/pkg/choice.h")
	if err := validateOrdinarySelectionResult(result, plan.Targets, plan.GoVersion); err == nil {
		t.Fatal("ordinary report reader ignored a forged CPP include scope")
	}
	if !isDiscoveryGoBuildInfrastructureFailure("source proof failure: consumed CPP source changed") {
		t.Fatal("serialized source-integrity failure could be relabeled source N/A")
	}
}

func TestCPPInputsCaptureHonorsCandidateDeadline(t *testing.T) {
	plan, root, _ := fixtureCPPInputs(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := captureDiscoveryCPPInputs(plan, root, runtime.GOROOT(), []string{"pkg/native_amd64.s"}, ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled candidate established CPP source proof: %v", err)
	}
}
