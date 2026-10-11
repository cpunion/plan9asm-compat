package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Source/driver proof failures are never Go-source incompatibility evidence.
// Keep the type through joined command errors so package-batch fallback cannot
// turn a changed header into a source N/A after a compiler also rejects it.
type discoverySourceProofError struct{ err error }

func (err *discoverySourceProofError) Error() string {
	return "source proof failure: " + err.err.Error()
}
func (err *discoverySourceProofError) Unwrap() error { return err.err }

func captureDiscoveryOrdinaryCPP(ctx context.Context, candidate discoveryCandidate, download moduleDownloadInfo, targets []string, dir string, env []string) (*discoveryOrdinarySelectionPlan, string, error) {
	plan, err := captureOrdinarySelectionPlan(candidate, download.Dir, targets)
	if err != nil {
		return nil, "", err
	}
	if err := verifyOrdinarySelectionZIP(plan, download.Zip, download.Path, download.Version, download.Sum); err != nil {
		return nil, "", err
	}
	scope, err := ordinarySelectionTestedAssembly(plan, candidate.AsmFiles)
	if err != nil {
		return nil, "", err
	}
	_, eligible, err := replayOrdinarySelection(plan, scope)
	if err != nil {
		return nil, "", err
	}
	files := ordinarySelectionEligibleCPPFiles(eligible)
	if len(files) == 0 {
		return plan, "", nil
	}
	output, _, err := runDiscoveryMachineCommand(ctx, dir, env, "go", "env", "-json", "GOROOT", "GOVERSION")
	if err != nil {
		return nil, "", fmt.Errorf("observe actual CPP driver source root: %w", err)
	}
	var actual map[string]string
	if err := json.Unmarshal(output, &actual); err != nil || len(actual) != 2 || !filepath.IsAbs(actual["GOROOT"]) || actual["GOVERSION"] != plan.GoVersion {
		return nil, "", fmt.Errorf("CPP source root/Go version differs from the candidate producer")
	}
	inputs, err := captureDiscoveryCPPInputs(plan, download.Dir, actual["GOROOT"], files, ctx)
	if err != nil {
		return nil, "", err
	}
	if err := verifyDiscoveryCPPModuleZIP(inputs, plan, download.Zip); err != nil {
		return nil, "", err
	}
	plan.CPPInputs = inputs
	if err := rejectDiscoveryUnconsumedCPPProfiles(ctx, plan, scope, dir, env); err != nil {
		return nil, "", err
	}
	return plan, actual["GOROOT"], nil
}

// Until the profile-aware package/translator/report consumers are all wired,
// an observed CPP feature profile is a pending coverage requirement, not a
// baseline pass or an empty-object N/A. This production guard deliberately
// blocks those inputs; it is replaced only by the schema-10 scope consumer.
func rejectDiscoveryUnconsumedCPPProfiles(ctx context.Context, plan *discoveryOrdinarySelectionPlan, files []string, dir string, env []string) error {
	required, err := discoveryCPPRequiresFeatureProfiles(plan.CPPInputs)
	if err != nil {
		return err
	}
	if !required {
		return nil
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		return err
	}
	markerDir := filepath.Join(dir, "cpp-feature-markers")
	if err := os.Mkdir(markerDir, 0700); err != nil {
		return err
	}
	profiles, err := captureDiscoveryFeatureProfiles(ctx, goBinary, markerDir, env, plan, files)
	if err != nil {
		return fmt.Errorf("required CPP feature observation (not source N/A): %w", err)
	}
	var identities []string
	for _, profile := range profiles {
		key := discoveryCPPFeatureCPUKey(profile.Observed.Environment["GOARCH"])
		identities = append(identities, profile.Observed.Target+" "+key+"="+profile.Observed.Environment[key]+" id="+profile.ID)
	}
	return fmt.Errorf("CPP profiles require profile-aware production consumers; pending, not N/A: %s", strings.Join(identities, "; "))
}

func discoveryCPPRequiresFeatureProfiles(inputs *discoveryCPPInputs) (bool, error) {
	if inputs == nil {
		return false, nil
	}
	required := false
	for _, unit := range inputs.Units {
		directives, err := discoveryCPPUnitDirectives(inputs, unit, make(map[string]bool))
		if err != nil {
			return false, err
		}
		required = required || discoveryCPPHasFeatureConditions(directives)
	}
	return required, nil
}

func ordinarySelectionEligibleCPPFiles(eligible map[nativeLayoutPlanKey]bool) []string {
	files := make(map[string]bool)
	for key := range eligible {
		files[key.File] = true
	}
	return sortedDiscoverySet(files)
}

func verifyDiscoveryOrdinaryCPP(plan *discoveryOrdinarySelectionPlan, moduleDir, goRoot string, candidate discoveryCandidate) error {
	if plan == nil {
		return nil // independently verified native/private exception protocol
	}
	if err := verifyDiscoveryProxyGoMod(plan); err != nil {
		return &discoverySourceProofError{err}
	}
	if err := verifyOrdinarySelectionUnchanged(plan, moduleDir, candidate); err != nil {
		return &discoverySourceProofError{err}
	}
	if err := verifyDiscoveryPreCPPOriginalSources(plan, moduleDir); err != nil {
		return &discoverySourceProofError{err}
	}
	if err := verifyDiscoveryFortranOriginalSources(plan, moduleDir, goRoot); err != nil {
		return &discoverySourceProofError{err}
	}
	if err := verifyDiscoveryMixedPackageSources(plan, goRoot); err != nil {
		return &discoverySourceProofError{err}
	}
	if err := verifyDiscoverySDKNamespaceSources(plan, goRoot); err != nil {
		return &discoverySourceProofError{err}
	}
	if err := verifyDiscoveryDocumentationSources(plan, goRoot); err != nil {
		return &discoverySourceProofError{err}
	}
	if plan.CPPInputs != nil {
		if err := verifyDiscoveryCPPInputsUnchanged(plan.CPPInputs, moduleDir, goRoot); err != nil {
			return &discoverySourceProofError{err}
		}
	}
	if plan.InstrumentationPlan != nil && plan.InstrumentationPlan.CPPInputs != nil {
		root := goRoot
		if root == "" {
			root = plan.instrumentationGoRoot
		}
		if err := verifyDiscoveryCPPInputsUnchanged(plan.InstrumentationPlan.CPPInputs, moduleDir, root); err != nil {
			return &discoverySourceProofError{err}
		}
	}
	for file, before := range plan.GeneratedGoSources {
		if err := discoveryCPPRegularSource(moduleDir, filepath.Join(moduleDir, filepath.FromSlash(file))); err != nil {
			return &discoverySourceProofError{err}
		}
		after, err := discoveryFeatureFileSHA256(filepath.Join(moduleDir, filepath.FromSlash(file)))
		if err != nil || before != after {
			return &discoverySourceProofError{fmt.Errorf("generated-header original imported Go source changed: %s: %v", file, err)}
		}
	}
	if err := verifyDiscoveryTestDependencySnapshot(plan, moduleDir); err != nil {
		return &discoverySourceProofError{err}
	}
	if err := verifyDiscoveryOrdinaryDependencySnapshots(plan); err != nil {
		return &discoverySourceProofError{err}
	}
	return nil
}

func runDiscoveryOrdinaryGuarded(plan *discoveryOrdinarySelectionPlan, moduleDir, goRoot string, candidate discoveryCandidate, run func() error) (runErr error) {
	if err := verifyDiscoveryOrdinaryCPP(plan, moduleDir, goRoot, candidate); err != nil {
		return err
	}
	defer func() {
		// A successful guard must retain the actual completed command receipt.
		// errors.Join(runErr, nil) would introduce an unexplained outer error.
		if err := verifyDiscoveryOrdinaryCPP(plan, moduleDir, goRoot, candidate); err != nil {
			runErr = errors.Join(runErr, err)
		}
	}()
	return run()
}
