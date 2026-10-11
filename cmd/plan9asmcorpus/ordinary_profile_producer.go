package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type discoveryProfileCaptureOptions struct {
	Markers    string
	Cache      *discoveryFeatureObservationCache
	Translator string
	Events     *discoveryPhaseJournal
}

// First observe source-tag profiles, then capture CPP from their selected file
// union. Capturing only a host/baseline union would lose feature-only assembly
// before its CPP predicates can contribute additional required profiles.
func captureDiscoveryOrdinaryProfiles(ctx context.Context, candidate discoveryCandidate, download moduleDownloadInfo, targets []string, dir string, env []string, options ...discoveryProfileCaptureOptions) (*discoveryOrdinarySelectionPlan, []discoveryFeatureProfile, []discoveryBuildConfiguration, []discoverySourceNotApplicableItem, string, error) {
	if len(options) > 1 || len(options) == 1 && (options[0].Cache == nil || !filepath.IsAbs(options[0].Markers)) {
		return nil, nil, nil, nil, "", fmt.Errorf("ordinary profiles require one owned observation cache")
	}
	plan, err := captureOrdinarySelectionInputs(candidate, download.Dir, targets)
	if err != nil {
		return nil, nil, nil, nil, "", err
	}
	if err := verifyOrdinarySelectionZIP(plan, download.Zip, download.Path, download.Version, download.Sum); err != nil {
		return nil, nil, nil, nil, "", err
	}
	scope, err := ordinarySelectionTestedAssembly(plan, candidate.AsmFiles)
	if err != nil {
		return nil, nil, nil, nil, "", err
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		return nil, nil, nil, nil, "", err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return nil, nil, nil, nil, "", err
	}
	markers := filepath.Join(dir, "actual-feature-markers")
	cache := &discoveryFeatureObservationCache{}
	if len(options) == 1 {
		markers, cache = options[0].Markers, options[0].Cache
	} else if err := os.Mkdir(markers, 0700); err != nil {
		return nil, nil, nil, nil, "", err
	}
	profiles, err := captureDiscoveryFeatureProfiles(ctx, binary, markers, env, plan, scope, cache)
	if err != nil {
		return nil, nil, nil, nil, "", err
	}
	initialDecisions, eligible, err := replayOrdinarySelectionForProfiles(plan, scope, profiles)
	if err != nil {
		return nil, nil, nil, nil, "", err
	}
	files := ordinaryProfileEligibleCPPFiles(eligible)
	documentationRequired := len(documentationRequiredPackages(initialDecisions)) != 0
	if len(files) != 0 || documentationRequired {
		if err := captureDiscoveryProxyGoMod(ctx, plan, download, dir, env); err != nil {
			return nil, nil, nil, nil, "", err
		}
	}
	var goRoot string
	if len(files) != 0 || documentationRequired {
		output, _, err := runDiscoveryMachineCommand(ctx, dir, env, binary, "env", "-json", "GOROOT", "GOVERSION")
		if err != nil {
			return nil, nil, nil, nil, "", err
		}
		var actual map[string]string
		if err := json.Unmarshal(output, &actual); err != nil || len(actual) != 2 || !filepath.IsAbs(actual["GOROOT"]) || actual["GOVERSION"] != plan.GoVersion {
			return nil, nil, nil, nil, "", fmt.Errorf("actual CPP root/Go version differs from the source producer")
		}
		goRoot = actual["GOROOT"]
		if documentationRequired {
			if err := captureDiscoveryDocumentationPackages(ctx, plan, profiles, initialDecisions, dir, goRoot, env, markers, cache); err != nil {
				return nil, nil, nil, nil, "", err
			}
		}
	}
	if len(files) != 0 {
		// Registration and profile selection reach a bounded fixed point
		// before any Go rejection or translation can close a scope. Generated
		// headers contain only object-like definitions, not new include edges;
		// unknown presence conservatively retains legal CPU proposals here.
		stable := false
		for iteration := 0; iteration < 8; iteration++ {
			preRejected, err := captureDiscoveryPreCPPRejections(ctx, plan, profiles, eligible, download, dir, goRoot, binary, env)
			if err != nil {
				return nil, nil, nil, nil, "", err
			}
			files = ordinaryProfileEligibleCPPFiles(preCPPRemainingScopes(eligible, preRejected))
			if len(files) == 0 {
				plan.CPPInputs, stable = nil, true
				break
			}
			for attempt := 0; ; attempt++ {
				plan.CPPInputs, err = captureDiscoveryDeferredCPPInputs(plan, download.Dir, goRoot, files, ctx)
				if err == nil {
					break
				}
				var unsupported *discoveryUnsupportedCPPError
				if attempt >= 512 || !errors.As(err, &unsupported) || !containsTargetFeature(files, unsupported.File) {
					return nil, nil, nil, nil, "", err
				}
				preRejected, err = captureDiscoveryPreCPPRejections(ctx, plan, profiles, eligible, download, dir, goRoot, binary, env, unsupported.File)
				if err != nil {
					return nil, nil, nil, nil, "", err
				}
				files = ordinaryProfileEligibleCPPFiles(preCPPRemainingScopes(eligible, preRejected))
				if len(files) == 0 {
					plan.CPPInputs = nil
					break
				}
			}
			if plan.CPPInputs == nil {
				stable = true
				break
			}
			if err := verifyDiscoveryCPPModuleZIP(plan.CPPInputs, plan, download.Zip); err != nil {
				return nil, nil, nil, nil, "", err
			}
			if len(options) == 1 {
				if err := installDiscoveryHeaderPlanning(ctx, plan, candidate, download, dir, goRoot, binary, markers, options[0].Translator, env, cache, options[0].Events); err != nil {
					return nil, nil, nil, nil, "", err
				}
			}
			profiles, err = captureDiscoveryFeatureProfiles(ctx, binary, markers, env, plan, scope, cache)
			if err != nil {
				return nil, nil, nil, nil, "", err
			}
			selectedDecisions, selected, err := replayOrdinarySelectionForProfiles(plan, scope, profiles)
			if err != nil {
				return nil, nil, nil, nil, "", err
			}
			if err := captureDiscoveryDocumentationPackages(ctx, plan, profiles, selectedDecisions, dir, goRoot, env, markers, cache); err != nil {
				return nil, nil, nil, nil, "", err
			}
			eligible = selected
			preRejected, err = captureDiscoveryPreCPPRejections(ctx, plan, profiles, eligible, download, dir, goRoot, binary, env)
			if err != nil {
				return nil, nil, nil, nil, "", err
			}
			next := ordinaryProfileEligibleCPPFiles(preCPPRemainingScopes(selected, preRejected))
			files, stable, err = ordinaryProfileCPPRegistrationUnion(files, next)
			if err != nil {
				return nil, nil, nil, nil, "", err
			}
			if stable {
				break
			}
		}
		if !stable {
			return nil, nil, nil, nil, "", fmt.Errorf("source/CPP/profile registration did not reach its bounded fixed point (not N/A)")
		}
	}
	decisions, eligible, err := replayOrdinarySelectionForProfiles(plan, scope, profiles)
	if err != nil {
		return nil, nil, nil, nil, "", err
	}
	if err := validateDiscoveryDocumentationPackages(plan, profiles, decisions); err != nil {
		return nil, nil, nil, nil, "", err
	}
	preRejected, err := validateDiscoveryPreCPPRejections(plan, profiles, eligible)
	if err != nil {
		return nil, nil, nil, nil, "", err
	}
	remaining := preCPPRemainingScopes(eligible, preRejected)
	if plan.CPPInputs != nil {
		if err := validateDiscoveryCPPInputs(plan.CPPInputs, plan, ordinaryProfileEligibleCPPFiles(remaining)); err != nil {
			return nil, nil, nil, nil, "", err
		}
	} else if len(remaining) != 0 {
		return nil, nil, nil, nil, "", fmt.Errorf("eligible assembly lacks its complete raw CPP registration")
	}
	plan.ProfileDecisions = decisions
	configs := ordinaryProfileConfigurations(remaining)
	var rejected []discoverySourceNotApplicableItem
	for _, proof := range plan.PreCPPRejections {
		rejected = append(rejected, discoverySourceNotApplicableItem{
			ProfileID: proof.ProfileID, BuildTags: proof.BuildTags, AsmFiles: []string{proof.File},
			Targets: []string{proof.Target}, Kind: nativeLayoutGoAssemblerTarget, Reason: proof.Reason,
		})
	}
	for _, decision := range decisions {
		if decision.Kind == discoverySourceNotApplicableNoGoPackage || decision.Kind == discoveryDocumentationKind {
			rejected = append(rejected, discoverySourceNotApplicableItem{
				ProfileID: decision.ProfileID, BuildTags: decision.BuildTags,
				AsmFiles: decision.AsmFiles, Targets: decision.Targets,
				Kind: decision.Kind, Reason: decision.Diagnostic,
			})
		}
	}
	if err := verifyDiscoveryOrdinaryCPP(plan, download.Dir, goRoot, candidate); err != nil {
		return nil, nil, nil, nil, "", err
	}
	if plan.headerPlanningRecheck != nil {
		if err := plan.headerPlanningRecheck(); err != nil {
			return nil, nil, nil, nil, "", err
		}
	}
	// Returned plans replay their immutable query receipts, not this live
	// producer context or its disposable workspace.
	plan.headerPlanningCapture, plan.headerPlanningRecheck = nil, nil
	return plan, profiles, configs, rejected, goRoot, nil
}

func ordinaryProfileCPPRegistrationUnion(registered, selected []string) ([]string, bool, error) {
	union := uniqueSortedDiscoveryStrings(append(append([]string(nil), registered...), selected...))
	if len(union) > 512 {
		return nil, false, fmt.Errorf("raw CPP root registration exceeds its bounded source scope (not N/A)")
	}
	return union, equalDiscoveryStrings(registered, union), nil
}

func ordinaryProfileEligibleCPPFiles(scopes map[discoveryProfileScope]bool) []string {
	files := make(map[string]bool)
	for scope := range scopes {
		files[scope.File] = true
	}
	return sortedDiscoverySet(files)
}

func ordinaryProfileConfigurations(scopes map[discoveryProfileScope]bool) []discoveryBuildConfiguration {
	byKey := make(map[discoveryProfileScope][]string)
	for scope := range scopes {
		file := scope.File
		scope.File = ""
		byKey[scope] = append(byKey[scope], file)
	}
	keys := make([]discoveryProfileScope, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		if a.ProfileID != b.ProfileID {
			return a.ProfileID < b.ProfileID
		}
		return a.Tags < b.Tags
	})
	var configs []discoveryBuildConfiguration
	for _, key := range keys {
		var tags []string
		if key.Tags != "" {
			tags = strings.Split(key.Tags, "\x00")
		}
		configs = append(configs, discoveryBuildConfiguration{
			ProfileID: key.ProfileID, BuildTags: tags, Targets: []string{key.Target},
			AsmFiles: uniqueSortedDiscoveryStrings(byKey[key]),
		})
	}
	return configs
}

func ordinaryProfileEnvironment(base []string, observed *discoveryTargetFeatures) []string {
	replacements := map[string]string{
		"GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "", "GOPACKAGESDRIVER": "off",
	}
	for key, value := range observed.Environment {
		if key != "GOVERSION" {
			replacements[key] = value
		}
	}
	return replaceEnv(base, replacements)
}

func verifyDiscoveryProfileCurrent(ctx context.Context, markers string, env []string, profile discoveryFeatureProfile, cache *discoveryFeatureObservationCache) error {
	binary, err := exec.LookPath("go")
	if err != nil {
		return &discoverySourceProofError{err}
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return &discoverySourceProofError{err}
	}
	current, err := cache.observe(ctx, binary, markers, env, profile.Request.Target, profile.Request.Overrides)
	if err != nil {
		return &discoverySourceProofError{err}
	}
	if discoveryFeatureProfileID(current) != profile.ID {
		return &discoverySourceProofError{fmt.Errorf("actual driver/source/tools/environment changed for profile %s", profile.ID)}
	}
	return nil
}

func profileObservation(profile *discoveryFeatureProfile) *discoveryTargetFeatures {
	if profile == nil {
		return nil
	}
	return profile.Observed
}
