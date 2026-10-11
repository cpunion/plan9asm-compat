package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func captureDiscoveryInstrumentationHeaderPlanning(ctx context.Context, cfg discoveryCorpusConfig, candidate discoveryCandidate, download moduleDownloadInfo,
	plan *discoveryOrdinarySelectionPlan, profiles []discoveryFeatureProfile, modeRoot, binary, goRoot string, env []string,
) (func(discoveryInstrumentationRequirement, string) (*gotoolprofile.GeneratedHeaderProof, error), error) {
	if ctx == nil {
		return nil, fmt.Errorf("same-mode header planning requires its actual parent context")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, fmt.Errorf("same-mode header planning requires a bounded parent context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var rules *gotoolprofile.NativeHeaderSourceRules
	proof := plan.InstrumentationPlan
	role := &discoveryInstrumentationHeaderPlanning{Protocol: discoveryInstrumentationHeaderPlanningProtocol, Rules: rules,
		Contents: make(map[string]string), Queries: []discoveryInstrumentationHeaderQuery{}, used: make(map[string]bool)}
	baselines := discoveryInstrumentationBaselines(profiles)
	modulePath, err := discoveryInstrumentationModulePath(plan)
	if err != nil {
		return nil, err
	}
	unsupported := false
	return func(requirement discoveryInstrumentationRequirement, assembly string) (*gotoolprofile.GeneratedHeaderProof, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// This registration is required only at an actual missing-header
		// suspension, never by unrelated mode sources without a native query.
		if rules == nil && !unsupported {
			var err error
			rules, err = gotoolprofile.CaptureNativeHeaderSourceRules(goRoot, plan.GoVersion)
			if err != nil {
				if !gotoolprofile.NativeHeaderSourceDomainUnsupported(err) {
					return nil, err
				}
				unsupported = true
			}
			role.Rules = rules
		}
		if unsupported {
			return nil, &discoveryHeaderPlanningUnsupported{"same-mode native property domain is unclosed; every CPU proposal remains required"}
		}
		key, err := instrumentationHeaderQueryKey(requirement, assembly)
		if err != nil {
			return nil, err
		}
		for _, query := range role.Queries {
			oldKey, err := instrumentationHeaderQueryKey(query.Requirement, query.Assembly)
			if err != nil {
				return nil, err
			}
			if oldKey == key {
				return replayDiscoveryInstrumentationPlanningHeader(plan, requirement, assembly, baselines)
			}
		}
		if len(role.Queries) >= 4096 {
			return nil, fmt.Errorf("same-mode native property queries exceed their explicit bound")
		}
		var query discoveryInstrumentationHeaderQuery
		err = cfg.runPhaseOperationContext(ctx, candidate, "instrumentation_header_query", key, func(ctx context.Context) error {
			if err := gotoolprofile.RecheckNativeHeaderSourceRules(goRoot, rules); err != nil {
				return err
			}
			directory := filepath.Join(modeRoot, fmt.Sprintf("header-query-%04d", len(role.Queries)))
			if err := os.Mkdir(directory, 0700); err != nil {
				return err
			}
			markerDir := filepath.Join(directory, "marker")
			if err := os.Mkdir(markerDir, 0700); err != nil {
				return err
			}
			observation, err := gotoolprofile.CaptureInstrumentationExportObservation(ctx, binary, markerDir, env,
				requirement.Target, requirement.Mode, requirement.CGO, requirement.Overrides, gotoolprofile.RunBounded)
			if err != nil {
				return err
			}
			if err := validateDiscoveryInstrumentationObservation(requirement, profiles, observation); err != nil {
				return err
			}
			input := discoveryInstrumentationOriginalInput(plan, observation, download.Dir, nil)
			inventory := proof.Sources[requirement.Directory]
			packagePlan, err := gotoolprofile.PlanInstrumentationOriginalPackage(input, inventory, observation.Early, requirement.Directory, requirement.Tags)
			if err != nil {
				return err
			}
			input.AsmFiles = append([]string(nil), packagePlan.SFiles...)
			packagePlan, err = gotoolprofile.PlanInstrumentationOriginalPackage(input, inventory, observation.Early, requirement.Directory, requirement.Tags)
			if err != nil || !containsTargetFeature(packagePlan.SFiles, assembly) {
				return fmt.Errorf("same-mode header query lost its actual selected assembly: %v", err)
			}
			wrapped, err := gotoolprofile.NewInstrumentationConsumerInput(input, inventory, observation, packagePlan)
			if err != nil {
				return err
			}
			execution, err := makeDiscoveryExecutionPlan(candidate, modulePath)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(directory, "go.mod"), []byte(execution.GoMod), 0600); err != nil {
				return err
			}
			modeEnv := ordinaryProfileEnvironment(env, observation.Early.BaselineFeatures)
			modeEnv = replaceEnv(modeEnv, observation.Early.Environment)
			modeEnv = replaceEnv(modeEnv, map[string]string{"GOENV": "off"})
			modules, err := captureDiscoveryInstrumentationTypeModules(ctx, binary, directory, modeEnv, wrapped)
			if err != nil {
				return err
			}
			foreignGuard, err := gotoolprofile.BindInstrumentationTypeModuleSources(ctx, binary, directory, modeEnv, modules, gotoolprofile.RunBounded)
			if err != nil {
				return err
			}
			properties, signatures, err := gotoolprofile.CaptureInstrumentationNativeHeaderQuerySources(ctx, binary, directory, modeEnv, wrapped, modules, gotoolprofile.RunBounded)
			if err != nil {
				return err
			}
			wrapped.TypeSources = signatures
			inputPath := filepath.Join(directory, "input.json")
			data, err := json.Marshal(wrapped)
			if err != nil {
				return err
			}
			if err := os.WriteFile(inputPath, data, 0600); err != nil {
				return err
			}
			goos, goarch, _ := strings.Cut(requirement.Target, "/")
			queryPath := filepath.Join(directory, "metadata.json")
			args := []string{"-metadata-only", "-instrumentation-profile=" + inputPath,
				"-instrumentation-package-dir=" + requirement.Directory, "-goos=" + goos, "-goarch=" + goarch,
				"-module-path=" + modulePath, "-patterns=" + packagePlan.PackagePath,
				"-asm-files=" + strings.Join(packagePlan.SFiles, ","), "-strict-load=true", "-keep-going=false",
				"-feature-timeout=" + cfg.CandidateTimeout.String(), "-out=" + filepath.Join(directory, "query"), "-report=" + queryPath}
			if len(requirement.Tags) != 0 {
				args = append(args, "-tags="+strings.Join(requirement.Tags, ","))
			}
			if err := runCapturedCommand(ctx, directory, modeEnv, cfg.Translator, args...); err != nil {
				return fmt.Errorf("actual same-mode planning metadata/header query: %w", err)
			}
			invocation, err := readDiscoveryInstrumentationInvocation(queryPath, wrapped, gotoolprofile.InstrumentationMetadataQuery, nil, nil)
			if err != nil {
				return err
			}
			if err := foreignGuard.Verify(ctx); err != nil {
				return err
			}
			if err := verifyDiscoveryCPPInputsUnchanged(proof.CPPInputs, download.Dir, goRoot); err != nil {
				return err
			}
			if err := gotoolprofile.RecheckNativeHeaderSourceRules(goRoot, rules); err != nil {
				return err
			}
			query = discoveryInstrumentationHeaderQuery{Requirement: requirement, Assembly: assembly,
				Observation: observation, PackagePlan: packagePlan, Metadata: invocation.Metadata}
			query.Signatures, err = compactInstrumentationHeaderTypes(role, signatures)
			if err != nil {
				return err
			}
			query.PropertyTypes, err = compactInstrumentationHeaderTypes(role, properties.Types)
			if err != nil {
				return err
			}
			copy := *properties
			query.ModuleMetadata = retainInstrumentationHeaderContents(role, properties.GoMods)
			copy.Types, copy.GoMods = nil, nil
			query.Properties = &copy
			return nil
		})
		if err != nil {
			if gotoolprofile.NativeHeaderSourceDomainUnsupported(err) {
				unsupported, proof.HeaderPlanning = true, nil
				return nil, &discoveryHeaderPlanningUnsupported{err.Error()}
			}
			return nil, err
		}
		role.Queries = append(role.Queries, query)
		proof.HeaderPlanning = role
		return replayDiscoveryInstrumentationPlanningHeader(plan, requirement, assembly, baselines)
	}, nil
}
