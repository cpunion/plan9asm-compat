package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// Instrumented packages have their own actual driver/export/metadata/CPP/LLVM
// consumers. Nothing here translates an instrumentation tag into custom tags,
// reuses an ordinary export, or turns an unproved failure into source N/A.
func runDiscoveryInstrumentation(cfg discoveryCorpusConfig, candidate discoveryCandidate, download moduleDownloadInfo, plan *discoveryOrdinarySelectionPlan, profiles []discoveryFeatureProfile, workDir string, env []string) (objects int, runErr error) {
	if plan == nil || plan.InstrumentationPlan == nil || plan.InstrumentationPlan.Protocol != discoveryInstrumentationPlanProtocol {
		return 0, fmt.Errorf("mode execution lacks its independently required denominator")
	}
	proof := plan.InstrumentationPlan
	if len(proof.Requirements) == 0 {
		return 0, nil
	}
	if len(proof.Outcomes) != 0 || len(proof.Sources) != 0 || len(proof.Observations) != 0 || proof.CPPInputs != nil || proof.ModuleMetadata != "" || proof.CPPRequirements != nil || proof.HeaderPlanning != nil || proof.headerPlanningCapture != nil {
		return 0, fmt.Errorf("mode execution requires a fresh owned result, not another run's proof")
	}
	proof.Sources = make(map[string]*gotoolprofile.InstrumentationOriginalSourceInventory)
	proof.Observations = make(map[string]*gotoolprofile.InstrumentationExportObservation)
	proof.Outcomes = make([]discoveryInstrumentationOutcome, len(proof.Requirements))
	for index, requirement := range proof.Requirements {
		proof.Outcomes[index] = discoveryInstrumentationOutcome{
			RequirementID: requirement.ID, Status: "failed", Stage: "environment",
		}
	}
	defer func() {
		if runErr != nil {
			for index := range proof.Outcomes {
				outcome := &proof.Outcomes[index]
				if outcome.Status != "llvm_objects_only" && outcome.Status != discoveryInstrumentationExcludedStatus &&
					outcome.Status != discoveryInstrumentationSourceRejectedStatus && outcome.Error == "" {
					outcome.Error = runErr.Error()
				}
			}
		}
	}()
	if err := captureDiscoveryInstrumentationNamespace(plan, download.Dir); err != nil {
		return 0, err
	}
	modulePath, err := discoveryInstrumentationModulePath(plan)
	if err != nil {
		return 0, err
	}
	modeRoot := filepath.Join(workDir, "instrumentation")
	if err := os.Mkdir(modeRoot, 0700); err != nil {
		return 0, err
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		return 0, err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return 0, err
	}
	var goRoot string
	observedRequests := make(map[string]string)
	selected := make(map[string]bool)
	prepareRequirement := func(index int, requirement discoveryInstrumentationRequirement) {
		outcome := &proof.Outcomes[index]
		outcome.RequirementID, outcome.Status = requirement.ID, "failed"
		outcome.Stage = "environment"
		stageErr := cfg.runPhaseOperation(candidate, "instrumentation_prepare", requirement.ID, func(ctx context.Context) error {
			output, stderr, err := gotoolprofile.RunBounded(ctx, workDir, env, binary, "env", "GOROOT")
			if err != nil || len(stderr) != 0 || !filepath.IsAbs(strings.TrimSpace(string(output))) {
				return fmt.Errorf("actual mode GOROOT: %v; %s", err, stderr)
			}
			actualRoot := strings.TrimSpace(string(output))
			if goRoot != "" && goRoot != actualRoot {
				return fmt.Errorf("mode source root changed")
			}
			goRoot = actualRoot
			plan.instrumentationGoRoot = actualRoot
			markerKey, err := json.Marshal(struct {
				Target, CGO string
				Mode        gotoolprofile.InstrumentationMode
				Overrides   map[string]string
			}{requirement.Target, requirement.CGO, requirement.Mode, requirement.Overrides})
			if err != nil {
				return err
			}
			id := observedRequests[string(markerKey)]
			if id == "" {
				outcome.Stage = "early_rules"
				earlyDir := filepath.Join(modeRoot, fmt.Sprintf("early-%04d", index))
				if err := os.Mkdir(earlyDir, 0700); err != nil {
					return err
				}
				early, excluded, err := gotoolprofile.CaptureInstrumentationScopeObservation(ctx, binary, earlyDir, env, requirement.Target, requirement.Mode, requirement.CGO, requirement.Overrides, requirement.Tags, gotoolprofile.RunBounded)
				if err != nil {
					return err
				}
				if early.Status != gotoolprofile.InstrumentationEarlyRuleAccepted {
					inventory := proof.Sources[requirement.Directory]
					if inventory == nil {
						input := discoveryInstrumentationBaselineInput(plan, early.BaselineFeatures, download.Dir, nil)
						inventory, err = gotoolprofile.CaptureInstrumentationOriginalSourceInventory(input, requirement.Directory)
						if err != nil {
							return fmt.Errorf("official rule original source binding: %w", err)
						}
						proof.Sources[requirement.Directory] = inventory
					}
					candidate := *outcome
					candidate.TargetExclusion, candidate.Status = excluded, discoveryInstrumentationExcludedStatus
					if err := validateDiscoveryInstrumentationTargetExclusion(plan, requirement, candidate, profiles); err != nil {
						return err
					}
					*outcome = candidate
					return nil
				}
				markerDir := filepath.Join(modeRoot, fmt.Sprintf("marker-%04d", index))
				outcome.Stage = "marker_export"
				if err := os.Mkdir(markerDir, 0700); err != nil {
					return err
				}
				observation, err := gotoolprofile.CaptureInstrumentationExportObservation(ctx, binary, markerDir, env, requirement.Target, requirement.Mode, requirement.CGO, requirement.Overrides, gotoolprofile.RunBounded)
				if err != nil {
					return err
				}
				id = gotoolprofile.InstrumentationEarlyProfileID(observation.Early)
				if _, duplicate := proof.Observations[id]; duplicate {
					return fmt.Errorf("conflicting actual mode observation identity")
				}
				proof.Observations[id] = observation
				observedRequests[string(markerKey)] = id
			}
			outcome.ObservationID = id
			observation := proof.Observations[id]
			if err := validateDiscoveryInstrumentationObservation(requirement, profiles, observation); err != nil {
				return err
			}
			input := discoveryInstrumentationOriginalInput(plan, observation, download.Dir, nil)
			inventory := proof.Sources[requirement.Directory]
			outcome.Stage = "original_sources"
			if inventory == nil {
				inventory, err = gotoolprofile.CaptureInstrumentationOriginalSourceInventory(input, requirement.Directory)
				if err != nil {
					return err
				}
				proof.Sources[requirement.Directory] = inventory
			}
			outcome.Stage = "original_selection"
			packagePlan, err := gotoolprofile.PlanInstrumentationOriginalPackage(input, inventory, observation.Early, requirement.Directory, requirement.Tags)
			if err != nil {
				return err
			}
			for _, file := range packagePlan.SFiles {
				selected[file] = true
			}
			return nil
		})
		if stageErr != nil {
			outcome.Error = stageErr.Error()
			runErr = errors.Join(runErr, stageErr)
		}
	}
	for index, requirement := range proof.Requirements {
		prepareRequirement(index, requirement)
	}
	if len(selected) != 0 {
		if err := cfg.runPhaseOperation(candidate, "instrumentation_planning", "", func(ctx context.Context) error {
			var err error
			proof.CPPInputs, err = captureDiscoveryDeferredCPPInputs(plan, download.Dir, goRoot, sortedDiscoverySet(selected), ctx)
			if err != nil {
				return err
			}
			if err := verifyDiscoveryCPPModuleZIP(proof.CPPInputs, plan, download.Zip); err != nil {
				return err
			}
			proof.headerPlanningCapture, err = captureDiscoveryInstrumentationHeaderPlanning(ctx, cfg, candidate, download, plan, profiles, modeRoot, binary, goRoot, env)
			if err != nil {
				return err
			}
			defer func() { proof.headerPlanningCapture = nil }()
			proof.CPPRequirements, err = planDiscoveryInstrumentationCPPRequirements(plan, discoveryInstrumentationBaselines(profiles), candidate.AsmFiles, ctx)
			return err
		}); err != nil {
			for index := range proof.Outcomes {
				if proof.Outcomes[index].Error == "" && proof.Outcomes[index].Status != discoveryInstrumentationExcludedStatus {
					proof.Outcomes[index].Stage, proof.Outcomes[index].Error = "cpp_registration", err.Error()
				}
			}
			return 0, errors.Join(runErr, err)
		}
	}
	registeredFiles := sortedDiscoverySet(selected)
	for _, requirement := range proof.CPPRequirements {
		index := len(proof.Outcomes)
		proof.Outcomes = append(proof.Outcomes, discoveryInstrumentationOutcome{
			RequirementID: requirement.ID, Status: "failed", Stage: "environment",
		})
		prepareRequirement(index, requirement)
	}
	if !equalDiscoveryStrings(registeredFiles, sortedDiscoverySet(selected)) {
		return 0, errors.Join(runErr, fmt.Errorf("mode CPU selection introduced an unregistered original CPP root"))
	}
	for index, requirement := range discoveryInstrumentationAllRequirements(proof) {
		outcome := &proof.Outcomes[index]
		if outcome.Error != "" || outcome.Status == discoveryInstrumentationExcludedStatus {
			continue
		}
		stageErr := cfg.runPhaseOperation(candidate, "instrumentation_consume", requirement.ID, func(ctx context.Context) error {
			observation := proof.Observations[outcome.ObservationID]
			outcome.Stage = "original_selection"
			input := discoveryInstrumentationOriginalInput(plan, observation, download.Dir, nil)
			inventory := proof.Sources[requirement.Directory]
			packagePlan, err := gotoolprofile.PlanInstrumentationOriginalPackage(input, inventory, observation.Early, requirement.Directory, requirement.Tags)
			if err != nil {
				return err
			}
			input.AsmFiles = append([]string(nil), packagePlan.SFiles...)
			// The complete selected assembly is part of the original input SHA;
			// derive again instead of editing the recorded planning identity.
			packagePlan, err = gotoolprofile.PlanInstrumentationOriginalPackage(input, inventory, observation.Early, requirement.Directory, requirement.Tags)
			if err != nil {
				return err
			}
			outcome.PackagePlan = packagePlan
			dir := filepath.Join(modeRoot, fmt.Sprintf("consume-%04d", index))
			outcome.Stage = "original_graph"
			if err := os.Mkdir(dir, 0700); err != nil {
				return err
			}
			execution, err := makeDiscoveryExecutionPlan(candidate, modulePath)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(execution.GoMod), 0600); err != nil {
				return err
			}
			modeEnv := ordinaryProfileEnvironment(env, observation.Early.BaselineFeatures)
			modeEnv = replaceEnv(modeEnv, observation.Early.Environment)
			modeEnv = replaceEnv(modeEnv, map[string]string{"GOENV": "off"})
			rejectOriginalSource := func(cause error) error {
				// A layout-parser error alone cannot exclude a mode. Only the
				// same SDK's actual compiler and independently replayed original
				// declarations can establish this separate zero-object outcome.
				if err := prepareDiscoveryInstrumentationRejectedModule(ctx, binary, dir, modeEnv, modulePath, download); err != nil {
					return fmt.Errorf("original mode declaration: %w; exact invocation setup: %v", cause, err)
				}
				rejection, rejectionErr := gotoolprofile.CaptureInstrumentationSourceRejection(ctx, binary, dir, modeEnv,
					input, inventory, observation, packagePlan, gotoolprofile.RunBounded)
				if rejectionErr != nil {
					return fmt.Errorf("original mode declaration: %w; no independently proved source refusal: %v", cause, rejectionErr)
				}
				if err := verifyDiscoveryCPPInputsUnchanged(proof.CPPInputs, download.Dir, goRoot); err != nil {
					return err
				}
				outcome.SourceRejection = rejection
				outcome.Status, outcome.Stage = discoveryInstrumentationSourceRejectedStatus, "original_source_rejection"
				return nil
			}
			wrapped, err := gotoolprofile.NewInstrumentationConsumerInput(input, inventory, observation, packagePlan)
			if err != nil {
				return rejectOriginalSource(err)
			}
			needed, err := gotoolprofile.InstrumentationRequiresTypeSources(wrapped)
			if err != nil {
				return rejectOriginalSource(err)
			}
			modules, err := captureDiscoveryInstrumentationTypeModules(ctx, binary, dir, modeEnv, wrapped)
			if err != nil {
				return err
			}
			var foreignGuard *gotoolprofile.InstrumentationTypeModuleGuard
			if needed || len(modules) != 0 {
				foreignGuard, err = gotoolprofile.BindInstrumentationTypeModuleSources(ctx, binary, dir, modeEnv, modules, gotoolprofile.RunBounded)
				if err != nil {
					return err
				}
				wrapped.TypeSources, err = gotoolprofile.CaptureInstrumentationTypeSourcesWithModules(ctx, binary, dir, modeEnv, wrapped, modules, gotoolprofile.RunBounded)
				if err != nil {
					return err
				}
				outcome.TypeSources = wrapped.TypeSources
			}
			inputPath := filepath.Join(dir, "input.json")
			data, err := json.Marshal(wrapped)
			if err != nil {
				return err
			}
			if err := os.WriteFile(inputPath, data, 0600); err != nil {
				return err
			}
			queryPath, objectPath := filepath.Join(dir, "query.json"), filepath.Join(dir, "objects.json")
			goos, goarch, _ := strings.Cut(requirement.Target, "/")
			common := []string{
				"-instrumentation-profile=" + inputPath, "-instrumentation-package-dir=" + requirement.Directory,
				"-goos=" + goos, "-goarch=" + goarch, "-module-path=" + modulePath,
				"-patterns=" + packagePlan.PackagePath, "-asm-files=" + strings.Join(packagePlan.SFiles, ","),
				"-strict-load=true", "-keep-going=false", "-feature-timeout=" + cfg.CandidateTimeout.String(),
			}
			if len(requirement.Tags) != 0 {
				common = append(common, "-tags="+strings.Join(requirement.Tags, ","))
			}
			queryArgs := append(append([]string(nil), common...), "-metadata-only", "-out="+filepath.Join(dir, "query"), "-report="+queryPath)
			outcome.Stage = "metadata_query"
			if err := runCapturedCommand(ctx, dir, modeEnv, cfg.Translator, queryArgs...); err != nil {
				return fmt.Errorf("actual same-mode metadata/header/declaration query: %w", err)
			}
			outcome.Query, err = readDiscoveryInstrumentationInvocation(queryPath, wrapped, gotoolprofile.InstrumentationMetadataQuery, nil, nil)
			if err != nil {
				return err
			}
			objectArgs := append(append([]string(nil), common...), "-instrumentation-metadata="+queryPath,
				"-compile", "-keep-obj", "-llc-opt-level=0", "-out="+filepath.Join(dir, "objects"), "-report="+objectPath)
			outcome.Stage = "llvm_objects"
			if err := runCapturedCommand(ctx, dir, modeEnv, cfg.Translator, objectArgs...); err != nil {
				return fmt.Errorf("actual same-mode CPP/LLVM objects: %w", err)
			}
			llvmVersion, stderr, err := gotoolprofile.RunBounded(ctx, dir, modeEnv, cfg.LLC, "--version")
			if err != nil || len(stderr) != 0 {
				return fmt.Errorf("actual LLVM22 tool identity: %v; %s", err, stderr)
			}
			llvmSHA, err := gotoolprofile.FileSHA256(cfg.LLC)
			if err != nil {
				return err
			}
			// The target triple is independently recomputed by the strict shared
			// reader. Only the actual executed tool's version/SHA is supplied.
			var raw gotoolprofile.InstrumentationInvocationProof
			data, err = os.ReadFile(objectPath)
			if err != nil || json.Unmarshal(data, &raw) != nil || raw.LLVM == nil {
				return fmt.Errorf("mode objects lack a structured actual LLVM result")
			}
			llvm := &gotoolprofile.InstrumentationLLVMTool{Version: string(llvmVersion), SHA256: llvmSHA, Triple: raw.LLVM.Triple}
			outcome.Objects, err = readDiscoveryInstrumentationInvocation(objectPath, wrapped, gotoolprofile.InstrumentationObjectCompile, outcome.Query.Metadata, llvm)
			if err != nil {
				return err
			}
			if err := verifyDiscoveryCPPInputsUnchanged(proof.CPPInputs, download.Dir, goRoot); err != nil {
				return err
			}
			outcome.Stage = "physical_readback"
			if foreignGuard != nil {
				if err := foreignGuard.Verify(ctx); err != nil {
					return err
				}
			}
			if err := verifyDiscoveryInstrumentationPhysicalOutputs(filepath.Join(dir, "objects"), outcome.Objects); err != nil {
				return err
			}
			outcome.Status = "llvm_objects_only"
			outcome.Stage = "complete"
			objects += outcome.Objects.ObjectCount
			return nil
		})
		if stageErr != nil {
			outcome.Error = stageErr.Error()
			runErr = errors.Join(runErr, stageErr)
		}
	}
	if discoveryInstrumentationTargetExclusions(plan) == len(discoveryInstrumentationAllRequirements(proof)) {
		runErr = errors.Join(runErr, fmt.Errorf("all required instrumentation modes are officially target-excluded; no compiled candidate objects"))
	}
	return objects, runErr
}

func discoveryInstrumentationOriginalInput(plan *discoveryOrdinarySelectionPlan, observation *gotoolprofile.InstrumentationExportObservation, root string, files []string) *gotoolprofile.ConsumerInput {
	return discoveryInstrumentationBaselineInput(plan, observation.Early.BaselineFeatures, root, files)
}

func discoveryInstrumentationBaselineInput(plan *discoveryOrdinarySelectionPlan, baseline *discoveryTargetFeatures, root string, files []string) *gotoolprofile.ConsumerInput {
	profile := discoveryFeatureProfile{ID: discoveryFeatureProfileID(baseline), Observed: baseline}
	modulePath, _ := discoveryInstrumentationModulePath(plan)
	// Invalid metadata produces an invalid input; actual and portable callers
	// report the specific namespace error before consuming this construction.
	input := ordinaryProfileConsumerInput(plan, profile, modulePath, root, files)
	// Original source protocols remain intact; a separate complete raw CPP
	// graph supplies mode resources, never an ordinary header or export.
	if cpp := plan.InstrumentationPlan.CPPInputs; cpp != nil {
		for id, source := range cpp.Sources {
			if name, tool := strings.CutPrefix(id, "tool/"); tool {
				input.ToolSources[name] = source.SHA256
			} else if name, original := strings.CutPrefix(id, "module/"); original {
				if old := input.Sources[name]; old != "" && old != source.SHA256 {
					input.Sources[name] = ""
				} else {
					input.Sources[name] = source.SHA256
				}
			}
		}
		for _, unit := range cpp.Units {
			for _, miss := range unit.PackageSearchMisses {
				if miss.Protocol != gotoolprofile.CPPPackageSearchMissProtocol {
					continue
				}
				if !containsInstrumentationSearchMiss(input.CPPIncludeSearchMisses, miss) {
					input.CPPIncludeSearchMisses = append(input.CPPIncludeSearchMisses, miss)
				}
			}
		}
		gotoolprofile.SortCPPIncludeSearch(input.CPPIncludeSearchMisses)
		if cpp.Protocol == discoveryReplayCPPInputsProtocol {
			graphInput, err := discoveryCPPOriginalConsumerInput(cpp)
			input.CPPSourceProtocol = gotoolprofile.CPPOriginalReplayProtocol
			input.CPPOriginals = nil
			if err == nil {
				input.CPPOriginals = graphInput.CPPOriginals
				input.CPPIncludeSearchMisses = graphInput.CPPIncludeSearchMisses
			}
		}
	}
	return input
}

func containsInstrumentationSearchMiss(all []gotoolprofile.CPPPackageSearchMiss, miss gotoolprofile.CPPPackageSearchMiss) bool {
	for _, old := range all {
		if reflect.DeepEqual(old, miss) {
			return true
		}
	}
	return false
}

func readDiscoveryInstrumentationInvocation(file string, input *gotoolprofile.InstrumentationConsumerInput, phase gotoolprofile.InstrumentationInvocationPhase, producer *gotoolprofile.InstrumentationMetadataProof, llvm *gotoolprofile.InstrumentationLLVMTool) (*gotoolprofile.InstrumentationInvocationProof, error) {
	reader, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	proof, readErr := gotoolprofile.DecodeInstrumentationInvocation(reader, input, phase, producer, llvm)
	return proof, errors.Join(readErr, reader.Close())
}

func verifyDiscoveryInstrumentationPhysicalOutputs(root string, proof *gotoolprofile.InstrumentationInvocationProof) error {
	if proof == nil || proof.Consumption == nil || proof.Consumption.Protocol != gotoolprofile.InstrumentationConsumptionProtocol {
		return fmt.Errorf("mode physical readback lacks its independent object proof")
	}
	budget := &gotoolprofile.InstrumentationLLVMArtifactBudget{}
	for index, file := range proof.Consumption.Files {
		actual, err := gotoolprofile.CaptureInstrumentationLLVMArtifacts(root, index, budget)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(actual, file.Artifacts) || file.Output.IR != actual.IR.SHA256 ||
			file.Output.Object != actual.Object.SHA256 || file.Output.Part != actual.IR.Name {
			return fmt.Errorf("mode physical LLVM artifacts differ from their exact role/result")
		}
	}
	return nil
}
