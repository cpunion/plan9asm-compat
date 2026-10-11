package main

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

const discoveryProgressSchema = 3

// A failed command's display text can contain private runner and cache paths.
// Keep its exact digest and stage in progress; the frozen report retains the
// original diagnostic. Neither display form supplies source/object authority.
// Copy only the edited nodes so collecting progress cannot alter raw evidence.
func summarizeDiscoverySelectionFailures(plan *discoveryOrdinarySelectionPlan) *discoveryOrdinarySelectionPlan {
	if plan == nil || plan.InstrumentationPlan == nil {
		return plan
	}
	result := *plan
	proof := *plan.InstrumentationPlan
	proof.Outcomes = append([]discoveryInstrumentationOutcome(nil), proof.Outcomes...)
	for index := range proof.Outcomes {
		outcome := &proof.Outcomes[index]
		if outcome.Error != "" && (outcome.Status == "failed" || outcome.Status == "early_target_rejected") {
			digest := sha256.Sum256([]byte(outcome.Error))
			outcome.Error = discoveryInstrumentationFailurePrefix(*outcome) + fmt.Sprintf("%x", digest)
		}
	}
	result.InstrumentationPlan = &proof
	return &result
}

func discoveryInstrumentationFailurePrefix(outcome discoveryInstrumentationOutcome) string {
	return outcome.Stage + " " + outcome.Status + "; raw_diagnostic_sha256="
}

// The ledger is a portable committed view, not a second raw log. Reject an
// uncompact failure instead of allowing a caller to bypass the collector.
func validateDiscoverySelectionFailureSummaries(plan *discoveryOrdinarySelectionPlan) error {
	if plan == nil || plan.InstrumentationPlan == nil {
		return nil
	}
	for _, outcome := range plan.InstrumentationPlan.Outcomes {
		if outcome.Error == "" {
			continue // The independent outcome validator rejects missing diagnostics.
		}
		prefix := discoveryInstrumentationFailurePrefix(outcome)
		if outcome.Status != "failed" && outcome.Status != "early_target_rejected" ||
			!strings.HasPrefix(outcome.Error, prefix) || !discoverySHA256Pattern.MatchString(strings.TrimPrefix(outcome.Error, prefix)) {
			return fmt.Errorf("assembly ledger instrumentation failure lacks a portable stage/diagnostic summary")
		}
	}
	return nil
}

// Raw matrix reports use absolute paths into their disposable module cache.
// Persist the matching scan-inventory path, never the runner's cache prefix.
func summarizeDiscoveryTargetSkips(candidate discoveryCandidate, items []matrixTargetNotApplicableItem) ([]matrixTargetNotApplicableItem, error) {
	result := append([]matrixTargetNotApplicableItem(nil), items...)
	for i := range result {
		item := &result[i]
		reported := strings.ReplaceAll(item.AsmFile, "\\", "/")
		matched := ""
		for _, file := range candidate.AsmFiles {
			if (reported == file || strings.HasSuffix(reported, "/"+file)) && len(file) > len(matched) {
				matched = file
			}
		}
		if matched == "" {
			return nil, fmt.Errorf("target skip file %q is absent from %s's scan inventory", item.AsmFile, candidate.exactKey())
		}
		item.AsmFile = matched
		item.Reason = discoveryTargetSkipReason(*item)
	}
	return result, nil
}

func discoveryTargetSkipReason(item matrixTargetNotApplicableItem) string {
	return fmt.Sprintf("%s: TEXT argument size disagrees with the Go declaration: got %d, want %d",
		item.Symbol, item.DeclaredArgSize, item.ExpectedArgSize)
}

// The raw shard report keeps the full Go diagnostic. The committed ledger
// keeps only stable, reviewable scope and classification: raw diagnostics can
// contain runner-specific cache paths and differ across otherwise equivalent
// runs.
type discoverySourceSkipSummary struct {
	ProfileID  string                            `json:"profile_id,omitempty"`
	BuildTags  []string                          `json:"build_tags,omitempty"`
	AsmFile    string                            `json:"asm_file,omitempty"`
	AsmFiles   []string                          `json:"asm_files,omitempty"`
	Targets    []string                          `json:"targets"`
	Kind       string                            `json:"kind"`
	Reason     string                            `json:"reason"`
	Diagnostic *discoverySourceDiagnosticWitness `json:"diagnostic,omitempty"`
}

func discoverySourceSkipReason(kind string) string {
	switch kind {
	case discoverySourceNotApplicableGoAssembler:
		return "Go 1.27 assembler rejected this source on all supported targets"
	case discoverySourceNotApplicableNoGoPackage:
		return "no current Go package selects this assembly source"
	case discoveryDocumentationKind:
		return discoveryDocumentationReason
	case discoverySourceNotApplicableGoBuild:
		return "Go 1.27 package build rejected this target"
	case discoverySourceNotApplicableAsmDecl:
		return "Go 1.27 asmdecl rejected the source or ABI for this target"
	case discoverySourceNotApplicableNoSymbols:
		return "Go 1.27 assembler emitted no symbols for this source"
	case discoverySourceNotApplicableFortranLoader:
		return "Go 1.27 CGO=0 loader rejected the original package's selected Fortran resources"
	case discoverySourceNotApplicableMixedPackage:
		return "Go 1.27 loader rejected conflicting original selected Go package clauses"
	case discoverySourceNotApplicableSDKNamespace:
		return "Go 1.27 loader rejected the exact original module and stock SDK namespace collision"
	case nativeLayoutGoAssemblerTarget:
		return "Go 1.27 assembler rejected this source for this target"
	default:
		return ""
	}
}

func summarizeDiscoverySourceSkips(items []discoverySourceNotApplicableItem) []discoverySourceSkipSummary {
	if len(items) == 0 {
		return nil
	}
	summaries := make([]discoverySourceSkipSummary, 0, len(items))
	for _, item := range items {
		var diagnostic *discoverySourceDiagnosticWitness
		if discoverySourceRejectionRequiresDiagnostic(item.Kind) {
			diagnostic = captureDiscoverySourceDiagnostic(item.Reason)
		}
		summaries = append(summaries, discoverySourceSkipSummary{
			ProfileID:  item.ProfileID,
			BuildTags:  append([]string(nil), item.BuildTags...),
			AsmFile:    item.AsmFile,
			AsmFiles:   append([]string(nil), item.AsmFiles...),
			Targets:    append([]string(nil), item.Targets...),
			Kind:       item.Kind,
			Reason:     discoverySourceSkipReason(item.Kind),
			Diagnostic: diagnostic,
		})
	}
	return summaries
}

type discoveryCandidateProgress struct {
	Module                          string                                `json:"module"`
	Version                         string                                `json:"version"`
	Status                          string                                `json:"status"`
	Translations                    int                                   `json:"translations,omitempty"`
	InstrumentationTranslations     int                                   `json:"instrumentation_translations,omitempty"`
	InstrumentationTargetExclusions int                                   `json:"instrumentation_target_exclusions,omitempty"`
	NotApplicableTranslations       int                                   `json:"not_applicable_translations,omitempty"`
	NotApplicableItems              []matrixTargetNotApplicableItem       `json:"not_applicable_items,omitempty"`
	SourceNotApplicableItems        []discoverySourceSkipSummary          `json:"source_not_applicable_items,omitempty"`
	NotApplicableReason             string                                `json:"not_applicable_reason,omitempty"`
	InvalidSourceReason             string                                `json:"invalid_source_reason,omitempty"`
	InvalidSourceEvidence           []discoveryInvalidMachineCodeEvidence `json:"invalid_source_evidence,omitempty"`
	Superseded                      *discoverySupersededSkip              `json:"superseded,omitempty"`
	PrivateExtension                *discoveryPrivateExtensionSkip        `json:"private_extension,omitempty"`
	NativeLayout                    *discoveryNativeLayoutSkip            `json:"native_layout,omitempty"`
	NativeLayoutPlan                *discoveryNativeLayoutPlan            `json:"native_layout_plan,omitempty"`
	OrdinarySelectionPlan           *discoveryOrdinarySelectionPlan       `json:"ordinary_selection_plan,omitempty"`
	FeatureProfiles                 []discoveryFeatureProfileReference    `json:"feature_profiles,omitempty"`
	FeatureConsumption              []*gotoolprofile.SelectionProof       `json:"feature_consumption,omitempty"`
	// Source-selection proofs persist their exact scopes for ledger replay.
	DiscoveredAsmFiles  []string                      `json:"discovered_asm_files,omitempty"`
	ApplicableAsmFiles  []string                      `json:"applicable_asm_files,omitempty"`
	BuildConfigurations []discoveryBuildConfiguration `json:"build_configurations,omitempty"`
}

// This is a derived view, not a mutable flag attached to a scanned version.
// Keeping test evidence outside the immutable scan ledger avoids making a
// report invalidate its own input fingerprint when it is published.
type discoveryProgress struct {
	SchemaVersion             int                          `json:"schema_version"`
	ValidationKind            string                       `json:"validation_kind"`
	Source                    discoverySourceIdentity      `json:"source"`
	LedgerSHA256              string                       `json:"ledger_sha256"`
	Targets                   []string                     `json:"targets"`
	Provenance                *discoveryCorpusProvenance   `json:"provenance,omitempty"`
	ShardCount                int                          `json:"shard_count"`
	ReportedShards            int                          `json:"reported_shards"`
	PassedShards              int                          `json:"passed_shards"`
	FailedShards              int                          `json:"failed_shards"`
	PartialShards             []int                        `json:"partial_shards"`
	PendingShards             []int                        `json:"pending_shards"`
	CandidateTotal            int                          `json:"candidate_total"`
	Passed                    int                          `json:"passed"`
	Failed                    int                          `json:"failed"`
	NotApplicable             int                          `json:"not_applicable"`
	SkippedInvalidSource      int                          `json:"skipped_invalid_source"`
	SkippedSuperseded         int                          `json:"skipped_superseded"`
	SkippedPrivateExtension   int                          `json:"skipped_private_extension"`
	SkippedNativeLayout       int                          `json:"skipped_native_layout"`
	Pending                   int                          `json:"pending"`
	DiscoveredAsmFiles        int                          `json:"discovered_asm_files"`
	Translations              int                          `json:"translations"`
	ModeTranslations          int                          `json:"instrumentation_translations,omitempty"`
	ModeTargetExclusions      int                          `json:"instrumentation_target_exclusions,omitempty"`
	NotApplicableTranslations int                          `json:"not_applicable_translations"`
	Complete                  bool                         `json:"complete"`
	Verified                  bool                         `json:"verified"`
	Candidates                []discoveryCandidateProgress `json:"candidates"`
	FeatureInventory          *discoveryFeatureInventory   `json:"feature_inventory"`
}

func collectDiscoveryProgress(ledgerPath, reportsPath string, targets []string, source discoverySourceIdentity, shardCount int, repoRoot ...string) (discoveryProgress, error) {
	if shardCount < 0 {
		return discoveryProgress{}, fmt.Errorf("invalid discovery shard count %d", shardCount)
	}
	if len(repoRoot) > 1 {
		return discoveryProgress{}, fmt.Errorf("discovery progress accepts at most one repository root")
	}
	var skips map[string]discoveryInvalidMachineCodeSkip
	var superseded map[string]discoverySupersededSkip
	var privateExtensions map[string]discoveryPrivateExtensionSkip
	var nativeLayouts map[string]discoveryNativeLayoutSkip
	if len(repoRoot) == 1 {
		var err error
		skips, err = loadInvalidMachineCodeSkips(repoRoot[0])
		if err != nil {
			return discoveryProgress{}, err
		}
		if skips == nil {
			skips = map[string]discoveryInvalidMachineCodeSkip{}
		}
		superseded, err = loadSupersededSkips(repoRoot[0], ledgerPath)
		if err != nil {
			return discoveryProgress{}, err
		}
		if superseded == nil {
			superseded = map[string]discoverySupersededSkip{}
		}
		privateExtensions, err = loadPrivateExtensionSkips(repoRoot[0], ledgerPath)
		if err != nil {
			return discoveryProgress{}, err
		}
		if privateExtensions == nil {
			privateExtensions = map[string]discoveryPrivateExtensionSkip{}
		}
		nativeLayouts, err = loadNativeLayoutSkips(repoRoot[0], ledgerPath)
		if err != nil {
			return discoveryProgress{}, err
		}
		if nativeLayouts == nil {
			nativeLayouts = map[string]discoveryNativeLayoutSkip{}
		}
	}
	progress := discoveryProgress{
		SchemaVersion:    discoveryProgressSchema,
		ValidationKind:   "translation_and_llvm22_object_compilation",
		Source:           source,
		Targets:          append([]string(nil), targets...),
		ShardCount:       shardCount,
		PartialShards:    []int{},
		PendingShards:    []int{},
		Candidates:       []discoveryCandidateProgress{},
		FeatureInventory: newDiscoveryFeatureInventory(),
	}
	if err := auditDiscoveryCorpusReports(ledgerPath, reportsPath, targets, source, skips, superseded, privateExtensions, nativeLayouts, &progress); err != nil {
		// Never return a plausible partial total after detecting corrupt evidence.
		return discoveryProgress{}, err
	}
	return progress, nil
}
