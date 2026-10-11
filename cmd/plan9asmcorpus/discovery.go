package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/llgo-compat/plan9asm/internal/discoverymeta"
	"github.com/llgo-compat/plan9asm/internal/gotoolchain"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

const discoveryReportSchema = 12

const (
	discoveryStatusPassed                  = "passed"
	discoveryStatusFailed                  = "failed"
	discoveryStatusNotApplicable           = "not_applicable"
	discoveryStatusSkippedInvalidSource    = "skipped_invalid_source"
	discoveryStatusSkippedSuperseded       = "skipped_superseded"
	discoveryStatusSkippedPrivateExtension = "skipped_private_extension"
	discoveryStatusSkippedNativeLayout     = "skipped_native_layout"
)

type discoveryRecord struct {
	Kind          string   `json:"kind"`
	Module        string   `json:"module"`
	Version       string   `json:"version"`
	Architectures []string `json:"architectures,omitempty"`
	AsmFiles      []string `json:"asm_files,omitempty"`
}

type discoveryCandidate struct {
	Module        string   `json:"module"`
	Version       string   `json:"version"`
	Architectures []string `json:"architectures"`
	AsmFiles      []string `json:"asm_files"`
}

func (c discoveryCandidate) exactKey() string {
	return c.Module + "@" + c.Version
}

type discoveryCorpusConfig struct {
	featureMarkerDir string
	featureCache     *discoveryFeatureObservationCache
	LedgerPath       string
	RepoRoot         string
	TranslatorRoot   string
	Translator       string
	LLC              string
	Targets          []string
	FilterTargets    bool
	ShardIndex       int
	ShardCount       int
	ExactCandidates  []string
	CandidateTimeout time.Duration
	ReportPath       string
	EventsPath       string
	phaseEvents      *discoveryPhaseJournal
	// Defaults to a shard-owned cache. A caller may provide an existing shared
	// directory, which runDiscoveryCorpus must never remove.
	buildCache            string
	privateExtensionSkips map[string]discoveryPrivateExtensionSkip
	nativeLayoutSkips     map[string]discoveryNativeLayoutSkip
	embeddedAliases       map[string]discoveryEmbeddedModuleAlias
	// Allows deterministic, offline orchestration tests; the CLI always uses
	// collectDiscoveryProvenance and cannot supply a claimed identity.
	captureProvenance func(discoveryCorpusConfig) (discoveryCorpusProvenance, error)
	runCandidate      func(discoveryCorpusConfig, discoveryCandidate, string) (matrixReport, []string, []discoveryBuildConfiguration, error)
	// A private test clock; command-line callers always use time.Now.
	checkpointNow func() time.Time
}

type discoveryExecutionPlan struct {
	ModulePath string
	Patterns   []string
	GoMod      string
}

type discoveryBuildConfiguration struct {
	ProfileID string   `json:"profile_id,omitempty"`
	BuildTags []string `json:"build_tags,omitempty"`
	Targets   []string `json:"targets"`
	AsmFiles  []string `json:"asm_files"`
}

type discoveryPackageGroup struct {
	Pattern  string
	AsmFiles []string
}

type discoveryTranslationUnit struct {
	Patterns []string
	AsmFiles []string
}

type discoveryPendingTranslation struct {
	Unit        discoveryTranslationUnit
	ReportPath  string
	OutputIndex int
	Invocation  commandInvocation
}

// Separate translator processes release their LLVM contexts on exit. Keep
// overlap small enough to bound peak memory on ordinary CI runners.
const discoveryTranslationParallelism = 2

// A translator process owns LLVM objects for its whole lifetime. One package
// per process bounds the peak for modules with many independent assembly
// packages, while candidate-level accounting still covers every file.
func discoveryTranslationUnits(groups []discoveryPackageGroup) []discoveryTranslationUnit {
	units := make([]discoveryTranslationUnit, 0, len(groups))
	for _, group := range groups {
		if len(group.AsmFiles) == 0 {
			continue
		}
		units = append(units, discoveryTranslationUnit{
			Patterns: []string{group.Pattern},
			AsmFiles: append([]string(nil), group.AsmFiles...),
		})
	}
	return units
}

func validateDiscoveryTranslationUnits(units []discoveryTranslationUnit, expectedFiles []string) error {
	seen := make(map[string]bool, len(expectedFiles))
	for _, unit := range units {
		if len(unit.Patterns) != 1 || unit.Patterns[0] == "" || len(unit.AsmFiles) == 0 {
			return fmt.Errorf("discovery translation unit must contain one package and its assembly")
		}
		for _, file := range unit.AsmFiles {
			if seen[file] {
				return fmt.Errorf("duplicate discovery translation file %s", file)
			}
			seen[file] = true
		}
	}
	if !equalDiscoveryStrings(uniqueSortedDiscoveryStrings(expectedFiles), sortedDiscoverySet(seen)) {
		return fmt.Errorf("discovery translation units do not cover every applicable assembly file")
	}
	return nil
}

const (
	discoverySourceNotApplicableGoAssembler = "go_assembler_rejected_all_supported_targets"
	discoverySourceNotApplicableNoGoPackage = "no_current_go_package"
	discoverySourceNotApplicableGoBuild     = "go_build_rejected_package_target"
	discoverySourceNotApplicableAsmDecl     = "go_vet_asmdecl_rejected_target"
	discoverySourceNotApplicableNoSymbols   = "go_assembler_emits_no_symbols"
)

type discoverySourceNotApplicableItem struct {
	ProfileID  string                            `json:"profile_id,omitempty"`
	BuildTags  []string                          `json:"build_tags,omitempty"`
	AsmFile    string                            `json:"asm_file,omitempty"`
	AsmFiles   []string                          `json:"asm_files,omitempty"`
	Targets    []string                          `json:"targets"`
	Kind       string                            `json:"kind"`
	Reason     string                            `json:"reason"`
	Diagnostic *discoverySourceDiagnosticWitness `json:"diagnostic,omitempty"`
}

type moduleDownloadInfo struct {
	Path     string `json:"Path"`
	Version  string `json:"Version"`
	Dir      string `json:"Dir"`
	GoMod    string `json:"GoMod"`
	Zip      string `json:"Zip"`
	Sum      string `json:"Sum"`
	GoModSum string `json:"GoModSum"`
	Error    string `json:"Error"`
}

type discoveryCorpusResult struct {
	// Only the ledger's internal reconstruction sets this. JSON reports cannot
	// opt out of checking raw compiler diagnostics by supplying a field.
	sourceDiagnosticsCompacted      bool
	featureInventory                *discoveryFeatureInventory
	Module                          string                                `json:"module"`
	Version                         string                                `json:"version"`
	Status                          string                                `json:"status"`
	DiscoveredAsmFiles              []string                              `json:"discovered_asm_files"`
	ApplicableAsmFiles              []string                              `json:"applicable_asm_files"`
	BuildConfigurations             []discoveryBuildConfiguration         `json:"build_configurations,omitempty"`
	Patterns                        []string                              `json:"patterns,omitempty"`
	Translations                    int                                   `json:"translations"`
	InstrumentationTranslations     int                                   `json:"instrumentation_translations,omitempty"`
	InstrumentationTargetExclusions int                                   `json:"instrumentation_target_exclusions,omitempty"`
	NotApplicableTranslations       int                                   `json:"not_applicable_translations,omitempty"`
	NotApplicableItems              []matrixTargetNotApplicableItem       `json:"not_applicable_items,omitempty"`
	SourceNotApplicableItems        []discoverySourceNotApplicableItem    `json:"source_not_applicable_items,omitempty"`
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
	Error                           string                                `json:"error,omitempty"`
}

type discoveryCorpusReport struct {
	SchemaVersion             int                        `json:"schema_version"`
	Partial                   bool                       `json:"partial,omitempty"`
	Provenance                discoveryCorpusProvenance  `json:"provenance"`
	Targets                   []string                   `json:"targets,omitempty"`
	TargetFiltered            bool                       `json:"target_filtered,omitempty"`
	ShardIndex                int                        `json:"shard_index"`
	ShardCount                int                        `json:"shard_count"`
	CandidateTotal            int                        `json:"candidate_total"`
	EligibleCandidates        int                        `json:"eligible_candidates"`
	Selected                  int                        `json:"selected"`
	Passed                    int                        `json:"passed"`
	Failed                    int                        `json:"failed"`
	NotApplicable             int                        `json:"not_applicable"`
	SkippedInvalidSource      int                        `json:"skipped_invalid_source"`
	SkippedSuperseded         int                        `json:"skipped_superseded"`
	SkippedPrivateExtension   int                        `json:"skipped_private_extension"`
	SkippedNativeLayout       int                        `json:"skipped_native_layout"`
	Translations              int                        `json:"translations"`
	ModeTranslations          int                        `json:"instrumentation_translations,omitempty"`
	ModeTargetExclusions      int                        `json:"instrumentation_target_exclusions,omitempty"`
	NotApplicableTranslations int                        `json:"not_applicable_translations"`
	Results                   []discoveryCorpusResult    `json:"results"`
	FeatureInventory          *discoveryFeatureInventory `json:"feature_inventory,omitempty"`
}

// walkDiscoveryRecords validates the complete JSONL input, including every
// matched payload, before handing each transient record to its consumer.
func walkDiscoveryRecords(root string, visit func(discoveryRecord) error) error {
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("stat discovery ledger: %w", err)
	}
	var files []string
	if !info.IsDir() {
		files = []string{root}
	} else {
		files, err = filepath.Glob(filepath.Join(root, "records", "*.jsonl"))
		if err != nil {
			return fmt.Errorf("list discovery ledger records: %w", err)
		}
	}
	if len(files) == 0 {
		return fmt.Errorf("discovery ledger %q contains no JSONL records", root)
	}
	sort.Strings(files)
	for _, filePath := range files {
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("open discovery records %s: %w", filePath, err)
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64<<10), 32<<20)
		line := 0
		for scanner.Scan() {
			line++
			if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
				continue
			}
			var record discoveryRecord
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				file.Close()
				return fmt.Errorf("decode discovery record %s:%d: %w", filePath, line, err)
			}
			if record.Kind == "matched" {
				if err := validateDiscoveryRecord(record); err != nil {
					file.Close()
					return fmt.Errorf("invalid discovery record %s:%d: %w", filePath, line, err)
				}
			}
			if visit != nil {
				if err := visit(record); err != nil {
					file.Close()
					return err
				}
			}
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			return fmt.Errorf("read discovery records %s: %w", filePath, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close discovery records %s: %w", filePath, err)
		}
	}
	return nil
}

func loadDiscoveryCandidates(root string) ([]discoveryCandidate, error) {
	type candidateSets struct {
		candidate discoveryCandidate
		arches    map[string]bool
		asmFiles  map[string]bool
	}
	merged := make(map[string]*candidateSets)
	err := walkDiscoveryRecords(root, func(record discoveryRecord) error {
		if record.Kind != "matched" {
			return nil
		}
		key := record.Module + "@" + record.Version
		item := merged[key]
		if item == nil {
			item = &candidateSets{
				candidate: discoveryCandidate{Module: record.Module, Version: record.Version},
				arches:    make(map[string]bool),
				asmFiles:  make(map[string]bool),
			}
			merged[key] = item
		}
		for _, arch := range record.Architectures {
			item.arches[arch] = true
		}
		for _, asmFile := range record.AsmFiles {
			item.asmFiles[asmFile] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	candidates := make([]discoveryCandidate, 0, len(merged))
	for _, item := range merged {
		for arch := range item.arches {
			item.candidate.Architectures = append(item.candidate.Architectures, arch)
		}
		for asmFile := range item.asmFiles {
			item.candidate.AsmFiles = append(item.candidate.AsmFiles, asmFile)
		}
		sort.Strings(item.candidate.Architectures)
		sort.Strings(item.candidate.AsmFiles)
		candidates = append(candidates, item.candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Module != candidates[j].Module {
			return candidates[i].Module < candidates[j].Module
		}
		return candidates[i].Version < candidates[j].Version
	})
	return candidates, nil
}

func validateDiscoveryRecord(record discoveryRecord) error {
	if record.Module == "" || strings.TrimSpace(record.Module) != record.Module || strings.ContainsAny(record.Module, "\r\n\t ") {
		return fmt.Errorf("invalid module %q", record.Module)
	}
	if record.Version == "" || strings.TrimSpace(record.Version) != record.Version || strings.ContainsAny(record.Version, "\r\n\t ") {
		return fmt.Errorf("invalid version %q", record.Version)
	}
	if len(record.AsmFiles) == 0 {
		return fmt.Errorf("%s@%s has no assembly files", record.Module, record.Version)
	}
	for _, asmFile := range record.AsmFiles {
		if asmFile == "" || strings.Contains(asmFile, "\\") || path.IsAbs(asmFile) || path.Clean(asmFile) != asmFile || strings.HasPrefix(asmFile, "../") || !strings.HasSuffix(asmFile, ".s") {
			return fmt.Errorf("%s@%s has unsafe assembly path %q", record.Module, record.Version, asmFile)
		}
	}
	return nil
}

func selectDiscoveryShard(candidates []discoveryCandidate, shardIndex, shardCount int) []discoveryCandidate {
	if shardCount <= 0 || shardIndex < 0 || shardIndex >= shardCount {
		return nil
	}
	selected := make([]discoveryCandidate, 0, len(candidates)/shardCount+1)
	for _, candidate := range candidates {
		if discoveryCandidateShard(candidate, shardCount) == shardIndex {
			selected = append(selected, candidate)
		}
	}
	return selected
}

func discoveryCandidateShard(candidate discoveryCandidate, shardCount int) int {
	if shardCount <= 0 {
		return -1
	}
	sum := sha256.Sum256([]byte(candidate.exactKey()))
	return int(binary.BigEndian.Uint64(sum[:8]) % uint64(shardCount))
}

func verifyDiscoveryCorpusReports(ledgerPath, reportsPath string, expectedTargets []string, source discoverySourceIdentity, repoRoot ...string) error {
	progress, err := collectDiscoveryProgress(ledgerPath, reportsPath, expectedTargets, source, 0, repoRoot...)
	if err != nil {
		return err
	}
	return requireCompleteDiscoveryProgress(progress, reportsPath)
}

// Only pass the result of the full current audit here. This helper is not a
// public proof reader or a shortcut for validating a persisted progress file.
func requireCompleteDiscoveryProgress(progress discoveryProgress, reportsPath string) error {
	if progress.ReportedShards == 0 {
		return fmt.Errorf("no discovery shard reports found in %q", reportsPath)
	}
	if !progress.Complete {
		return fmt.Errorf("found %d discovery shard reports, want exactly %d complete; %d ledger matches pending", progress.ReportedShards, progress.ShardCount, progress.Pending)
	}
	if progress.Failed != 0 {
		return fmt.Errorf("discovery shards have %d failed candidates", progress.Failed)
	}
	return nil
}

// The passing gate and the progress view deliberately share every integrity
// check. Missing whole shards and genuine failures are useful progress, but
// incomplete, stale or mixed-input reports are never evidence of a pass.
func auditDiscoveryCorpusReports(
	ledgerPath, reportsPath string,
	expectedTargets []string,
	source discoverySourceIdentity,
	skips map[string]discoveryInvalidMachineCodeSkip,
	superseded map[string]discoverySupersededSkip,
	privateExtensions map[string]discoveryPrivateExtensionSkip,
	nativeLayouts map[string]discoveryNativeLayoutSkip,
	progress *discoveryProgress,
) error {
	ledgerSHA, err := discoveryLedgerFingerprint(ledgerPath)
	if err != nil {
		return err
	}
	candidates, err := loadDiscoveryCandidates(ledgerPath)
	if err != nil {
		return err
	}
	expected := make(map[string]discoveryCandidate, len(candidates))
	for _, candidate := range candidates {
		expected[candidate.exactKey()] = candidate
		progress.DiscoveredAsmFiles += len(candidate.AsmFiles)
	}
	progress.CandidateTotal = len(candidates)
	progress.LedgerSHA256 = ledgerSHA
	files, err := discoveryCorpusReportFiles(reportsPath)
	if err != nil && !(progress.ShardCount > 0 && errors.Is(err, os.ErrNotExist)) {
		return err
	}
	seenShards := make(map[int]string)
	partialShards := make(map[int]bool)
	seenCandidates := make(map[string]string, len(candidates))
	outcomes := make(map[string]discoveryCandidateProgress, len(candidates))
	shardCount := progress.ShardCount
	var provenance discoveryCorpusProvenance
	for _, filePath := range files {
		report, err := readDiscoveryCorpusReport(filePath)
		if err != nil {
			return err
		}
		if report.SchemaVersion != discoveryReportSchema {
			return fmt.Errorf("%s: unsupported discovery report schema %d", filePath, report.SchemaVersion)
		}
		if err := validateDiscoveryProvenance(report.Provenance, source, ledgerSHA); err != nil {
			return fmt.Errorf("%s: %w", filePath, err)
		}
		if len(seenShards) != 0 && report.Provenance != provenance {
			return fmt.Errorf("%s: mixed discovery source/toolchain provenance", filePath)
		}
		provenance = report.Provenance
		if err := validateDiscoveryCorpusAccounting(report); err != nil {
			return fmt.Errorf("%s: %w", filePath, err)
		}
		if err := mergeDiscoveryFeatureInventory(progress.FeatureInventory, report.FeatureInventory); err != nil {
			return fmt.Errorf("%s: merge actual feature inventory: %w", filePath, err)
		}
		if len(report.Results) == 0 && (report.Translations != 0 || report.NotApplicableTranslations != 0 || report.ModeTranslations != 0 || report.ModeTargetExclusions != 0) {
			return fmt.Errorf("%s: empty shard has nonzero translation counts", filePath)
		}
		if report.TargetFiltered {
			return fmt.Errorf("%s: target-filtered report cannot prove complete ledger coverage", filePath)
		}
		if !equalDiscoveryStrings(report.Targets, expectedTargets) {
			return fmt.Errorf("%s: targets %v do not match required matrix %v", filePath, report.Targets, expectedTargets)
		}
		if report.CandidateTotal != len(candidates) || report.EligibleCandidates != len(candidates) {
			return fmt.Errorf("%s: candidate totals are total=%d eligible=%d, want %d ledger matches", filePath, report.CandidateTotal, report.EligibleCandidates, len(candidates))
		}
		if report.ShardCount <= 0 || report.ShardIndex < 0 || report.ShardIndex >= report.ShardCount {
			return fmt.Errorf("%s: invalid shard %d/%d", filePath, report.ShardIndex, report.ShardCount)
		}
		if shardCount == 0 {
			shardCount = report.ShardCount
		} else if report.ShardCount != shardCount {
			return fmt.Errorf("%s: shard_count %d does not match %d", filePath, report.ShardCount, shardCount)
		}
		if previous, ok := seenShards[report.ShardIndex]; ok {
			return fmt.Errorf("duplicate discovery shard %d in %s and %s", report.ShardIndex, previous, filePath)
		}
		seenShards[report.ShardIndex] = filePath
		if len(report.Results) != report.Selected {
			return fmt.Errorf("%s: selected=%d but contains %d auditable results", filePath, report.Selected, len(report.Results))
		}
		if want := len(selectDiscoveryShard(candidates, report.ShardIndex, report.ShardCount)); report.Selected != want {
			if !report.Partial || report.Selected > want {
				return fmt.Errorf("%s: shard inventory has %d results, want %d ledger matches", filePath, report.Selected, want)
			}
		} else if report.Partial {
			return fmt.Errorf("%s: partial shard has a complete inventory", filePath)
		}
		for _, result := range report.Results {
			key := result.Module + "@" + result.Version
			switch result.Status {
			case discoveryStatusPassed:
				if result.Translations <= 0 || result.Error != "" {
					return fmt.Errorf("%s: passed result %s requires positive translations and no error", filePath, key)
				}
			case discoveryStatusFailed:
				if strings.TrimSpace(result.Error) == "" {
					return fmt.Errorf("%s: failed result %s has no diagnostic", filePath, key)
				}
			case discoveryStatusNotApplicable:
				if result.Translations != 0 || strings.TrimSpace(result.NotApplicableReason) == "" || result.Error != "" {
					return fmt.Errorf("%s: not-applicable result %s requires a reason, zero successful translations and no error", filePath, key)
				}
			case discoveryStatusSkippedInvalidSource:
				if result.Translations != 0 || result.NotApplicableTranslations != 0 || result.Error != "" ||
					result.InvalidSourceReason == "" || len(result.InvalidSourceEvidence) == 0 {
					return fmt.Errorf("%s: invalid-source skip %s lacks evidence or claims translations", filePath, key)
				}
			case discoveryStatusSkippedSuperseded:
				if result.Translations != 0 || result.NotApplicableTranslations != 0 || result.Error != "" ||
					result.Superseded == nil {
					return fmt.Errorf("%s: superseded skip %s lacks evidence or claims translations", filePath, key)
				}
			case discoveryStatusSkippedPrivateExtension:
				if err := validatePrivateExtensionResult(result); err != nil {
					return fmt.Errorf("%s: private-extension skip %s: %w", filePath, key, err)
				}
			case discoveryStatusSkippedNativeLayout:
				if err := validateNativeLayoutResult(result); err != nil {
					return fmt.Errorf("%s: native-layout skip %s: %w", filePath, key, err)
				}
			}
			candidate, ok := expected[key]
			if !ok {
				return fmt.Errorf("%s: result %s is not a current ledger match", filePath, key)
			}
			if want := discoveryCandidateShard(candidate, report.ShardCount); want != report.ShardIndex {
				return fmt.Errorf("%s: result %s belongs to shard %d/%d, not %d", filePath, key, want, report.ShardCount, report.ShardIndex)
			}
			if previous, ok := seenCandidates[key]; ok {
				return fmt.Errorf("duplicate discovery result %s in %s and %s", key, previous, filePath)
			}
			if !equalDiscoveryStrings(result.DiscoveredAsmFiles, candidate.AsmFiles) {
				return fmt.Errorf("%s: result %s assembly inventory %v does not match ledger %v", filePath, key, result.DiscoveredAsmFiles, candidate.AsmFiles)
			}
			if _, pinned := nativeLayouts[key]; pinned &&
				result.Status != discoveryStatusSkippedNativeLayout && result.Status != discoveryStatusFailed {
				return fmt.Errorf("%s: result %s ignores its pinned native-layout exception", filePath, key)
			}
			if result.Status == discoveryStatusSkippedInvalidSource {
				if !invalidSourceSkipMatchesResult(skips[key], result) {
					return fmt.Errorf("%s: result %s invalid-source skip differs from the pinned manifest", filePath, key)
				}
			}
			if result.Status == discoveryStatusSkippedSuperseded {
				if !supersededSkipMatchesResult(superseded[key], result) {
					return fmt.Errorf("%s: result %s supersession differs from the pinned manifest", filePath, key)
				}
			}
			if result.Status == discoveryStatusSkippedPrivateExtension {
				if !privateExtensionSkipMatchesResult(privateExtensions[key], result) {
					return fmt.Errorf("%s: result %s private-extension skip differs from the pinned manifest", filePath, key)
				}
			}
			if result.Status == discoveryStatusSkippedNativeLayout {
				if !nativeLayoutSkipMatchesResult(nativeLayouts[key], result) {
					return fmt.Errorf("%s: result %s native-layout skip differs from the pinned manifest", filePath, key)
				}
			}
			scope, err := discoveryResultAssemblyScope(result)
			if err != nil {
				return fmt.Errorf("%s: %w", filePath, err)
			}
			testedCandidate := candidate
			testedCandidate.AsmFiles = scope
			targetSkips, err := summarizeDiscoveryTargetSkips(testedCandidate, result.NotApplicableItems)
			if err != nil {
				return fmt.Errorf("%s: %w", filePath, err)
			}
			seenCandidates[key] = filePath
			outcomes[key] = discoveryCandidateProgress{
				Module: result.Module, Version: result.Version, Status: result.Status,
				Translations:                    result.Translations,
				NotApplicableTranslations:       result.NotApplicableTranslations,
				NotApplicableItems:              targetSkips,
				SourceNotApplicableItems:        summarizeDiscoverySourceSkips(result.SourceNotApplicableItems),
				NotApplicableReason:             result.NotApplicableReason,
				InvalidSourceReason:             result.InvalidSourceReason,
				InvalidSourceEvidence:           append([]discoveryInvalidMachineCodeEvidence(nil), result.InvalidSourceEvidence...),
				Superseded:                      result.Superseded,
				PrivateExtension:                result.PrivateExtension,
				NativeLayout:                    result.NativeLayout,
				NativeLayoutPlan:                result.NativeLayoutPlan,
				OrdinarySelectionPlan:           summarizeDiscoverySelectionFailures(result.OrdinarySelectionPlan),
				FeatureProfiles:                 result.FeatureProfiles,
				FeatureConsumption:              result.FeatureConsumption,
				InstrumentationTranslations:     result.InstrumentationTranslations,
				InstrumentationTargetExclusions: result.InstrumentationTargetExclusions,
			}
			if result.NativeLayoutPlan != nil || result.OrdinarySelectionPlan != nil {
				outcome := outcomes[key]
				outcome.DiscoveredAsmFiles = append([]string(nil), result.DiscoveredAsmFiles...)
				outcome.ApplicableAsmFiles = append([]string(nil), result.ApplicableAsmFiles...)
				outcome.BuildConfigurations = result.BuildConfigurations
				outcomes[key] = outcome
			}
		}
		progress.ReportedShards++
		if report.Partial {
			partialShards[report.ShardIndex] = true
			progress.PartialShards = append(progress.PartialShards, report.ShardIndex)
		} else if report.Failed == 0 {
			progress.PassedShards++
		} else {
			progress.FailedShards++
		}
		progress.Passed += report.Passed
		progress.Failed += report.Failed
		progress.NotApplicable += report.NotApplicable
		progress.SkippedInvalidSource += report.SkippedInvalidSource
		progress.SkippedSuperseded += report.SkippedSuperseded
		progress.SkippedPrivateExtension += report.SkippedPrivateExtension
		progress.SkippedNativeLayout += report.SkippedNativeLayout
		progress.Translations += report.Translations
		progress.ModeTranslations += report.ModeTranslations
		progress.ModeTargetExclusions += report.ModeTargetExclusions
		progress.NotApplicableTranslations += report.NotApplicableTranslations
	}
	progress.ShardCount = shardCount
	for shard := 0; shard < shardCount; shard++ {
		if _, ok := seenShards[shard]; !ok || partialShards[shard] {
			progress.PendingShards = append(progress.PendingShards, shard)
		}
	}
	sort.Ints(progress.PartialShards)
	for _, candidate := range candidates {
		outcome, ok := outcomes[candidate.exactKey()]
		if !ok {
			outcome = discoveryCandidateProgress{
				Module: candidate.Module, Version: candidate.Version, Status: "pending",
			}
			progress.Pending++
		}
		progress.Candidates = append(progress.Candidates, outcome)
	}
	if len(seenShards) > 0 {
		progress.Provenance = &provenance
	}
	progress.Complete = shardCount > 0 && len(progress.PendingShards) == 0 && progress.Pending == 0
	progress.Verified = progress.Complete && progress.Failed == 0
	finalLedgerSHA, err := discoveryLedgerFingerprint(ledgerPath)
	if err != nil {
		return err
	}
	if finalLedgerSHA != ledgerSHA {
		return fmt.Errorf("discovery ledger changed while reading reports")
	}
	return nil
}

func discoveryCorpusReportFiles(reportPath string) ([]string, error) {
	info, err := os.Stat(reportPath)
	if err != nil {
		return nil, fmt.Errorf("stat discovery reports: %w", err)
	}
	if !info.IsDir() {
		return []string{reportPath}, nil
	}
	var files []string
	err = filepath.WalkDir(reportPath, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "shard-") && strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, name)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list discovery reports: %w", err)
	}
	sort.Strings(files)
	return files, nil
}

func readDiscoveryCorpusReport(reportPath string) (discoveryCorpusReport, error) {
	discoveryReportMu.RLock()
	defer discoveryReportMu.RUnlock()
	file, err := openDiscoveryReport(reportPath)
	if err != nil {
		return discoveryCorpusReport{}, fmt.Errorf("open discovery report %s: %w", reportPath, err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var report discoveryCorpusReport
	if err := decoder.Decode(&report); err != nil {
		return discoveryCorpusReport{}, fmt.Errorf("decode discovery report %s: %w", reportPath, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return discoveryCorpusReport{}, fmt.Errorf("decode discovery report %s: %w", reportPath, err)
	}
	return report, nil
}

func equalDiscoveryStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func filterDiscoveryCandidatesForTargets(candidates []discoveryCandidate, targets []string) ([]discoveryCandidate, error) {
	filtered := make([]discoveryCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		files, err := discoverymeta.FilterAssemblyFiles(candidate.AsmFiles, targets)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			continue
		}
		candidate.AsmFiles = files
		candidate.Architectures = discoverymeta.ArchitectureHints(files)
		filtered = append(filtered, candidate)
	}
	return filtered, nil
}

func discoveryPackagePatterns(candidate discoveryCandidate) []string {
	return discoveryPackagePatternsForModule(candidate, candidate.Module)
}

func discoveryPackagePatternsForModule(candidate discoveryCandidate, modulePath string) []string {
	groups := discoveryPackageGroupsForModule(candidate, modulePath)
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		out = append(out, group.Pattern)
	}
	return out
}

func discoveryPackageGroupsForModule(candidate discoveryCandidate, modulePath string) []discoveryPackageGroup {
	filesByPattern := make(map[string][]string)
	for _, asmFile := range candidate.AsmFiles {
		dir := path.Dir(asmFile)
		pattern := modulePath
		if dir != "." {
			pattern += "/" + dir
		}
		filesByPattern[pattern] = append(filesByPattern[pattern], asmFile)
	}
	patterns := make([]string, 0, len(filesByPattern))
	for pattern := range filesByPattern {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	groups := make([]discoveryPackageGroup, 0, len(patterns))
	for _, pattern := range patterns {
		groups = append(groups, discoveryPackageGroup{
			Pattern:  pattern,
			AsmFiles: uniqueSortedDiscoveryStrings(filesByPattern[pattern]),
		})
	}
	return groups
}

func makeDiscoveryExecutionPlan(candidate discoveryCandidate, declaredModule string) (discoveryExecutionPlan, error) {
	if declaredModule == "" {
		declaredModule = candidate.Module
	}
	if strings.TrimSpace(declaredModule) != declaredModule || strings.ContainsAny(declaredModule, "\r\n\t ") {
		return discoveryExecutionPlan{}, fmt.Errorf("invalid declared module path %q", declaredModule)
	}
	goMod := fmt.Sprintf("module plan9asm.local/discovery\n\ngo 1.27\n\nrequire %s %s\n", declaredModule, candidate.Version)
	if declaredModule != candidate.Module {
		goMod += fmt.Sprintf("\nreplace %s => %s %s\n", declaredModule, candidate.Module, candidate.Version)
	}
	return discoveryExecutionPlan{
		ModulePath: declaredModule,
		Patterns:   discoveryPackagePatternsForModule(candidate, declaredModule),
		GoMod:      goMod,
	}, nil
}

func parseDeclaredModulePath(contents []byte) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "module") || (len(line) > len("module") && line[len("module")] != ' ' && line[len("module")] != '\t') {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "module"))
		if rest == "" {
			return "", fmt.Errorf("empty module directive")
		}
		var modulePath string
		if rest[0] == '"' || rest[0] == '`' {
			if _, err := fmt.Sscanf(rest, "%q", &modulePath); err != nil {
				return "", fmt.Errorf("parse module directive %q: %w", line, err)
			}
		} else {
			modulePath = strings.Fields(rest)[0]
		}
		if modulePath == "" || strings.ContainsAny(modulePath, "\r\n\t ") {
			return "", fmt.Errorf("invalid module directive path %q", modulePath)
		}
		return modulePath, nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("go.mod has no module directive")
}

func applicableDiscoveryAssemblyFiles(candidate discoveryCandidate, moduleDir string, targets []string) ([]string, error) {
	configs, err := discoveryBuildConfigurations(candidate, moduleDir, targets)
	if err != nil {
		return nil, err
	}
	var applicable []string
	for _, config := range configs {
		applicable = append(applicable, config.AsmFiles...)
	}
	sort.Strings(applicable)
	return applicable, nil
}

func discoveryBuildConfigurations(candidate discoveryCandidate, moduleDir string, targets []string) ([]discoveryBuildConfiguration, error) {
	return discoveryBuildConfigurationsWithEvidence(candidate, moduleDir, targets, nil)
}

func discoveryBuildConfigurationsWithEvidence(candidate discoveryCandidate, moduleDir string, targets []string, sourceNotApplicable *[]discoverySourceNotApplicableItem, nativePlans ...*discoveryNativeLayoutPlan) ([]discoveryBuildConfiguration, error) {
	if moduleDir == "" {
		return nil, fmt.Errorf("%s: downloaded module has no directory", candidate.exactKey())
	}
	contexts := make([]build.Context, 0, len(targets))
	for _, target := range targets {
		goos, goarch, ok := strings.Cut(target, "/")
		if !ok || goos == "" || goarch == "" {
			return nil, fmt.Errorf("invalid discovery target %q", target)
		}
		ctx := build.Default
		ctx.GOOS = goos
		ctx.GOARCH = goarch
		ctx.Compiler = "gc"
		ctx.CgoEnabled = false
		contexts = append(contexts, ctx)
	}
	var nativePlan *discoveryNativeLayoutPlan
	if len(nativePlans) != 0 {
		nativePlan = nativePlans[0]
		nativePlan.GoVersion = runtime.Version()
		nativePlan.Targets = uniqueSortedDiscoveryStrings(targets)
		nativePlan.ReleaseTags = append([]string(nil), build.Default.ReleaseTags...)
		nativePlan.ToolTags = append([]string(nil), build.Default.ToolTags...)
	}

	goFilesByDir := make(map[string][]string)
	invalidGoFilesByDir := make(map[string][]string)
	constraintTagsByFile := make(map[string][]string)
	configsByTargetAndTags := make(map[string]*discoveryBuildConfiguration)
	for _, asmFile := range candidate.AsmFiles {
		dirRel := path.Dir(asmFile)
		var selection *nativeLayoutSourceSelection
		if nativePlan != nil {
			input, err := readNativeLayoutSourceInput(moduleDir, asmFile)
			if err != nil {
				return nil, err
			}
			nativePlan.Selections = append(nativePlan.Selections, nativeLayoutSourceSelection{Assembly: input})
			recordNativeLayoutSourceInput(nativePlan, input)
			selection = &nativePlan.Selections[len(nativePlan.Selections)-1]
		}
		if discoveryDirIsIgnored(dirRel) {
			if selection != nil {
				selection.ExcludedKind = nativeLayoutIgnoredDirectory
				selection.ExcludedReason = "Go ignores this assembly directory"
			}
			continue
		}
		nested, err := discoveryDirIsNestedModule(moduleDir, dirRel)
		if err != nil {
			return nil, err
		}
		if nested {
			if selection != nil {
				selection.ExcludedKind = nativeLayoutNestedModule
				selection.ExcludedReason = "assembly belongs to a nested module"
				selection.NestedModule, err = nativeLayoutNestedModuleInput(moduleDir, dirRel)
				if err != nil {
					return nil, err
				}
				recordNativeLayoutSourceInput(nativePlan, *selection.NestedModule)
			}
			continue
		}
		dir := filepath.Join(moduleDir, filepath.FromSlash(dirRel))
		goFiles, ok := goFilesByDir[dir]
		if !ok {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return nil, fmt.Errorf("read assembly package directory %s: %w", dir, err)
			}
			for _, entry := range entries {
				name := entry.Name()
				if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
					continue
				}
				if _, parseErr := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.PackageClauseOnly); parseErr != nil {
					invalidGoFilesByDir[dir] = append(invalidGoFilesByDir[dir], name)
					continue
				}
				goFiles = append(goFiles, name)
			}
			goFilesByDir[dir] = goFiles
		}
		if selection != nil {
			for _, name := range goFiles {
				input, err := readNativeLayoutSourceInput(moduleDir, path.Join(dirRel, name))
				if err != nil {
					return nil, err
				}
				selection.GoFiles = append(selection.GoFiles, input)
				recordNativeLayoutSourceInput(nativePlan, input)
			}
		}
		if len(goFiles) == 0 {
			if sourceNotApplicable != nil {
				invalid := uniqueSortedDiscoveryStrings(invalidGoFilesByDir[dir])
				reason := "assembly directory contains no non-test Go source accepted by Go 1.27"
				if len(invalid) != 0 {
					reason += "; invalid .go files: " + strings.Join(invalid, ", ")
				}
				*sourceNotApplicable = append(*sourceNotApplicable, discoverySourceNotApplicableItem{
					AsmFile: asmFile,
					Targets: uniqueSortedDiscoveryStrings(targets),
					Kind:    discoverySourceNotApplicableNoGoPackage,
					Reason:  reason,
				})
			}
			if selection != nil {
				selection.ExcludedKind = discoverySourceNotApplicableNoGoPackage
				selection.ExcludedReason = "assembly directory contains no accepted non-test Go source"
			}
			continue
		}
		fileNames := append([]string(nil), goFiles...)
		fileNames = append(fileNames, path.Base(asmFile))
		var customTags []string
		for _, fileName := range fileNames {
			fullPath := filepath.Join(dir, fileName)
			tags, ok := constraintTagsByFile[fullPath]
			if !ok {
				var err error
				tags, err = discoveryConstraintTags(fullPath)
				if err != nil {
					return nil, err
				}
				constraintTagsByFile[fullPath] = tags
			}
			customTags = append(customTags, tags...)
		}
		customTags = uniqueDiscoveryCustomTags(customTags, contexts)
		type contextMatch struct {
			context   build.Context
			target    string
			buildTags []string
		}
		matches := make([]contextMatch, 0, len(contexts))
		for i := range contexts {
			target := contexts[i].GOOS + "/" + contexts[i].GOARCH
			buildTags, ok, err := findDiscoveryBuildTags(
				contexts[i], dir, path.Base(asmFile), goFiles,
				customTags, constraintTagsByFile,
			)
			if err != nil {
				return nil, fmt.Errorf("classify assembly %s: %w", asmFile, err)
			}
			if !ok {
				if selection != nil {
					selection.Decisions = append(selection.Decisions, nativeLayoutSelectionDecision{
						Target: target, Kind: nativeLayoutBuildConstraints,
						Reason: "Go filename or build constraints do not select an assembly/Go source pair",
					})
				}
				continue
			}
			matches = append(matches, contextMatch{context: contexts[i], target: target, buildTags: buildTags})
		}
		matchedContexts := make([]build.Context, 0, len(matches))
		for _, match := range matches {
			matchedContexts = append(matchedContexts, match.context)
		}
		sourcePath := filepath.Join(moduleDir, filepath.FromSlash(asmFile))
		inference, err := inferUnsuffixedAssemblyTargetsWithEvidence(sourcePath, matchedContexts)
		if err != nil {
			return nil, fmt.Errorf("classify assembly source %s: %w", asmFile, err)
		}
		sourceTargets, restrictBySource := inference.eligible, inference.restrict
		for _, match := range matches {
			if restrictBySource && !sourceTargets[match.target] {
				rejection := strings.ReplaceAll(inference.rejected[match.target], sourcePath, asmFile)
				if selection != nil {
					selection.Decisions = append(selection.Decisions, nativeLayoutSelectionDecision{
						Target: match.target, BuildTags: match.buildTags,
						Kind:   nativeLayoutGoAssemblerTarget,
						Reason: rejection,
					})
				}
				if sourceNotApplicable != nil {
					*sourceNotApplicable = append(*sourceNotApplicable, discoverySourceNotApplicableItem{
						AsmFile: asmFile, Targets: []string{match.target}, BuildTags: match.buildTags,
						Kind: nativeLayoutGoAssemblerTarget, Reason: rejection,
					})
				}
				continue
			}
			noSymbols, err := discoveryAssemblyObjectHasNoSymbols(
				filepath.Join(moduleDir, filepath.FromSlash(asmFile)),
				match.context.GOOS, match.context.GOARCH,
			)
			if err != nil {
				return nil, fmt.Errorf("inspect assembly object %s for %s: %w", asmFile, match.target, err)
			}
			if noSymbols {
				if sourceNotApplicable != nil {
					*sourceNotApplicable = append(*sourceNotApplicable, discoverySourceNotApplicableItem{
						AsmFile:   asmFile,
						BuildTags: append([]string(nil), match.buildTags...),
						Targets:   []string{match.target},
						Kind:      discoverySourceNotApplicableNoSymbols,
						Reason:    "current Go assembler accepted the source but emitted no object symbols",
					})
				}
				if selection != nil {
					selection.Decisions = append(selection.Decisions, nativeLayoutSelectionDecision{
						Target: match.target, BuildTags: match.buildTags,
						Kind:   discoverySourceNotApplicableNoSymbols,
						Reason: "current Go assembler emitted no object symbols",
					})
				}
				continue
			}
			if selection != nil {
				selection.Decisions = append(selection.Decisions, nativeLayoutSelectionDecision{
					Target: match.target, BuildTags: match.buildTags, Kind: nativeLayoutSelected,
				})
			}
			key := match.target + "\x00" + strings.Join(match.buildTags, ",")
			config := configsByTargetAndTags[key]
			if config == nil {
				config = &discoveryBuildConfiguration{
					BuildTags: append([]string(nil), match.buildTags...),
					Targets:   []string{match.target},
				}
				configsByTargetAndTags[key] = config
			}
			config.AsmFiles = append(config.AsmFiles, asmFile)
		}
	}
	// Targets can share one translator invocation only when both their build
	// tags and exact source-inferred assembly allowlist are identical.
	configsByShape := make(map[string]*discoveryBuildConfiguration)
	for _, config := range configsByTargetAndTags {
		config.AsmFiles = uniqueSortedDiscoveryStrings(config.AsmFiles)
		shape := strings.Join(config.BuildTags, ",") + "\x00" + strings.Join(config.AsmFiles, "\x00")
		group := configsByShape[shape]
		if group == nil {
			group = &discoveryBuildConfiguration{
				BuildTags: append([]string(nil), config.BuildTags...),
				AsmFiles:  append([]string(nil), config.AsmFiles...),
			}
			configsByShape[shape] = group
		}
		group.Targets = append(group.Targets, config.Targets...)
	}
	keys := make([]string, 0, len(configsByShape))
	for key := range configsByShape {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	configs := make([]discoveryBuildConfiguration, 0, len(keys))
	for _, key := range keys {
		config := configsByShape[key]
		config.Targets = uniqueSortedDiscoveryStrings(config.Targets)
		configs = append(configs, *config)
	}
	if nativePlan != nil {
		nativePlan.BuildConfigurations = configs
	}
	return configs, nil
}

func discoveryAssemblyObjectHasNoSymbols(filePath, goos, goarch string, profiles ...*discoveryAsmCommandProfile) (noSymbols bool, inspectErr error) {
	if len(profiles) > 1 {
		return false, fmt.Errorf("direct assembler symbol check requires one actual profile")
	}
	if len(profiles) == 1 && (profiles[0] == nil || profiles[0].Context == nil) {
		return false, fmt.Errorf("direct assembler symbol check requires candidate context")
	}
	declaresSymbols, err := discoverySourceMentionsSymbolDirective(filePath)
	if err != nil {
		return false, err
	}
	if declaresSymbols {
		return false, nil
	}
	var goRoot string
	goBinary := "go"
	baseArgs := []string{"tool", "asm"}
	targetEnv := replaceEnv(os.Environ(), map[string]string{
		"GOOS": goos, "GOARCH": goarch,
		"GOTOOLCHAIN": "local", "GOWORK": "off",
	})
	if len(profiles) == 1 {
		if profiles[0] == nil {
			return false, fmt.Errorf("missing actual assembly profile")
		}
		goRoot = profiles[0].GoRoot
		var macroSources map[string]string
		goBinary, baseArgs, targetEnv, macroSources, err = discoveryAssemblyProfileCommand(profiles[0], goos, goarch, goRoot)
		if err != nil {
			return false, err
		}
		defer func() {
			if err := verifyDiscoveryAssemblyProfileTools(profiles[0], macroSources); err != nil {
				noSymbols = false
				inspectErr = errors.Join(inspectErr, err)
			}
		}()
	} else {
		goRoot, err = gotoolchain.Root()
		if err != nil {
			return false, err
		}
	}

	tempDir, err := os.MkdirTemp("", "plan9asm-asm-symbols-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tempDir)
	object := filepath.Join(tempDir, "source.o")
	asmArgs := append(append([]string(nil), baseArgs...), []string{
		"-I", filepath.Dir(filePath),
		"-I", filepath.Join(goRoot, "pkg", "include"),
		"-o", object, filePath,
	}...)
	run := func(args ...string) ([]byte, error) {
		if len(profiles) == 1 {
			return runCapturedCommandOutput(profiles[0].Context, "", targetEnv, goBinary, args...)
		}
		command := exec.Command(goBinary, args...)
		command.Env = targetEnv
		return command.CombinedOutput()
	}
	if output, err := run(asmArgs...); err != nil {
		if len(profiles) == 1 && profiles[0].Context.Err() != nil {
			return false, fmt.Errorf("direct assembler symbol probe: %w", profiles[0].Context.Err())
		}
		if len(profiles) == 1 && (isDiscoveryGoBuildInfrastructureFailure(string(output)) || !discoveryAssemblerSourceDiagnostic(filePath, string(output))) {
			return false, fmt.Errorf("direct assembler symbol probe: %w: %s", err, output)
		}
		// This probe establishes no-symbol evidence only. Other classification
		// and build checks retain any Go-assembler failure as a real outcome.
		return false, nil
	}
	output, err := run("tool", "nm", object)
	lines := strings.TrimSpace(string(output))
	if strings.HasSuffix(lines, ": no symbols") {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect Go object symbols: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return lines == "", nil
}

func discoverySourceMentionsSymbolDirective(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	const overlap = len("GLOBL") - 1
	chunk := make([]byte, 64<<10)
	block := make([]byte, 0, len(chunk)+overlap)
	var tail []byte
	for {
		n, readErr := file.Read(chunk)
		if n > 0 {
			block = append(block[:0], tail...)
			block = append(block, chunk[:n]...)
			for _, directive := range [][]byte{[]byte("TEXT"), []byte("GLOBL"), []byte("DATA")} {
				if bytes.Contains(block, directive) {
					return true, nil
				}
			}
			start := len(block) - overlap
			if start < 0 {
				start = 0
			}
			tail = append(tail[:0], block[start:]...)
		}
		if readErr == io.EOF {
			return false, nil
		}
		if readErr != nil {
			return false, readErr
		}
	}
}

// inferUnsuffixedAssemblyTargets adds a source-level check only when Go's
// filename convention does not already identify an architecture. Go itself
// selects files by name and build tags; external packages sometimes omit both
// while containing unmistakably architecture-specific assembly. Asking the
// same Go assembler that will build the package prevents such x86 sources from
// being sent to ARM or Wasm translators without maintaining a second opcode
// taxonomy here.
func inferUnsuffixedAssemblyTargets(filePath string, contexts []build.Context) (map[string]bool, bool, error) {
	eligible, restrict, _, err := inferUnsuffixedAssemblyTargetsDetailed(filePath, contexts)
	return eligible, restrict, err
}

func inferUnsuffixedAssemblyTargetsDetailed(filePath string, contexts []build.Context) (map[string]bool, bool, string, error) {
	inference, err := inferUnsuffixedAssemblyTargetsWithEvidence(filePath, contexts)
	return inference.eligible, inference.restrict, inference.reason, err
}

type assemblySourceTargetInference struct {
	eligible map[string]bool
	restrict bool
	reason   string
	rejected map[string]string
}

type assemblySourceTargetProbe struct {
	accepted   bool
	conclusive bool
	reason     string
}

func inferUnsuffixedAssemblyTargetsWithEvidence(filePath string, contexts []build.Context) (assemblySourceTargetInference, error) {
	var inference assemblySourceTargetInference
	if explicitAssemblyFilenameArchitecture(path.Base(filePath)) != "" {
		return inference, nil
	}
	goRoot, err := gotoolchain.Root()
	if err != nil {
		return inference, err
	}
	eligible := make(map[string]bool, len(contexts))
	probed := make(map[string]assemblySourceTargetProbe)
	inference.rejected = make(map[string]string)
	acceptedAny := false
	conclusiveAny := false
	for _, ctx := range contexts {
		key := ctx.GOOS + "/" + ctx.GOARCH
		result, ok := probed[key]
		if !ok {
			probeCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
			result, err = probeAssemblySourceForTarget(probeCtx, filePath, ctx.GOOS, ctx.GOARCH, goRoot)
			cancel()
			if err != nil {
				return assemblySourceTargetInference{}, fmt.Errorf("Go assembler architecture probe for %s: %w", key, err)
			}
			probed[key] = result
		}
		if result.accepted || !result.conclusive {
			eligible[key] = true
		}
		if result.conclusive && !result.accepted {
			inference.rejected[key] = result.reason
		}
		acceptedAny = acceptedAny || result.accepted
		conclusiveAny = conclusiveAny || result.conclusive
	}
	if !acceptedAny && conclusiveAny && len(eligible) == 0 {
		// The source is a fixture, generated artifact, or assembly for a target
		// outside this repository's supported matrix. The current Go assembler
		// supplies stronger applicability evidence than an opcode guess: keep an
		// explicit empty allowlist instead of failing translation or silently
		// treating it as cross-architecture source.
		var rejectedTargets []string
		for target := range probed {
			rejectedTargets = append(rejectedTargets, target)
		}
		sort.Strings(rejectedTargets)
		inference.eligible, inference.restrict = eligible, true
		inference.reason = fmt.Sprintf("current Go assembler rejected unsuffixed source for every selected target: %s", strings.Join(rejectedTargets, ", "))
		for _, target := range rejectedTargets {
			inference.reason += "\n" + target + ": " + inference.rejected[target]
		}
		return inference, nil
	}
	if !conclusiveAny {
		// Usually a generated go_asm.h (or another build-generated include) was
		// unavailable. Keep every target visible instead of silently excluding it.
		return inference, nil
	}
	inference.eligible, inference.restrict = eligible, true
	return inference, nil
}

func explicitAssemblyFilenameArchitecture(name string) string {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	for _, arch := range []string{
		"386", "amd64", "amd64p32", "arm", "arm64", "armbe", "arm64be",
		"loong64", "mips", "mipsle", "mips64", "mips64le", "mips64p32",
		"mips64p32le", "ppc", "ppc64", "ppc64le", "riscv", "riscv64",
		"s390", "s390x", "sparc", "sparc64", "wasm",
	} {
		if strings.HasSuffix(base, "_"+arch) {
			return arch
		}
	}
	return ""
}

func probeAssemblySourceForTarget(ctx context.Context, filePath, goos, goarch, goRoot string, profiles ...*discoveryAsmCommandProfile) (result assemblySourceTargetProbe, probeErr error) {
	if len(profiles) > 1 {
		return assemblySourceTargetProbe{}, fmt.Errorf("direct assembler probe requires one actual profile")
	}
	goBinary := "go"
	baseArgs := []string{"tool", "asm"}
	baseEnv := replaceEnv(os.Environ(), map[string]string{
		"GOOS": goos, "GOARCH": goarch, "GOTOOLCHAIN": "local", "GOWORK": "off",
	})
	if len(profiles) == 1 {
		var err error
		var macroSources map[string]string
		goBinary, baseArgs, baseEnv, macroSources, err = discoveryAssemblyProfileCommand(profiles[0], goos, goarch, goRoot)
		if err != nil {
			return assemblySourceTargetProbe{}, err
		}
		defer func() {
			if err := verifyDiscoveryAssemblyProfileTools(profiles[0], macroSources); err != nil {
				result = assemblySourceTargetProbe{}
				probeErr = errors.Join(probeErr, err)
			}
		}()
	}
	run := func(extraInclude string) ([]byte, error) {
		args := append([]string(nil), baseArgs...)
		if extraInclude != "" {
			args = append(args, "-I", extraInclude)
		}
		args = append(args, "-I", filepath.Dir(filePath), "-I", filepath.Join(goRoot, "pkg", "include"), "-o", os.DevNull, filePath)
		return runCapturedCommandOutput(ctx, "", baseEnv, goBinary, args...)
	}
	output, err := run("")
	if err == nil {
		return assemblySourceTargetProbe{accepted: true, conclusive: true}, nil
	}
	if isDiscoveryGoBuildInfrastructureFailure(discoveryCommandDiagnostic(err)) {
		return assemblySourceTargetProbe{}, err
	}
	message := strings.ToLower(string(output))
	usedGeneratedHeaderStub := false
	if missingGoAsmHeader(message) {
		stubDir, stubErr := os.MkdirTemp("", "plan9asm-go-asm-header-")
		if stubErr != nil {
			return assemblySourceTargetProbe{}, fmt.Errorf("create architecture probe header directory: %w", stubErr)
		}
		defer os.RemoveAll(stubDir)
		if stubErr := os.WriteFile(filepath.Join(stubDir, "go_asm.h"), nil, 0o600); stubErr != nil {
			return assemblySourceTargetProbe{}, fmt.Errorf("write architecture probe header: %w", stubErr)
		}
		output, err = run(stubDir)
		usedGeneratedHeaderStub = true
		if err == nil {
			return assemblySourceTargetProbe{accepted: true, conclusive: true}, nil
		}
		message = strings.ToLower(string(output))
	}
	if isDiscoveryGoBuildInfrastructureFailure(discoveryCommandDiagnostic(err)) {
		return assemblySourceTargetProbe{}, err
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() <= 0 {
		return assemblySourceTargetProbe{}, err
	}
	for _, fragment := range []string{"no such file or directory", "cannot find", "could not find"} {
		if strings.Contains(message, fragment) {
			return assemblySourceTargetProbe{}, nil
		}
	}
	if !discoveryAssemblerSourceDiagnostic(filePath, string(output)) {
		// A positive exit alone is not evidence of invalid assembly. Empty,
		// internal, wrapper and unrecognized tool errors must remain failures.
		return assemblySourceTargetProbe{}, err
	}
	if usedGeneratedHeaderStub && !strings.Contains(message, "unrecognized instruction") {
		// An empty compiler-generated header supplies no constants/layouts.
		// Its absence cannot prove that an operand or symbol is invalid. An
		// unrecognized opcode is independent of those header definitions;
		// otherwise keep the target eligible for its real package build.
		return assemblySourceTargetProbe{}, nil
	}
	return assemblySourceTargetProbe{
		conclusive: true,
		reason:     "current Go assembler rejected this source for the selected target:\n" + string(output),
	}, nil
}

func discoveryAssemblerSourceDiagnostic(filePath, output string) bool {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "panic:") || strings.HasPrefix(trimmed, "fatal error:") ||
			strings.HasPrefix(trimmed, "runtime:") || strings.HasPrefix(trimmed, "go tool asm:") {
			return false
		}
	}
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, filePath+":") && !strings.HasPrefix(trimmed, "asm: ") {
			continue
		}
		prefix, location, found := strings.Cut(trimmed, filePath+":")
		if !found {
			continue
		}
		var encoderMessage string
		if prefix != "" && prefix != "asm: " {
			// Encoder errors put the exact full source location in parentheses.
			// A suffix match in another directory's same-named file must not
			// establish rejection of the file currently being probed.
			if !strings.HasPrefix(prefix, "asm: ") || !strings.HasSuffix(prefix, "(") {
				continue
			}
			encoderMessage = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(prefix, "asm: "), "("))
			if encoderMessage == "" {
				continue
			}
		}
		end := 0
		for end < len(location) && location[end] >= '0' && location[end] <= '9' {
			end++
		}
		if end == 0 || end == len(location) || (location[end] != ':' && location[end] != ')') {
			continue
		}
		lineNumber, err := strconv.ParseUint(location[:end], 10, 32)
		if err != nil || lineNumber == 0 {
			continue
		}
		message := strings.TrimSpace(location[end+1:])
		if location[end] == ':' {
			// cmd/asm's ordinary diagnostics may carry a column, while its
			// encoder diagnostics use "asm: file:line) instruction". A bare
			// location, zero/overflow position or empty message is not evidence.
			message, _, err = discoverySourceDiagnosticMessage(location[end+1:])
			if err != nil {
				continue
			}
		}
		if message != "" || encoderMessage != "" {
			return true
		}
	}
	// The final failure footer is emitted even when the cause is lost. It is
	// not a source diagnostic and must not establish architecture inapplicability.
	return false
}

func missingGoAsmHeader(message string) bool {
	message = strings.ToLower(message)
	if !strings.Contains(message, "go_asm.h") {
		return false
	}
	for _, fragment := range []string{"no such file or directory", "cannot find", "could not find"} {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

func discoveryConstraintTags(filePath string) ([]string, error) {
	if strings.HasSuffix(filePath, ".go") {
		return discoveryGoConstraintTags(filePath)
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open build constraints %s: %w", filePath, err)
	}
	defer file.Close()
	set := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	inBlockComment := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if inBlockComment {
			if strings.Contains(line, "*/") {
				inBlockComment = false
			}
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "/*") {
			inBlockComment = !strings.Contains(line, "*/")
			continue
		}
		if !strings.HasPrefix(line, "//") {
			break
		}
		if !strings.HasPrefix(line, "//go:build ") && !strings.HasPrefix(line, "// +build ") {
			continue
		}
		expr, err := constraint.Parse(line)
		if err != nil {
			return nil, fmt.Errorf("parse build constraint %s: %w", filePath, err)
		}
		collectDiscoveryConstraintTags(expr, set)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read build constraints %s: %w", filePath, err)
	}
	tags := make([]string, 0, len(set))
	for tag := range set {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags, nil
}

func discoveryGoConstraintTags(filePath string) ([]string, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), filePath, nil, parser.PackageClauseOnly|parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse Go build constraints %s: %w", filePath, err)
	}
	set := make(map[string]bool)
	for _, group := range parsed.Comments {
		for _, comment := range group.List {
			line := strings.TrimSpace(comment.Text)
			if !strings.HasPrefix(line, "//go:build ") && !strings.HasPrefix(line, "// +build ") {
				continue
			}
			expr, err := constraint.Parse(line)
			if err != nil {
				return nil, fmt.Errorf("parse build constraint %s: %w", filePath, err)
			}
			collectDiscoveryConstraintTags(expr, set)
		}
	}
	tags := make([]string, 0, len(set))
	for tag := range set {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags, nil
}

func collectDiscoveryConstraintTags(expr constraint.Expr, tags map[string]bool) {
	switch expr := expr.(type) {
	case *constraint.TagExpr:
		tags[expr.Tag] = true
	case *constraint.NotExpr:
		collectDiscoveryConstraintTags(expr.X, tags)
	case *constraint.AndExpr:
		collectDiscoveryConstraintTags(expr.X, tags)
		collectDiscoveryConstraintTags(expr.Y, tags)
	case *constraint.OrExpr:
		collectDiscoveryConstraintTags(expr.X, tags)
		collectDiscoveryConstraintTags(expr.Y, tags)
	}
}

func uniqueDiscoveryCustomTags(tags []string, contexts []build.Context) []string {
	reserved := map[string]bool{
		// "ignore" conventionally marks generator inputs and other files that
		// are not part of any build. Enabling it globally also selects Go's own
		// ignored generator programs and produces packages that cannot compile.
		"ignore": true,
		"aix":    true, "android": true, "darwin": true, "dragonfly": true,
		"freebsd": true, "hurd": true, "illumos": true, "ios": true,
		"js": true, "linux": true, "netbsd": true, "openbsd": true,
		"plan9": true, "solaris": true, "unix": true, "wasip1": true,
		"windows": true, "zos": true,
		"386": true, "amd64": true, "amd64p32": true, "arm": true,
		"armbe": true, "arm64": true, "arm64be": true, "loong64": true,
		"mips": true, "mipsle": true, "mips64": true, "mips64le": true,
		"mips64p32": true, "mips64p32le": true, "ppc": true, "ppc64": true,
		"ppc64le": true, "riscv": true, "riscv64": true, "s390": true,
		"s390x": true, "sparc": true, "sparc64": true, "wasm": true,
		"cgo": true, "gc": true, "gccgo": true,
	}
	for _, ctx := range contexts {
		reserved[ctx.GOOS] = true
		reserved[ctx.GOARCH] = true
		reserved[ctx.Compiler] = true
		for _, tag := range ctx.ReleaseTags {
			reserved[tag] = true
		}
		for _, tag := range ctx.ToolTags {
			reserved[tag] = true
		}
	}
	set := make(map[string]bool)
	for _, tag := range tags {
		if tag != "" && !reserved[tag] {
			set[tag] = true
		}
	}
	out := make([]string, 0, len(set))
	for tag := range set {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedDiscoveryStrings(values []string) []string {
	out := uniqueDiscoveryStrings(values)
	sort.Strings(out)
	return out
}

func uniqueDiscoveryStrings(values []string) []string {
	set := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if set[value] {
			continue
		}
		set[value] = true
		out = append(out, value)
	}
	return out
}

func discoveryDirIsIgnored(dir string) bool {
	if dir == "." || dir == "" {
		return false
	}
	for _, elem := range strings.Split(filepath.ToSlash(dir), "/") {
		if elem == "testdata" || elem == "vendor" || strings.HasPrefix(elem, ".") || strings.HasPrefix(elem, "_") {
			return true
		}
	}
	return false
}

func discoveryDirIsNestedModule(moduleDir, dirRel string) (bool, error) {
	for dirRel != "." && dirRel != "" {
		_, err := os.Stat(filepath.Join(moduleDir, filepath.FromSlash(dirRel), "go.mod"))
		switch {
		case err == nil:
			return true, nil
		case os.IsNotExist(err):
			// Continue toward the root module.
		case err != nil:
			return false, fmt.Errorf("stat nested go.mod in %s: %w", dirRel, err)
		}
		dirRel = path.Dir(dirRel)
	}
	return false, nil
}

func runDiscoveryCorpus(cfg discoveryCorpusConfig) (runErr error) {
	if cfg.ShardCount <= 0 || cfg.ShardIndex < 0 || cfg.ShardIndex >= cfg.ShardCount {
		return fmt.Errorf("invalid discovery shard %d/%d", cfg.ShardIndex, cfg.ShardCount)
	}
	if cfg.CandidateTimeout <= 0 {
		return fmt.Errorf("candidate timeout must be positive")
	}
	// Candidate commands run in isolated module directories. Resolve paths
	// before provenance capture so the checked tools are also the executed
	// tools, regardless of the candidate's working directory or PATH.
	var err error
	cfg.RepoRoot, err = filepath.Abs(cfg.RepoRoot)
	if err != nil {
		return fmt.Errorf("resolve discovery repository: %w", err)
	}
	if cfg.TranslatorRoot != "" {
		cfg.TranslatorRoot, err = filepath.Abs(cfg.TranslatorRoot)
		if err != nil {
			return fmt.Errorf("resolve translator repository: %w", err)
		}
	}
	for _, path := range []*string{&cfg.Translator, &cfg.LLC} {
		if *path == "" { // Offline orchestration fixtures have no executables.
			continue
		}
		*path, err = resolveDiscoveryExecutable(*path)
		if err != nil {
			return err
		}
	}
	captureProvenance := collectDiscoveryProvenance
	if cfg.captureProvenance != nil {
		captureProvenance = cfg.captureProvenance
	}
	runCandidate := runDiscoveryCandidate
	if cfg.runCandidate != nil {
		runCandidate = cfg.runCandidate
	}
	provenance, err := captureProvenance(cfg)
	if err != nil {
		return fmt.Errorf("discovery provenance preflight: %w", err)
	}
	cfg.phaseEvents, err = openDiscoveryPhaseJournal(cfg.EventsPath, cfg, provenance)
	if err != nil {
		return err
	}
	var report discoveryCorpusReport
	if cfg.phaseEvents != nil {
		defer func() {
			recovered := recover()
			terminal := runErr
			if recovered != nil {
				terminal = fmt.Errorf("discovery operation panic: %v", recovered)
			}
			if err := cfg.phaseEvents.close(terminal); err != nil {
				runErr = errors.Join(runErr, err)
				if report.SchemaVersion != 0 {
					if report.Provenance.Invalidated != "" {
						report.Provenance.Invalidated += "; "
					}
					report.Provenance.Invalidated += "requested phase journal failed"
					runErr = errors.Join(runErr, writeDiscoveryCorpusReport(cfg.ReportPath, report))
				}
			}
			if recovered != nil {
				panic(recovered)
			}
		}()
	}
	if provenance.Source.Dirty {
		fmt.Println("diagnostic-only discovery run: dirty source cannot satisfy aggregate verification")
	}
	inventory, err := loadDiscoveryCandidateInventory(cfg.LedgerPath, cfg)
	if err != nil {
		return err
	}
	// Bind requests before workspace setup, without reducing the ledger or
	// complete shard that readers independently reconstruct.
	fullShard := inventory.FullShard
	selected, err := selectDiscoveryExactCandidates(cfg, inventory.Identities, fullShard)
	if err != nil {
		return err
	}
	invalidSourceSkips, err := loadInvalidMachineCodeSkips(cfg.RepoRoot)
	if err != nil {
		return err
	}
	supersededSkips, err := loadSupersededSkips(cfg.RepoRoot, cfg.LedgerPath)
	if err != nil {
		return err
	}
	privateExtensionSkips, err := loadPrivateExtensionSkips(cfg.RepoRoot, cfg.LedgerPath)
	if err != nil {
		return err
	}
	cfg.privateExtensionSkips = privateExtensionSkips
	nativeLayoutSkips, err := loadNativeLayoutSkips(cfg.RepoRoot, cfg.LedgerPath)
	if err != nil {
		return err
	}
	cfg.nativeLayoutSkips = nativeLayoutSkips
	embeddedAliases, err := loadDiscoveryEmbeddedModuleAliases(cfg.RepoRoot, inventory.Identities)
	if err != nil {
		return err
	}
	cfg.embeddedAliases = embeddedAliases
	report = discoveryCorpusReport{
		SchemaVersion:      discoveryReportSchema,
		Provenance:         provenance,
		Targets:            append([]string(nil), cfg.Targets...),
		TargetFiltered:     cfg.FilterTargets,
		ShardIndex:         cfg.ShardIndex,
		ShardCount:         cfg.ShardCount,
		CandidateTotal:     len(inventory.Identities),
		EligibleCandidates: inventory.Eligible,
		Partial:            len(fullShard) > 0,
		Results:            make([]discoveryCorpusResult, 0, len(selected)),
		FeatureInventory:   newDiscoveryFeatureInventory(),
	}
	tmpRoot, err := os.MkdirTemp("", fmt.Sprintf("plan9asm-discovery-%02d-", cfg.ShardIndex))
	if err != nil {
		return err
	}
	defer func() {
		if err := removeDiscoveryCandidateWorkspace(tmpRoot); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("clean discovery shard workspace: %w", err))
		}
	}()
	cfg.featureMarkerDir = filepath.Join(tmpRoot, "actual-feature-markers")
	if err := os.Mkdir(cfg.featureMarkerDir, 0700); err != nil {
		return err
	}
	cfg.featureCache = &discoveryFeatureObservationCache{}
	// Reuse standard-library compilation within this shard. A caller-owned
	// cache can also be shared by parallel shards; only the shard-owned default
	// is discarded when this run returns.
	if cfg.buildCache == "" {
		cfg.buildCache = filepath.Join(tmpRoot, "build-cache")
		if err := os.Mkdir(cfg.buildCache, 0700); err != nil {
			return fmt.Errorf("create owned discovery build cache: %w", err)
		}
	} else {
		if !filepath.IsAbs(cfg.buildCache) {
			return fmt.Errorf("discovery build cache must be an absolute path: %q", cfg.buildCache)
		}
		info, err := os.Stat(cfg.buildCache)
		if err != nil {
			return fmt.Errorf("stat discovery build cache: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("discovery build cache is not a directory: %q", cfg.buildCache)
		}
	}
	if report.Partial {
		// A runner can be canceled inside its first candidate. Publish an
		// auditable zero-result checkpoint before entering that long operation.
		if err := writeDiscoveryCorpusReport(cfg.ReportPath, report); err != nil {
			return err
		}
	}
	checkpointNow := cfg.checkpointNow
	if checkpointNow == nil {
		checkpointNow = time.Now
	}
	lastCheckpoint := checkpointNow()
	checkpoint := func(completed int) error {
		if !report.Partial || completed >= len(selected) || cfg.ReportPath == "" {
			return nil
		}
		// Amortize provenance scans for quick candidates, but publish the
		// completed prefix before another long candidate can hide it for
		// hours. This never reports the still-running candidate as passed.
		if completed%8 != 0 && checkpointNow().Sub(lastCheckpoint) < time.Minute {
			return nil
		}
		// Never publish a pass after a source, ledger or tool mutation.
		current, provenanceErr := captureProvenance(cfg)
		if provenanceErr != nil || current != provenance {
			report.Provenance.Invalidated = "source, ledger or tools changed during corpus run"
		}
		if err := writeDiscoveryCorpusReport(cfg.ReportPath, report); err != nil {
			return err
		}
		if report.Provenance.Invalidated != "" {
			return fmt.Errorf("discovery provenance invalidated during checkpoint: %s (capture error: %v)", report.Provenance.Invalidated, provenanceErr)
		}
		lastCheckpoint = checkpointNow()
		return nil
	}
	for i, candidate := range selected {
		fmt.Printf("[%d/%d] %s\n", i+1, len(selected), candidate.exactKey())
		result := discoveryCorpusResult{
			Module:             candidate.Module,
			Version:            candidate.Version,
			DiscoveredAsmFiles: append([]string(nil), candidate.AsmFiles...),
		}
		candidateDir := filepath.Join(tmpRoot, fmt.Sprintf("candidate-%04d", i))
		if skip, ok := supersededSkips[candidate.exactKey()]; ok {
			if err := cfg.phaseEvents.run(candidate.exactKey(), "candidate", "superseded_membership", func() error { return nil }); err != nil {
				return err
			}
			result.Status = discoveryStatusSkippedSuperseded
			result.Superseded = &skip
			report.SkippedSuperseded++
			report.Results = append(report.Results, result)
			report.Selected++
			fmt.Printf("SKIP_SUPERSEDED %s: %s replaces it\n", candidate.exactKey(), skip.ReplacementModule+"@"+skip.ReplacementVersion)
			if err := checkpoint(i + 1); err != nil {
				return err
			}
			continue
		}
		if skip, ok := invalidSourceSkips[candidate.exactKey()]; ok {
			err := cfg.phaseEvents.run(candidate.exactKey(), "candidate", "invalid_source_verification", func() error {
				return verifyInvalidMachineCodeCandidate(cfg, candidate, candidateDir, skip)
			})
			if err == nil {
				result.Status = discoveryStatusSkippedInvalidSource
				result.InvalidSourceReason = skip.Reason
				result.InvalidSourceEvidence = append(result.InvalidSourceEvidence, skip.Evidence...)
				report.SkippedInvalidSource++
				fmt.Printf("SKIP_INVALID_SOURCE %s: %s\n", candidate.exactKey(), skip.Reason)
			} else {
				result.Status = discoveryStatusFailed
				result.Error = fmt.Sprintf("invalid-source skip proof failed: %v", err)
				report.Failed++
				fmt.Fprintf(os.Stderr, "FAIL %s: %s\n", candidate.exactKey(), result.Error)
			}
			report.Results = append(report.Results, result)
			report.Selected++
			if err := checkpoint(i + 1); err != nil {
				return err
			}
			continue
		}
		var matrix matrixReport
		var patterns []string
		var buildConfigurations []discoveryBuildConfiguration
		runErr := cfg.phaseEvents.run(candidate.exactKey(), "candidate", "", func() error {
			var err error
			matrix, patterns, buildConfigurations, err = runCandidate(cfg, candidate, candidateDir)
			return err
		})
		applicableAsmFiles := discoveryConfigurationAsmFiles(buildConfigurations)
		applicableAsmFiles = uniqueSortedDiscoveryStrings(append(applicableAsmFiles, discoveryInstrumentationExecutedFiles(matrix.OrdinarySelectionPlan)...))
		result.Patterns = patterns
		result.ApplicableAsmFiles = applicableAsmFiles
		result.BuildConfigurations = buildConfigurations
		result.NotApplicableItems = append(result.NotApplicableItems, matrix.NotApplicableItems...)
		result.SourceNotApplicableItems = append(result.SourceNotApplicableItems, matrix.SourceNotApplicableItems...)
		result.OrdinarySelectionPlan = matrix.OrdinarySelectionPlan
		result.FeatureConsumption = matrix.FeatureConsumption
		result.InstrumentationTranslations = matrix.InstrumentationTranslations
		report.ModeTranslations += matrix.InstrumentationTranslations
		result.InstrumentationTargetExclusions = matrix.InstrumentationTargetExclusions
		report.ModeTargetExclusions += matrix.InstrumentationTargetExclusions
		if matrix.OrdinarySelectionPlan != nil && matrix.OrdinarySelectionPlan.HeaderPlanning != nil {
			if err := mergeDiscoveryFeatureInventory(report.FeatureInventory, matrix.OrdinarySelectionPlan.headerPlanningInventory); err != nil {
				return fmt.Errorf("register actual header planning observations: %w", err)
			}
		}
		if len(matrix.FeatureProfiles) != 0 {
			result.FeatureProfiles, err = registerDiscoveryFeatureProfiles(report.FeatureInventory, matrix.FeatureProfiles)
			if err != nil {
				return fmt.Errorf("register actual candidate profiles: %w", err)
			}
		}
		if runErr != nil {
			result.Status = discoveryStatusFailed
			result.Error = runErr.Error()
			report.Failed++
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", candidate.exactKey(), runErr)
		} else if matrix.PrivateExtension != nil {
			result.Status = discoveryStatusSkippedPrivateExtension
			result.PrivateExtension = matrix.PrivateExtension
			result.Translations = matrix.Success
			result.NotApplicableTranslations = matrix.NotApplicable
			report.SkippedPrivateExtension++
			report.Translations += matrix.Success
			report.NotApplicableTranslations += matrix.NotApplicable
			fmt.Printf("SKIP_PRIVATE_EXTENSION %s: %s on %s; other translations=%d\n",
				candidate.exactKey(), matrix.PrivateExtension.AsmFile,
				matrix.PrivateExtension.Target, matrix.Success)
		} else if matrix.NativeLayout != nil {
			result.Status = discoveryStatusSkippedNativeLayout
			result.NativeLayout = matrix.NativeLayout
			result.NativeLayoutPlan = matrix.NativeLayoutPlan
			result.Translations = matrix.Success
			result.NotApplicableTranslations = matrix.NotApplicable
			report.SkippedNativeLayout++
			report.Translations += matrix.Success
			report.NotApplicableTranslations += matrix.NotApplicable
			fmt.Printf("SKIP_NATIVE_LAYOUT %s: %s on %s; other translations=%d\n",
				candidate.exactKey(), matrix.NativeLayout.AsmFile,
				strings.Join(matrix.NativeLayout.Targets, ","), matrix.Success)
		} else if len(applicableAsmFiles) == 0 || matrix.Success == 0 {
			result.Status = discoveryStatusNotApplicable
			if len(applicableAsmFiles) == 0 {
				result.NotApplicableReason = "no discovered assembly file belongs to a buildable Go package on the supported target matrix"
			} else {
				result.NotApplicableReason = "every target-selected assembly source has evidence-backed current-Go source or ABI incompatibility"
			}
			if result.OrdinarySelectionPlan != nil {
				result.NotApplicableReason = ordinarySelectionReason(result.OrdinarySelectionPlan, result.SourceNotApplicableItems, result.NotApplicableItems)
			}
			result.NotApplicableTranslations = matrix.NotApplicable
			report.NotApplicableTranslations += matrix.NotApplicable
			report.NotApplicable++
			fmt.Printf("NOT_APPLICABLE %s: discovered_files=%d\n", candidate.exactKey(), len(candidate.AsmFiles))
		} else {
			result.Status = discoveryStatusPassed
			result.Translations = matrix.Success
			result.NotApplicableTranslations = matrix.NotApplicable
			report.Passed++
			report.Translations += matrix.Success
			report.NotApplicableTranslations += matrix.NotApplicable
			fmt.Printf("PASS %s: applicable_files=%d translations=%d not_applicable_translations=%d targets=%d\n", candidate.exactKey(), len(applicableAsmFiles), matrix.Success, matrix.NotApplicable, matrix.TotalTargets)
		}
		report.Results = append(report.Results, result)
		report.Selected++
		if err := checkpoint(i + 1); err != nil {
			return err
		}
	}
	report.Partial = len(report.Results) < len(fullShard)
	if err := validateDiscoveryCorpusAccounting(report); err != nil {
		return err
	}
	finalProvenance, provenanceErr := captureProvenance(cfg)
	if provenanceErr != nil || finalProvenance != provenance {
		report.Provenance.Invalidated = "source, ledger or tools changed during corpus run"
	}
	if err := writeDiscoveryCorpusReport(cfg.ReportPath, report); err != nil {
		return err
	}
	if report.Provenance.Invalidated != "" {
		return fmt.Errorf("discovery provenance invalidated: %s (capture error: %v)", report.Provenance.Invalidated, provenanceErr)
	}
	if report.Failed != 0 {
		return fmt.Errorf("discovery shard %d/%d failed: passed=%d failed=%d selected=%d", cfg.ShardIndex, cfg.ShardCount, report.Passed, report.Failed, report.Selected)
	}
	if report.Partial {
		fmt.Printf("exact discovery request completed: %d/%d candidates in shard %d/%d; unreported candidates remain pending\n",
			report.Selected, len(fullShard), cfg.ShardIndex, cfg.ShardCount)
	}
	fmt.Printf(
		"discovery shard %d/%d completed: passed=%d not_applicable=%d "+
			"skipped_invalid_source=%d skipped_superseded=%d "+
			"skipped_private_extension=%d skipped_native_layout=%d "+
			"translations=%d not_applicable_translations=%d instrumentation_translations=%d\n",
		cfg.ShardIndex, cfg.ShardCount,
		report.Passed, report.NotApplicable,
		report.SkippedInvalidSource, report.SkippedSuperseded,
		report.SkippedPrivateExtension, report.SkippedNativeLayout,
		report.Translations, report.NotApplicableTranslations, report.ModeTranslations,
	)
	return nil
}

func resolveDiscoveryExecutable(name string) (string, error) {
	resolved := name
	if !strings.ContainsAny(name, `/\`) && filepath.VolumeName(name) == "" {
		var err error
		resolved, err = exec.LookPath(name)
		if err != nil {
			return "", fmt.Errorf("resolve discovery executable %q: %w", name, err)
		}
	}
	resolved, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve discovery executable %q: %w", name, err)
	}
	return resolved, nil
}

func validateDiscoveryCorpusAccounting(report discoveryCorpusReport) error {
	if len(report.Results) == 0 && (report.ModeTranslations != 0 || report.ModeTargetExclusions != 0) {
		return fmt.Errorf("empty report cannot claim mode LLVM objects or target exclusions")
	}
	if report.SchemaVersion == discoveryReportSchema {
		if report.Provenance.InstrumentationScopeProtocol != discoveryInstrumentationPlanProtocol {
			return fmt.Errorf("current report lacks its mandatory instrumentation scope protocol")
		}
		if err := validateDiscoveryFeatureInventory(report.FeatureInventory); err != nil {
			return err
		}
	}
	if report.SchemaVersion != discoveryReportSchema {
		if report.Provenance.InstrumentationScopeProtocol != "" || report.ModeTargetExclusions != 0 {
			return fmt.Errorf("historical report cannot claim the current mode-scope protocol")
		}
		for _, result := range report.Results {
			if result.InstrumentationTargetExclusions != 0 || result.OrdinarySelectionPlan != nil && result.OrdinarySelectionPlan.InstrumentationPlan != nil && result.OrdinarySelectionPlan.InstrumentationPlan.Protocol != discoveryInstrumentationLegacyProtocol {
				return fmt.Errorf("historical report cannot relabel current mode-scope evidence")
			}
		}
	}
	if report.SchemaVersion == 9 {
		if report.FeatureInventory != nil || report.ModeTranslations != 0 {
			return fmt.Errorf("schema 9 cannot claim profile-aware source/CPP/compiler coverage")
		}
		for _, result := range report.Results {
			if len(result.FeatureProfiles) != 0 || len(result.FeatureConsumption) != 0 || result.InstrumentationTranslations != 0 ||
				result.OrdinarySelectionPlan != nil && result.OrdinarySelectionPlan.InstrumentationPlan != nil ||
				result.OrdinarySelectionPlan != nil && len(result.OrdinarySelectionPlan.ProfileDecisions) != 0 {
				return fmt.Errorf("schema 9 cannot relabel profile-aware evidence")
			}
			for _, config := range result.BuildConfigurations {
				if config.ProfileID != "" {
					return fmt.Errorf("schema 9 cannot collapse the profile scope dimension")
				}
			}
		}
	}
	for _, count := range []int{
		report.CandidateTotal, report.EligibleCandidates, report.Selected,
		report.Passed, report.Failed, report.NotApplicable, report.SkippedInvalidSource,
		report.SkippedSuperseded, report.SkippedPrivateExtension,
		report.SkippedNativeLayout,
		report.Translations, report.NotApplicableTranslations, report.ModeTranslations, report.ModeTargetExclusions,
	} {
		if count < 0 {
			return fmt.Errorf("discovery report contains a negative count")
		}
	}
	classified := report.Passed + report.Failed + report.NotApplicable +
		report.SkippedInvalidSource + report.SkippedSuperseded +
		report.SkippedPrivateExtension + report.SkippedNativeLayout
	if report.Selected != classified {
		return fmt.Errorf(
			"discovery report accounting mismatch: selected=%d classified=%d",
			report.Selected, classified,
		)
	}
	if len(report.Results) != 0 && len(report.Results) != report.Selected {
		return fmt.Errorf("discovery report result count mismatch: selected=%d results=%d", report.Selected, len(report.Results))
	}
	var passed, failed, notApplicable int
	var skippedInvalidSource, skippedSuperseded, skippedPrivateExtension, skippedNativeLayout int
	var translations, notApplicableTranslations, modeTranslations, modeTargetExclusions int
	for _, result := range report.Results {
		if result.Translations < 0 || result.NotApplicableTranslations < 0 || result.InstrumentationTranslations < 0 || result.InstrumentationTargetExclusions < 0 {
			return fmt.Errorf("%s@%s: negative translation counts", result.Module, result.Version)
		}
		switch result.Status {
		case discoveryStatusPassed:
			passed++
		case discoveryStatusFailed:
			failed++
		case discoveryStatusNotApplicable:
			notApplicable++
		case discoveryStatusSkippedInvalidSource:
			skippedInvalidSource++
			if err := validateInvalidSourceReportEvidence(result); err != nil {
				return fmt.Errorf("%s@%s: %w", result.Module, result.Version, err)
			}
		case discoveryStatusSkippedSuperseded:
			skippedSuperseded++
			if result.Superseded == nil || result.Superseded.Module != result.Module ||
				result.Superseded.Version != result.Version || result.Translations != 0 ||
				result.NotApplicableTranslations != 0 || result.Error != "" ||
				len(result.ApplicableAsmFiles) != 0 || len(result.BuildConfigurations) != 0 ||
				len(result.InvalidSourceEvidence) != 0 || result.InvalidSourceReason != "" {
				return fmt.Errorf("%s@%s: invalid superseded skip", result.Module, result.Version)
			}
		case discoveryStatusSkippedPrivateExtension:
			skippedPrivateExtension++
			if err := validatePrivateExtensionResult(result); err != nil {
				return fmt.Errorf("%s@%s: %w", result.Module, result.Version, err)
			}
		case discoveryStatusSkippedNativeLayout:
			skippedNativeLayout++
			if err := validateNativeLayoutResult(result); err != nil {
				return fmt.Errorf("%s@%s: %w", result.Module, result.Version, err)
			}
			if !equalDiscoveryStrings(uniqueSortedDiscoveryStrings(report.Targets), result.NativeLayoutPlan.Targets) {
				return fmt.Errorf("native-layout pre-filter plan differs from report target matrix")
			}
			if report.Provenance.GoVersion != "" && result.NativeLayoutPlan.GoVersion != report.Provenance.GoVersion {
				return fmt.Errorf("native-layout plan Go selection version differs from report provenance")
			}
		default:
			return fmt.Errorf("%s@%s: invalid discovery result status %q", result.Module, result.Version, result.Status)
		}
		if result.Status != discoveryStatusSkippedSuperseded && result.Superseded != nil {
			return fmt.Errorf("%s@%s: non-superseded result carries supersession", result.Module, result.Version)
		}
		if result.Status != discoveryStatusSkippedPrivateExtension && result.PrivateExtension != nil {
			return fmt.Errorf("%s@%s: non-private result carries private-extension skip", result.Module, result.Version)
		}
		if result.Status != discoveryStatusSkippedNativeLayout && result.NativeLayout != nil {
			return fmt.Errorf("%s@%s: non-native result carries native-layout skip", result.Module, result.Version)
		}
		if result.Status != discoveryStatusSkippedNativeLayout && result.NativeLayoutPlan != nil {
			return fmt.Errorf("non-native result carries native-layout plan")
		}
		translations += result.Translations
		modeTranslations += result.InstrumentationTranslations
		modeTargetExclusions += result.InstrumentationTargetExclusions
		notApplicableTranslations += result.NotApplicableTranslations
		if err := validateDiscoverySourceNotApplicableEvidence(result); err != nil {
			return fmt.Errorf("%s@%s: %w", result.Module, result.Version, err)
		}
		if result.Status == discoveryStatusPassed || result.Status == discoveryStatusNotApplicable {
			var err error
			if report.SchemaVersion == discoveryReportSchema {
				result.featureInventory = report.FeatureInventory
				err = validateOrdinaryProfileResult(result, report.Targets, report.Provenance.GoVersion)
			} else {
				err = validateOrdinarySelectionResult(result, report.Targets, report.Provenance.GoVersion)
			}
			if err != nil {
				return fmt.Errorf("%s@%s: %w", result.Module, result.Version, err)
			}
		} else if result.OrdinarySelectionPlan != nil && result.Status != discoveryStatusFailed {
			return fmt.Errorf("non-ordinary result carries ordinary source-selection proof")
		}
		if err := validateDiscoveryInstrumentationFailure(result, report.FeatureInventory); err != nil {
			return err
		}
		if plan := result.OrdinarySelectionPlan; plan != nil && plan.InstrumentationPlan != nil && !equalDiscoveryStrings(plan.Targets, uniqueSortedDiscoveryStrings(report.Targets)) {
			return fmt.Errorf("mode denominator target matrix differs from its report")
		}
		if err := validateDiscoveryInstrumentationToolProvenance(result, report.Provenance); err != nil {
			return err
		}
	}
	if len(report.Results) != 0 &&
		(passed != report.Passed || failed != report.Failed ||
			notApplicable != report.NotApplicable ||
			skippedInvalidSource != report.SkippedInvalidSource ||
			skippedSuperseded != report.SkippedSuperseded ||
			skippedPrivateExtension != report.SkippedPrivateExtension ||
			skippedNativeLayout != report.SkippedNativeLayout) {
		return fmt.Errorf("discovery report result status counts differ from summary")
	}
	if len(report.Results) != 0 && (translations != report.Translations || notApplicableTranslations != report.NotApplicableTranslations || modeTranslations != report.ModeTranslations || modeTargetExclusions != report.ModeTargetExclusions) {
		return fmt.Errorf("discovery report result translation counts are translations=%d not_applicable=%d, summary is translations=%d not_applicable=%d", translations, notApplicableTranslations, report.Translations, report.NotApplicableTranslations)
	}
	return nil
}

func validateDiscoverySourceNotApplicableEvidence(result discoveryCorpusResult) error {
	scope, err := discoveryResultAssemblyScope(result)
	if err != nil {
		return err
	}
	discovered := make(map[string]bool, len(scope))
	for _, asmFile := range scope {
		discovered[asmFile] = true
	}
	allowedKinds := map[string]bool{
		discoverySourceNotApplicableGoAssembler:   true,
		discoverySourceNotApplicableNoGoPackage:   true,
		discoveryDocumentationKind:                true,
		discoverySourceNotApplicableGoBuild:       true,
		discoverySourceNotApplicableAsmDecl:       true,
		discoverySourceNotApplicableNoSymbols:     true,
		discoverySourceNotApplicableFortranLoader: true,
		discoverySourceNotApplicableMixedPackage:  true,
		discoverySourceNotApplicableSDKNamespace:  true,
		nativeLayoutGoAssemblerTarget:             true,
	}
	for _, item := range result.SourceNotApplicableItems {
		files := append([]string(nil), item.AsmFiles...)
		if item.AsmFile != "" {
			files = append(files, item.AsmFile)
		}
		files = uniqueSortedDiscoveryStrings(files)
		valid := allowedKinds[item.Kind] && len(files) != 0 && len(item.Targets) != 0 && item.Reason != ""
		for _, asmFile := range files {
			valid = valid && discovered[asmFile]
		}
		for _, target := range item.Targets {
			goos, goarch, ok := strings.Cut(target, "/")
			valid = valid && ok && goos != "" && goarch != ""
		}
		if !valid {
			return fmt.Errorf("invalid source not-applicable evidence: kind=%q files=%v targets=%v", item.Kind, files, item.Targets)
		}
		if item.Kind == discoverySourceNotApplicableFortranLoader &&
			(result.OrdinarySelectionPlan == nil || result.OrdinarySelectionPlan.Protocol != ordinarySelectionScopeProtocol ||
				len(result.OrdinarySelectionPlan.FortranRejections) == 0 || len(result.FeatureProfiles) == 0 || item.Diagnostic != nil) {
			return fmt.Errorf("Fortran loader source exclusion lacks its independent typed original-source proof")
		}
		if item.Kind == discoverySourceNotApplicableMixedPackage &&
			(result.OrdinarySelectionPlan == nil || result.OrdinarySelectionPlan.Protocol != ordinarySelectionScopeProtocol ||
				len(result.OrdinarySelectionPlan.MixedPackageRejections) == 0 || len(result.FeatureProfiles) == 0 || item.Diagnostic != nil) {
			return fmt.Errorf("mixed-package source exclusion lacks its independent typed original-source proof")
		}
		if item.Kind == discoverySourceNotApplicableSDKNamespace &&
			(result.OrdinarySelectionPlan == nil || result.OrdinarySelectionPlan.Protocol != ordinarySelectionScopeProtocol ||
				len(result.OrdinarySelectionPlan.SDKNamespaceRejections) == 0 || len(result.FeatureProfiles) == 0 || item.Diagnostic != nil) {
			return fmt.Errorf("SDK namespace source exclusion lacks its independent typed original-source proof")
		}
		if item.Kind == discoveryDocumentationKind &&
			(result.OrdinarySelectionPlan == nil || result.OrdinarySelectionPlan.DocumentationSourceProtocol != discoveryDocumentationProtocol ||
				len(result.OrdinarySelectionPlan.DocumentationPackages) == 0 || len(result.FeatureProfiles) == 0 || item.Diagnostic != nil) {
			return fmt.Errorf("documentation source exclusion lacks its independent typed original-source proof")
		}
		if isDiscoveryGoBuildInfrastructureFailure(item.Reason) {
			return fmt.Errorf("source not-applicable evidence contains an infrastructure failure: kind=%q files=%v targets=%v", item.Kind, files, item.Targets)
		}
		if discoverySourceRejectionRequiresDiagnostic(item.Kind) {
			if err := validateDiscoverySourceRejectionDiagnostic(item, result.sourceDiagnosticsCompacted); err != nil {
				return fmt.Errorf("source not-applicable evidence: kind=%q files=%v targets=%v: %w", item.Kind, files, item.Targets, err)
			}
		}
	}
	return nil
}

func discoveryConfigurationAsmFiles(configs []discoveryBuildConfiguration) []string {
	var files []string
	for _, config := range configs {
		files = append(files, config.AsmFiles...)
	}
	return uniqueSortedDiscoveryStrings(files)
}

func runDiscoveryCandidate(cfg discoveryCorpusConfig, candidate discoveryCandidate, workDir string) (result matrixReport, patterns []string, configurations []discoveryBuildConfiguration, runErr error) {
	// Own exactly this newly created candidate directory. Never delete a
	// caller's pre-existing workspace or the user's shared module cache.
	if err := os.Mkdir(workDir, 0755); err != nil {
		return matrixReport{}, nil, nil, err
	}
	defer func() {
		if err := removeDiscoveryCandidateWorkspace(workDir); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("clean candidate workspace: %w", err))
		}
	}()
	// Downloading metadata does not require the corpus build toolchain. Keep
	// this bootstrap workspace compatible with the root module's Go floor;
	// the later build plan still explicitly requires the current corpus Go.
	if err := os.WriteFile(filepath.Join(workDir, "go.mod"), []byte("module plan9asm.local/discovery\n\ngo 1.20\n"), 0644); err != nil {
		return matrixReport{}, nil, nil, fmt.Errorf("write temporary go.mod: %w", err)
	}
	var env []string
	var download moduleDownloadInfo
	err := cfg.runPhaseOperation(candidate, "download", "", func(ctx context.Context) error {
		var err error
		env, err = discoveryCandidateEnvironment(ctx, workDir, os.Environ())
		if err != nil {
			return err
		}
		if cfg.buildCache != "" {
			env = replaceEnv(env, map[string]string{"GOCACHE": cfg.buildCache})
		}
		return retryDiscoveryGoNetwork(ctx, []time.Duration{time.Second, 3 * time.Second}, func() error {
			downloadJSON, commandErr := runCapturedCommandOutput(
				ctx,
				workDir,
				env,
				"go",
				"mod",
				"download",
				"-json",
				candidate.Module+"@"+candidate.Version,
			)
			download, err = resolveModuleDownload(
				downloadJSON,
				commandErr,
				filepath.Join(workDir, "module-source"),
			)
			if err != nil {
				return fmt.Errorf("download module: %w", err)
			}
			return nil
		})
	})
	if err != nil {
		return matrixReport{}, nil, nil, err
	}
	var ordinaryPlan *discoveryOrdinarySelectionPlan
	var ordinaryProfiles []discoveryFeatureProfile
	var ordinaryConfigurations []discoveryBuildConfiguration
	var ordinarySourceItems []discoverySourceNotApplicableItem
	profileCache := &discoveryFeatureObservationCache{}
	profileMarkers := cfg.featureMarkerDir
	if profileMarkers == "" {
		profileMarkers = filepath.Join(workDir, "actual-feature-markers")
		if err := os.Mkdir(profileMarkers, 0700); err != nil {
			return matrixReport{}, nil, nil, err
		}
	} else if cfg.featureCache == nil {
		return matrixReport{}, nil, nil, fmt.Errorf("shared feature markers lack their owned observation cache")
	} else {
		profileCache = cfg.featureCache
	}
	var cppGoRoot string
	captureOrdinary := func() error {
		return cfg.runPhaseOperation(candidate, "ordinary_planning", "", func(ctx context.Context) error {
			var err error
			ordinaryPlan, ordinaryProfiles, ordinaryConfigurations, ordinarySourceItems, cppGoRoot, err = captureDiscoveryOrdinaryProfiles(ctx, candidate, download, cfg.Targets, workDir, env, discoveryProfileCaptureOptions{Markers: profileMarkers, Cache: profileCache, Translator: cfg.Translator, Events: cfg.phaseEvents})
			return err
		})
	}
	_, nativeConfigured := cfg.nativeLayoutSkips[candidate.exactKey()]
	_, privateConfigured := cfg.privateExtensionSkips[candidate.exactKey()]
	if len(candidate.AsmFiles) != 0 && !nativeConfigured && !privateConfigured {
		if err := captureOrdinary(); err != nil {
			return matrixReport{}, nil, nil, fmt.Errorf("capture exact ordinary/CPP inputs before package checks: %w", err)
		}
	}
	defer func() {
		// Target operations have already waited and cancelled their contexts.
		// Final source verification has its own bounded operation, before the
		// owned candidate workspace is released; no cancelled context is reused.
		if err := runDiscoveryOperation(cfg.CandidateTimeout, func(ctx context.Context) error {
			if ordinaryPlan != nil {
				ordinaryPlan.testDependencyContext = ctx
				ordinaryPlan.ordinaryDependencyContext = ctx
			}
			return verifyDiscoveryOrdinaryCPP(ordinaryPlan, download.Dir, cppGoRoot, candidate)
		}); err != nil {
			runErr = errors.Join(runErr, err)
		}
	}()
	var sourceNotApplicable []discoverySourceNotApplicableItem
	var nativePlan *discoveryNativeLayoutPlan
	var nativePlans []*discoveryNativeLayoutPlan
	if _, ok := cfg.nativeLayoutSkips[candidate.exactKey()]; ok {
		nativePlan = &discoveryNativeLayoutPlan{}
		nativePlans = append(nativePlans, nativePlan)
	}
	buildConfigurations := ordinaryConfigurations
	if ordinaryPlan != nil {
		sourceNotApplicable = ordinarySourceItems
	} else {
		buildConfigurations, err = discoveryBuildConfigurationsWithEvidence(candidate, download.Dir, cfg.Targets, &sourceNotApplicable, nativePlans...)
	}
	if err != nil {
		return matrixReport{}, nil, nil, fmt.Errorf("classify discovered assembly: %w", err)
	}
	if err := runDiscoveryOperation(cfg.CandidateTimeout, func(ctx context.Context) error {
		if ordinaryPlan != nil {
			ordinaryPlan.ordinaryDependencyContext = ctx
			ordinaryPlan.testDependencyContext = ctx
		}
		return verifyDiscoveryOrdinaryCPP(ordinaryPlan, download.Dir, cppGoRoot, candidate)
	}); err != nil {
		return matrixReport{}, nil, nil, err
	}
	var privateExtension *discoveryPrivateExtensionSkip
	if skip, ok := cfg.privateExtensionSkips[candidate.exactKey()]; ok {
		filtered, active, err := filterPrivateExtensionConfigurations(buildConfigurations, skip)
		if err != nil {
			return matrixReport{}, nil, nil, err
		}
		if active {
			if err := verifyPrivateExtensionSource(download.Dir, skip); err != nil {
				return matrixReport{}, nil, nil, err
			}
			if err := runDiscoveryOperation(cfg.CandidateTimeout, func(ctx context.Context) error {
				return verifyPrivateExtensionGoAssembler(ctx, workDir, download.Dir, env, skip)
			}); err != nil {
				return matrixReport{}, nil, nil, err
			}
			buildConfigurations = filtered
			privateExtension = &skip
		}
	}
	var nativeLayout *discoveryNativeLayoutSkip
	if skip, ok := cfg.nativeLayoutSkips[candidate.exactKey()]; ok {
		if privateExtension != nil {
			return matrixReport{}, nil, nil, fmt.Errorf("candidate has both native-layout and private-extension skips")
		}
		filtered, active, err := filterNativeLayoutConfigurations(buildConfigurations, skip)
		if err != nil {
			return matrixReport{}, nil, nil, err
		}
		if !active {
			return matrixReport{}, nil, nil, fmt.Errorf(
				"native-layout source %s on %s is not selected by Go build constraints",
				skip.AsmFile, strings.Join(skip.Targets, ","),
			)
		}
		if err := verifyNativeLayoutSource(download.Dir, skip); err != nil {
			return matrixReport{}, nil, nil, err
		}
		if err := runDiscoveryOperation(cfg.CandidateTimeout, func(ctx context.Context) error {
			return verifyNativeLayoutGoObject(ctx, workDir, download.Dir, env, skip)
		}); err != nil {
			return matrixReport{}, nil, nil, err
		}
		buildConfigurations = filtered
		nativeLayout = &skip
	}
	// Only an active, independently verified exception has a separate proof
	// protocol. A configured but unselected private exception remains ordinary.
	if ordinaryPlan == nil && nativeLayout == nil && privateExtension == nil && len(candidate.AsmFiles) != 0 {
		if err := captureOrdinary(); err != nil {
			return matrixReport{}, nil, nil, fmt.Errorf("capture ordinary selection/CPP inputs: %w", err)
		}
		buildConfigurations = ordinaryConfigurations
		sourceNotApplicable = ordinarySourceItems
	}
	if len(buildConfigurations) == 0 {
		aggregate := matrixReport{
			SourceNotApplicableItems: sourceNotApplicable,
			PrivateExtension:         privateExtension,
			NativeLayout:             nativeLayout,
			NativeLayoutPlan:         nativePlan,
			OrdinarySelectionPlan:    ordinaryPlan,
			FeatureProfiles:          ordinaryProfiles,
		}
		if ordinaryPlan != nil {
			modeObjects, err := runDiscoveryInstrumentation(cfg, candidate, download, ordinaryPlan, ordinaryProfiles, workDir, env)
			aggregate.Success, aggregate.InstrumentationTranslations = modeObjects, modeObjects
			aggregate.InstrumentationTargetExclusions = discoveryInstrumentationTargetExclusions(ordinaryPlan)
			aggregate.TotalAsm = modeObjects
			aggregate.TotalTargets = len(discoveryInstrumentationExecutedTargets(ordinaryPlan))
			if err == nil && modeObjects == 0 && discoveryInstrumentationSourceRejections(ordinaryPlan) != 0 {
				err = fmt.Errorf("original mode sources were rejected and no eligible candidate LLVM objects were compiled")
			}
			return aggregate, nil, buildConfigurations, err
		}
		return aggregate, nil, buildConfigurations, nil
	}
	testedCandidate := candidate
	if ordinaryPlan != nil {
		testedCandidate.AsmFiles, err = ordinarySelectionTestedAssembly(ordinaryPlan, candidate.AsmFiles)
		if err != nil {
			return matrixReport{}, nil, buildConfigurations, err
		}
	}
	embeddedAlias, hasEmbeddedAlias := cfg.embeddedAliases[candidate.exactKey()]
	if hasEmbeddedAlias {
		if err := prepareDiscoveryEmbeddedAlias(workDir, download, embeddedAlias); err != nil {
			return matrixReport{}, nil, buildConfigurations, fmt.Errorf("prepare embedded self-import: %w", err)
		}
	}
	declaredModule := candidate.Module
	if download.GoMod != "" {
		goModContents, err := os.ReadFile(download.GoMod)
		if err != nil {
			return matrixReport{}, nil, buildConfigurations, fmt.Errorf("read downloaded go.mod: %w", err)
		}
		declaredModule, err = parseDeclaredModulePath(goModContents)
		if err != nil {
			return matrixReport{}, nil, buildConfigurations, fmt.Errorf("read declared module path: %w", err)
		}
	}
	patternSet := make(map[string]bool)
	aggregate := matrixReport{
		SourceNotApplicableItems: sourceNotApplicable,
		PrivateExtension:         privateExtension,
		NativeLayout:             nativeLayout,
		NativeLayoutPlan:         nativePlan,
		OrdinarySelectionPlan:    ordinaryPlan,
		FeatureProfiles:          ordinaryProfiles,
	}
	runTargets := make(map[string]bool)
	executedBuildConfigurations := make([]discoveryBuildConfiguration, 0, len(buildConfigurations))
	invocationIndex := 0
	for _, buildConfiguration := range buildConfigurations {
		var activeProfile *discoveryFeatureProfile
		operationEnv := env
		if ordinaryPlan != nil {
			for index := range ordinaryProfiles {
				if ordinaryProfiles[index].ID == buildConfiguration.ProfileID {
					activeProfile = &ordinaryProfiles[index]
				}
			}
			if activeProfile == nil || len(buildConfiguration.Targets) != 1 || buildConfiguration.Targets[0] != activeProfile.Observed.Target {
				return matrixReport{}, nil, nil, fmt.Errorf("ordinary configuration lacks its exact actual target profile")
			}
			operationEnv = ordinaryProfileEnvironment(env, activeProfile.Observed)
		}
		applicableCandidate := candidate
		applicableCandidate.AsmFiles = buildConfiguration.AsmFiles
		plan, err := makeDiscoveryExecutionPlan(applicableCandidate, declaredModule)
		if err != nil {
			return matrixReport{}, nil, buildConfigurations, err
		}
		if hasEmbeddedAlias {
			plan, err = addDiscoveryEmbeddedAliasToPlan(plan, embeddedAlias)
			if err != nil {
				return matrixReport{}, nil, buildConfigurations, err
			}
		}
		if err := os.WriteFile(filepath.Join(workDir, "go.mod"), []byte(plan.GoMod), 0644); err != nil {
			return matrixReport{}, nil, buildConfigurations, fmt.Errorf("write exact module mapping: %w", err)
		}
		packageGroups := discoveryPackageGroupsForModule(applicableCandidate, plan.ModulePath)
		for _, target := range buildConfiguration.Targets {
			err := cfg.runPhaseOperation(candidate, "ordinary_target", fmt.Sprintf("%s/%s/%d", target, buildConfiguration.ProfileID, invocationIndex), func(ctx context.Context) error {
				if ordinaryPlan != nil {
					ordinaryPlan.testDependencyContext = ctx
					ordinaryPlan.ordinaryDependencyContext = ctx
				}
				guard := func(run func() error) (operationErr error) {
					if activeProfile != nil {
						if err := verifyDiscoveryProfileCurrent(ctx, profileMarkers, env, *activeProfile, profileCache); err != nil {
							return err
						}
						defer func() {
							if err := verifyDiscoveryProfileCurrent(ctx, profileMarkers, env, *activeProfile, profileCache); err != nil {
								operationErr = errors.Join(operationErr, err)
							}
						}()
					}
					return runDiscoveryOrdinaryGuarded(ordinaryPlan, download.Dir, cppGoRoot, candidate, run)
				}
				var targetAsmFiles []string
				var eligibleGroups []discoveryPackageGroup
				fortranProofs := make(map[string]discoveryFortranLoaderRejection)
				mixedPackageProofs := make(map[string]discoveryMixedPackageRejection)
				sdkNamespaceProofs := make(map[string]discoverySDKNamespaceRejection)
				buildErrors, err := runDiscoveryPackageChecksWithProof(packageGroups, func(patterns []string) error {
					return guard(func() error {
						return runDiscoveryGoBuild(ctx, workDir, operationEnv, target, buildConfiguration.BuildTags, patterns...)
					})
				}, func(group discoveryPackageGroup, failure error) (bool, error) {
					if activeProfile == nil {
						return false, nil
					}
					if isPotentialSDKNamespaceFailure(failure) {
						var proof discoverySDKNamespaceRejection
						err := guard(func() error {
							var err error
							proof, err = captureSDKNamespaceRejection(ctx, ordinaryPlan, *activeProfile, download.Dir, workDir,
								cppGoRoot, operationEnv, group, buildConfiguration.BuildTags, failure)
							return err
						})
						if err != nil {
							return false, err
						}
						ordinaryPlan.SDKNamespaceRejections = append(ordinaryPlan.SDKNamespaceRejections, proof)
						sdkNamespaceProofs[group.Pattern] = proof
						return true, nil
					}
					if isPotentialMixedPackageFailure(failure) {
						var proof discoveryMixedPackageRejection
						err := guard(func() error {
							var err error
							proof, err = captureMixedPackageRejection(ctx, ordinaryPlan, *activeProfile, download.Dir, workDir,
								cppGoRoot, operationEnv, group, buildConfiguration.BuildTags, failure)
							return err
						})
						if err != nil {
							return false, err
						}
						ordinaryPlan.MixedPackageRejections = append(ordinaryPlan.MixedPackageRejections, proof)
						mixedPackageProofs[group.Pattern] = proof
						return true, nil
					}
					if !isPotentialFortranLoaderFailure(group.Pattern, failure) {
						return false, nil
					}
					var proof discoveryFortranLoaderRejection
					err := guard(func() error {
						var err error
						proof, err = captureFortranLoaderRejection(ctx, ordinaryPlan, *activeProfile, download.Dir, workDir,
							cppGoRoot, operationEnv, group, buildConfiguration.BuildTags, failure)
						return err
					})
					if err != nil {
						return false, err
					}
					ordinaryPlan.FortranRejections = append(ordinaryPlan.FortranRejections, proof)
					fortranProofs[group.Pattern] = proof
					return true, nil
				})
				if err != nil {
					return fmt.Errorf("verify current Go packages for %s with build tags %v: %w",
						target, buildConfiguration.BuildTags, err)
				}
				var buildableGroups []discoveryPackageGroup
				for index, group := range packageGroups {
					if err := buildErrors[index]; err != nil {
						if proof, found := sdkNamespaceProofs[group.Pattern]; found {
							aggregate.SourceNotApplicableItems = append(aggregate.SourceNotApplicableItems, discoverySourceNotApplicableItem{
								ProfileID: proof.ProfileID, BuildTags: proof.BuildTags, AsmFiles: proof.AsmFiles,
								Targets: []string{proof.Target}, Kind: discoverySourceNotApplicableSDKNamespace, Reason: proof.Stderr,
							})
							continue
						}
						if proof, found := mixedPackageProofs[group.Pattern]; found {
							aggregate.SourceNotApplicableItems = append(aggregate.SourceNotApplicableItems, discoverySourceNotApplicableItem{
								ProfileID: proof.ProfileID, BuildTags: proof.BuildTags, AsmFiles: proof.AsmFiles,
								Targets: []string{proof.Target}, Kind: discoverySourceNotApplicableMixedPackage, Reason: proof.Stderr,
							})
							continue
						}
						if proof, found := fortranProofs[group.Pattern]; found {
							aggregate.SourceNotApplicableItems = append(aggregate.SourceNotApplicableItems, discoverySourceNotApplicableItem{
								ProfileID: proof.ProfileID, BuildTags: proof.BuildTags, AsmFiles: proof.AsmFiles,
								Targets: []string{proof.Target}, Kind: discoverySourceNotApplicableFortranLoader, Reason: proof.Stderr,
							})
							continue
						}
						aggregate.SourceNotApplicableItems = append(aggregate.SourceNotApplicableItems, discoverySourceNotApplicableItem{
							ProfileID: buildConfiguration.ProfileID,
							BuildTags: append([]string(nil), buildConfiguration.BuildTags...),
							AsmFiles:  append([]string(nil), group.AsmFiles...),
							Targets:   []string{target},
							Kind:      discoverySourceNotApplicableGoBuild,
							Reason:    discoveryCommandDiagnostic(err),
						})
						continue
					}
					buildableGroups = append(buildableGroups, group)
				}
				vetErrors, err := runDiscoveryPackageChecks(buildableGroups, func(patterns []string) error {
					return guard(func() error {
						return runDiscoveryAsmDecl(ctx, workDir, operationEnv, target, buildConfiguration.BuildTags, patterns)
					})
				})
				if err != nil {
					return fmt.Errorf("verify current Go asmdecl for %s with build tags %v: %w",
						target, buildConfiguration.BuildTags, err)
				}
				for index, group := range buildableGroups {
					validAsmFiles := append([]string(nil), group.AsmFiles...)
					if err := vetErrors[index]; err != nil {
						packageAsmFiles, packageErr := discoveryAsmDeclPackageFiles(
							testedCandidate, group, download.Dir, target, buildConfiguration.BuildTags,
							profileObservation(activeProfile),
						)
						if packageErr != nil {
							return fmt.Errorf("enumerate Go-selected assembly for %s on %s: %w",
								group.Pattern, target, packageErr)
						}
						rejected, classifyErr := classifyDiscoveryAsmDeclFailure(download.Dir, packageAsmFiles, testedCandidate.AsmFiles, err)
						foreignOnly := classifyErr != nil && discoveryAsmDeclOnlyForeignCandidateABI(
							download.Dir, testedCandidate.AsmFiles, packageAsmFiles, err,
						)
						if classifyErr != nil && !foreignOnly {
							return fmt.Errorf("verify current Go asmdecl for %s on %s: %w", group.Pattern, target, classifyErr)
						}
						if !foreignOnly {
							aggregate.SourceNotApplicableItems = append(aggregate.SourceNotApplicableItems, discoverySourceNotApplicableItem{
								ProfileID: buildConfiguration.ProfileID,
								BuildTags: append([]string(nil), buildConfiguration.BuildTags...),
								AsmFiles:  append([]string(nil), rejected...),
								Targets:   []string{target},
								Kind:      discoverySourceNotApplicableAsmDecl,
								Reason:    discoveryAsmDeclRejectionEvidence(download.Dir, err, rejected),
							})
							validAsmFiles = subtractDiscoveryStrings(validAsmFiles, rejected)
						}
					}
					if len(validAsmFiles) == 0 {
						continue
					}
					targetAsmFiles = append(targetAsmFiles, validAsmFiles...)
					eligibleGroups = append(eligibleGroups, discoveryPackageGroup{
						Pattern: group.Pattern, AsmFiles: validAsmFiles,
					})
				}
				if len(targetAsmFiles) == 0 {
					return nil
				}
				targetAsmFiles = uniqueSortedDiscoveryStrings(targetAsmFiles)
				executed := discoveryBuildConfiguration{
					ProfileID: buildConfiguration.ProfileID,
					BuildTags: append([]string(nil), buildConfiguration.BuildTags...),
					Targets:   []string{target},
					AsmFiles:  append([]string(nil), targetAsmFiles...),
				}
				executedBuildConfigurations = append(executedBuildConfigurations, executed)
				units := discoveryTranslationUnits(eligibleGroups)
				if err := validateDiscoveryTranslationUnits(units, targetAsmFiles); err != nil {
					return err
				}
				translations := make([]discoveryPendingTranslation, 0, len(units))
				for _, unit := range units {
					if activeProfile != nil && discoveryCPPFilesNeedGeneratedMetadata(ordinaryPlan.CPPInputs, unit.AsmFiles) {
						if len(ordinaryPlan.GeneratedHeaders) >= 4096 {
							return fmt.Errorf("actual generated-header queries exceed their explicit scope bound")
						}
						var metadata *gotoolprofile.MetadataProof
						if err := guard(func() error {
							var err error
							metadata, err = captureDiscoveryGeneratedHeaderQuery(ctx, ordinaryPlan, download, *activeProfile,
								buildConfiguration.BuildTags, discoveryPackageGroup{Pattern: unit.Patterns[0], AsmFiles: unit.AsmFiles},
								workDir, operationEnv, cfg.Translator, invocationIndex)
							return err
						}); err != nil {
							return fmt.Errorf("actual generated-header origin for %s on %s: %w", unit.Patterns[0], target, err)
						}
						ordinaryPlan.GeneratedHeaders = append(ordinaryPlan.GeneratedHeaders, discoveryGeneratedHeaderQuery{
							Target: target, ProfileID: activeProfile.ID, BuildTags: append([]string(nil), buildConfiguration.BuildTags...),
							AsmFiles: append([]string(nil), unit.AsmFiles...), Metadata: metadata,
						})
					}
					if activeProfile != nil {
						if err := guard(func() error {
							return captureDiscoveryTestDeclarationQuery(ctx, ordinaryPlan, download, *activeProfile,
								buildConfiguration.BuildTags, discoveryPackageGroup{Pattern: unit.Patterns[0], AsmFiles: unit.AsmFiles},
								workDir, operationEnv, cfg.Translator, invocationIndex)
						}); err != nil {
							return fmt.Errorf("actual missing test declaration pre-load source role: %w", err)
						}
					}
					patternSet[unit.Patterns[0]] = true
					reportPath := filepath.Join(workDir, fmt.Sprintf("matrix-report-%04d.json", invocationIndex))
					outputIndex := invocationIndex
					invocation := makeDiscoveryTranslatorInvocation(
						workDir,
						plan.ModulePath,
						unit.Patterns,
						buildConfiguration.BuildTags,
						[]string{target},
						unit.AsmFiles,
						discoveryTargetOutputDirectory(workDir, outputIndex),
						cfg.translatorSourceRoot(),
						cfg.LLC,
						reportPath,
					)
					if activeProfile != nil {
						input := ordinaryProfileConsumerInput(ordinaryPlan, *activeProfile, declaredModule, download.Dir, unit.AsmFiles, buildConfiguration.BuildTags)
						inputPath := filepath.Join(workDir, fmt.Sprintf("feature-input-%04d.json", invocationIndex))
						data, err := gotoolprofile.MarshalConsumerInput(input)
						if err != nil {
							return err
						}
						if err := os.WriteFile(inputPath, data, 0600); err != nil {
							return err
						}
						invocation.Args = append(invocation.Args, "-feature-profile="+inputPath, "-feature-timeout="+cfg.CandidateTimeout.String())
					}
					translations = append(translations, discoveryPendingTranslation{
						Unit:        unit,
						ReportPath:  reportPath,
						OutputIndex: outputIndex,
						Invocation:  invocation,
					})
					invocationIndex++
				}
				if err := verifyDiscoveryOrdinaryCPP(ordinaryPlan, download.Dir, cppGoRoot, candidate); err != nil {
					return err
				}
				if err := runDiscoveryBounded(ctx, len(translations), discoveryTranslationParallelism,
					func(ctx context.Context, index int) error {
						translation := translations[index]
						invocation := translation.Invocation
						if err := guard(func() error {
							return runCapturedCommand(ctx, invocation.Dir, operationEnv, cfg.Translator, invocation.Args...)
						}); err != nil {
							return fmt.Errorf("translate and compile package %s for %s with build tags %v: %w",
								translation.Unit.Patterns[0], target, buildConfiguration.BuildTags, err)
						}
						if err := verifyDiscoveryOrdinaryCPP(ordinaryPlan, download.Dir, cppGoRoot, candidate); err != nil {
							return err
						}
						return nil
					}); err != nil {
					return err
				}
				if err := verifyDiscoveryOrdinaryCPP(ordinaryPlan, download.Dir, cppGoRoot, candidate); err != nil {
					return err
				}
				for _, translation := range translations {
					targetCandidate := candidate
					targetCandidate.AsmFiles = translation.Unit.AsmFiles
					report, err := loadReport(translation.ReportPath)
					if err != nil {
						return err
					}
					if err := validateDiscoveryReport([]string{target}, targetCandidate, report); err != nil {
						return fmt.Errorf("package %s target %s build tags %v: %w",
							translation.Unit.Patterns[0], target, buildConfiguration.BuildTags, err)
					}
					runTargets[target] = true
					aggregate.TotalAsm += report.TotalAsm
					aggregate.Success += report.Success
					aggregate.NotApplicable += report.NotApplicable
					aggregate.Failed += report.Failed
					items := collectMatrixNotApplicableItems(report)
					if activeProfile != nil {
						items, err = summarizeDiscoveryTargetSkips(targetCandidate, items)
						if err != nil {
							return err
						}
						allowedABI := make(map[string]bool)
						for index := range items {
							items[index].ProfileID = activeProfile.ID
							items[index].BuildTags = append([]string(nil), buildConfiguration.BuildTags...)
							allowedABI[items[index].AsmFile] = true
						}
						if len(report.Targets) != 1 {
							return fmt.Errorf("actual profile consumer omitted its single target report")
						}
						proof := report.Targets[0].FeatureSelection
						input := ordinaryProfileConsumerInput(ordinaryPlan, *activeProfile, declaredModule, download.Dir, translation.Unit.AsmFiles, buildConfiguration.BuildTags)
						if err := gotoolprofile.ValidateSelectionWithABI(input, proof, buildConfiguration.BuildTags, true, allowedABI); err != nil {
							return fmt.Errorf("actual package/profile/CPP/LLVM consumption: %w", err)
						}
						aggregate.FeatureConsumption = append(aggregate.FeatureConsumption, proof)
					}
					aggregate.NotApplicableItems = append(aggregate.NotApplicableItems, items...)
					if err := removeDiscoveryTargetOutput(workDir, translation.OutputIndex); err != nil {
						return fmt.Errorf("remove target %s generated output: %w", target, err)
					}
				}
				return nil
			})
			if err != nil {
				return matrixReport{}, sortedDiscoverySet(patternSet), executedBuildConfigurations, err
			}
		}
	}
	aggregate.TotalTargets = len(runTargets)
	if ordinaryPlan != nil {
		modeObjects, err := runDiscoveryInstrumentation(cfg, candidate, download, ordinaryPlan, ordinaryProfiles, workDir, env)
		aggregate.InstrumentationTranslations = modeObjects
		aggregate.InstrumentationTargetExclusions = discoveryInstrumentationTargetExclusions(ordinaryPlan)
		aggregate.Success += modeObjects
		aggregate.TotalAsm += modeObjects
		for _, target := range discoveryInstrumentationExecutedTargets(ordinaryPlan) {
			runTargets[target] = true
		}
		aggregate.TotalTargets = len(runTargets)
		if err != nil {
			return aggregate, sortedDiscoverySet(patternSet), executedBuildConfigurations, err
		}
		if aggregate.Success == 0 && discoveryInstrumentationSourceRejections(ordinaryPlan) != 0 {
			return aggregate, sortedDiscoverySet(patternSet), executedBuildConfigurations,
				fmt.Errorf("original mode sources were rejected and no eligible candidate LLVM objects were compiled")
		}
	}
	return aggregate, sortedDiscoverySet(patternSet), executedBuildConfigurations, nil
}

func discoveryTargetOutputDirectory(workDir string, index int) string {
	return filepath.Join(workDir, "out", fmt.Sprintf("config-%04d", index))
}

func removeDiscoveryTargetOutput(workDir string, index int) error {
	return os.RemoveAll(discoveryTargetOutputDirectory(workDir, index))
}

func runDiscoveryOperation(timeout time.Duration, run func(context.Context) error) error {
	return runDiscoveryOperationContext(context.Background(), timeout, run)
}

func runDiscoveryOperationContext(parent context.Context, timeout time.Duration, run func(context.Context) error) error {
	if parent == nil {
		return fmt.Errorf("discovery operation requires its actual parent context")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	err := run(ctx)
	if contextErr := ctx.Err(); contextErr != nil {
		return errors.Join(err, contextErr)
	}
	return err
}

func discoveryCommandEnvironment(base []string) []string {
	// Direct GOPROXY fallback must not inherit a developer's URL rewrite to
	// SSH or block waiting for credentials to public source repositories.
	return replaceEnv(base, map[string]string{
		"CGO_ENABLED":       "0",
		"GIT_CONFIG_GLOBAL": os.DevNull,
		// Git maintenance may otherwise detach and keep mutating an owned
		// cache after Go returns. Ephemeral caches do not need background work.
		"GIT_CONFIG_COUNT":    "2",
		"GIT_CONFIG_KEY_0":    "gc.autoDetach",
		"GIT_CONFIG_VALUE_0":  "false",
		"GIT_CONFIG_KEY_1":    "maintenance.autoDetach",
		"GIT_CONFIG_VALUE_1":  "false",
		"GIT_TERMINAL_PROMPT": "0",
		"GOFLAGS":             "-mod=mod",
		"GOENV":               "off",
		"GOTOOLCHAIN":         "local",
		"GOWORK":              "off",
	})
}

func discoveryCandidateEnvironment(ctx context.Context, workDir string, base []string) ([]string, error) {
	env := discoveryCommandEnvironment(base)
	output, err := runCapturedCommandOutput(ctx, workDir, env, "go", "env", "-json", "GOMODCACHE", "GOPROXY")
	if err != nil {
		return nil, fmt.Errorf("read shared module cache configuration: %w", err)
	}
	var shared struct{ GOMODCACHE, GOPROXY string }
	if err := json.Unmarshal(output, &shared); err != nil {
		return nil, fmt.Errorf("decode shared module cache configuration: %w", err)
	}
	if err := os.Mkdir(filepath.Join(workDir, "tmp"), 0700); err != nil {
		return nil, fmt.Errorf("create candidate temporary directory: %w", err)
	}
	if err := os.Mkdir(filepath.Join(workDir, "build-cache"), 0700); err != nil {
		return nil, fmt.Errorf("create owned candidate build cache: %w", err)
	}
	return isolatedDiscoveryModuleEnvironment(env, workDir, shared.GOMODCACHE, shared.GOPROXY), nil
}

func isolatedDiscoveryModuleEnvironment(base []string, workDir, sharedCache, upstreamProxy string) []string {
	proxy := upstreamProxy
	if sharedCache != "" {
		cachePath := filepath.ToSlash(filepath.Join(sharedCache, "cache", "download"))
		if !strings.HasPrefix(cachePath, "/") {
			cachePath = "/" + cachePath
		}
		cacheURL := (&url.URL{Scheme: "file", Path: cachePath}).String()
		proxy = cacheURL
		if upstreamProxy != "" {
			proxy += "," + upstreamProxy
		}
	}
	return replaceEnv(base, map[string]string{
		"GOPATH":      filepath.Join(workDir, "gopath"),
		"GOMODCACHE":  filepath.Join(workDir, "module-cache"),
		"GOCACHE":     filepath.Join(workDir, "build-cache"),
		"GOCACHEPROG": "",
		"GOTMPDIR":    filepath.Join(workDir, "tmp"),
		"TMPDIR":      filepath.Join(workDir, "tmp"),
		"TMP":         filepath.Join(workDir, "tmp"),
		"TEMP":        filepath.Join(workDir, "tmp"),
		"GOPROXY":     proxy,
		"GOFLAGS":     "-mod=mod -modcacherw",
	})
}

func removeDiscoveryCandidateWorkspace(workDir string) error {
	return retryDiscoveryWorkspaceCleanup(20, 100*time.Millisecond, func() error {
		return removeDiscoveryCandidateWorkspaceOnce(workDir)
	})
}

// Even after terminating subprocesses, an in-flight filesystem operation can
// race directory removal. Bound retries to ENOTEMPTY; all persistent failures
// remain errors and no shared or caller-owned cache is touched.
func retryDiscoveryWorkspaceCleanup(attempts int, delay time.Duration, remove func() error) error {
	for attempt := 1; ; attempt++ {
		err := remove()
		if err == nil || attempt >= attempts || !errors.Is(err, syscall.ENOTEMPTY) {
			return err
		}
		time.Sleep(delay)
	}
}

func removeDiscoveryCandidateWorkspaceOnce(workDir string) error {
	// Go normally extracts read-only module directories. Only walk this owned
	// candidate tree; WalkDir does not follow symlinks into any shared cache.
	if err := filepath.WalkDir(workDir, func(name string, entry os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if err := os.Chmod(name, 0700); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return os.RemoveAll(workDir)
}

func resolveModuleDownload(downloadJSON []byte, commandErr error, extractDir string) (moduleDownloadInfo, error) {
	var download moduleDownloadInfo
	if err := json.Unmarshal(downloadJSON, &download); err != nil {
		if commandErr != nil {
			return moduleDownloadInfo{}, commandErr
		}
		return moduleDownloadInfo{}, fmt.Errorf("decode module download metadata: %w", err)
	}
	if download.Dir != "" {
		if info, err := os.Stat(download.Dir); err == nil && info.IsDir() {
			return download, nil
		}
	}
	if download.Zip != "" {
		if err := extractModuleZip(download.Zip, extractDir, download.Path, download.Version); err == nil {
			download.Dir = extractDir
			if download.GoMod == "" {
				download.GoMod = filepath.Join(extractDir, "go.mod")
			}
			return download, nil
		} else if commandErr == nil && download.Error == "" {
			return moduleDownloadInfo{}, fmt.Errorf("extract cached module ZIP: %w", err)
		}
	}
	if download.Error != "" {
		return moduleDownloadInfo{}, errors.New(download.Error)
	}
	if commandErr != nil {
		return moduleDownloadInfo{}, commandErr
	}
	return moduleDownloadInfo{}, errors.New("module download metadata contains neither a directory nor a usable ZIP")
}

func extractModuleZip(zipPath, destination, modulePath, version string) error {
	if err := module.Check(modulePath, version); err != nil {
		return fmt.Errorf("validate module version: %w", err)
	}
	// Module cache file names escape uppercase letters (for example, Upper
	// becomes !upper), but paths inside a module ZIP retain the canonical,
	// unescaped module path and version.
	prefix := modulePath + "@" + version + "/"
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	if err := os.MkdirAll(destination, 0755); err != nil {
		return err
	}
	for _, file := range reader.File {
		name := filepath.ToSlash(file.Name)
		if !strings.HasPrefix(name, prefix) {
			return fmt.Errorf("module ZIP entry %q is outside expected prefix %q", file.Name, prefix)
		}
		relative := strings.TrimPrefix(name, prefix)
		if relative == "" {
			continue
		}
		clean := path.Clean(relative)
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
			return fmt.Errorf("unsafe module ZIP path %q", file.Name)
		}
		target := filepath.Join(destination, filepath.FromSlash(clean))
		rel, err := filepath.Rel(destination, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe module ZIP path %q", file.Name)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if !file.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-regular module ZIP entry %q", file.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		source, err := file.Open()
		if err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err == nil {
			_, err = io.Copy(output, source)
		}
		closeOutputErr := error(nil)
		if output != nil {
			closeOutputErr = output.Close()
		}
		closeSourceErr := source.Close()
		if err != nil {
			return err
		}
		if closeOutputErr != nil {
			return closeOutputErr
		}
		if closeSourceErr != nil {
			return closeSourceErr
		}
	}
	return nil
}

func runDiscoveryGoBuild(ctx context.Context, dir string, env []string, target string, buildTags []string, patterns ...string) error {
	goos, goarch, ok := strings.Cut(target, "/")
	if !ok || goos == "" || goarch == "" {
		return fmt.Errorf("invalid discovery target %q", target)
	}
	// Compile the exact packages and their dependencies, including assembly,
	// without requiring a main package to final-link. Library coverage belongs
	// here; executable linking and execution have separate compatibility gates.
	// Do not use -e or -find: compiler/assembler errors must remain failures.
	args := []string{"list", "-export", "-mod=mod"}
	if len(buildTags) != 0 {
		args = append(args, "-tags="+strings.Join(buildTags, ","))
	}
	args = append(args, patterns...)
	targetEnv := replaceEnv(env, map[string]string{
		"CGO_ENABLED": "0",
		"GOOS":        goos,
		"GOARCH":      goarch,
	})
	return retryDiscoveryGoNetwork(ctx, []time.Duration{time.Second, 3 * time.Second}, func() error {
		return runCapturedCommand(ctx, dir, targetEnv, "go", args...)
	})
}

// Check all selected packages in one Go invocation when possible. This lets
// Go share package loading and parallel compilation across sibling assembly
// packages. On a source failure, repeat each package independently so the
// corpus can record exact source-inapplicability evidence. Infrastructure
// failures remain fatal, including failures from the initial batch.
func runDiscoveryPackageChecks(
	groups []discoveryPackageGroup,
	check func([]string) error,
) ([]error, error) {
	return runDiscoveryPackageChecksWithProof(groups, check, nil)
}

// A typed source-role proof may discharge its one exact package failure.
// Infrastructure/source-guard failures still take precedence, and every other
// no-position diagnostic retains the original hard failure behavior.
func runDiscoveryPackageChecksWithProof(
	groups []discoveryPackageGroup,
	check func([]string) error,
	prove func(discoveryPackageGroup, error) (bool, error),
) ([]error, error) {
	results := make([]error, len(groups))
	if len(groups) == 0 {
		return results, nil
	}
	if len(groups) > 1 {
		patterns := make([]string, 0, len(groups))
		for _, group := range groups {
			patterns = append(patterns, group.Pattern)
		}
		if err := check(patterns); err == nil {
			return results, nil
		} else if isDiscoveryInfrastructureFailure(err) {
			return nil, err
		}
	}
	for index, group := range groups {
		results[index] = check([]string{group.Pattern})
		if isDiscoveryInfrastructureFailure(results[index]) {
			return nil, fmt.Errorf("package %s: %w", group.Pattern, results[index])
		}
		if results[index] != nil && prove != nil {
			accepted, err := prove(group, results[index])
			if err != nil {
				return nil, fmt.Errorf("package %s source-role proof: %w", group.Pattern, err)
			}
			if accepted {
				continue
			}
		}
		if results[index] != nil && !hasDiscoveryConcreteSourceDiagnostic(discoveryCommandDiagnostic(results[index])) {
			return nil, fmt.Errorf("package %s lacks a concrete source rejection diagnostic (not N/A): %w", group.Pattern, results[index])
		}
	}
	return results, nil
}

// Run independent package operations with a fixed worker count. The first
// failure cancels in-flight commands, but every worker exits before returning
// so no child process can outlive the candidate workspace that owns it.
func runDiscoveryBounded(
	parent context.Context,
	count, limit int,
	run func(context.Context, int) error,
) error {
	if limit <= 0 {
		return fmt.Errorf("discovery parallelism must be positive")
	}
	if count == 0 {
		return parent.Err()
	}
	if limit > count {
		limit = count
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	jobs := make(chan int)
	var workers sync.WaitGroup
	var firstFailure sync.Once
	var firstErr error
	for worker := 0; worker < limit; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					continue
				}
				if err := run(ctx, index); err != nil {
					firstFailure.Do(func() {
						firstErr = err
						cancel()
					})
				}
			}
		}()
	}
dispatch:
	for index := 0; index < count; index++ {
		select {
		case <-ctx.Done():
			break dispatch
		case jobs <- index:
		}
	}
	close(jobs)
	workers.Wait()
	if firstErr != nil {
		return firstErr
	}
	return parent.Err()
}

// Downloading a module and building its dependencies can both encounter
// transient proxy failures. Retry only network diagnostics within the original
// operation deadline. Source, checksum, resource and toolchain errors need a
// different fix and must not be hidden behind repeated attempts.
func retryDiscoveryGoNetwork(ctx context.Context, delays []time.Duration, operation func() error) error {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := operation()
		if err == nil || attempt >= len(delays) || !isDiscoveryRetryableNetworkFailure(discoveryCommandDiagnostic(err)) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-time.After(delays[attempt]):
		}
	}
}

func isDiscoveryInfrastructureFailure(err error) bool {
	if err == nil {
		return false
	}
	var sourceProof *discoverySourceProofError
	if errors.As(err, &sourceProof) {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, errDiscoveryPhaseEvents) ||
		errors.Is(err, errDiscoveryCommandOutputExceeded) ||
		errors.Is(err, errDiscoveryAsmDeclSourceProof) ||
		errors.Is(err, exec.ErrWaitDelay) ||
		errors.Is(err, errDiscoveryCommandCleanup) ||
		isDiscoveryGoBuildInfrastructureFailure(discoveryCommandDiagnostic(err)) {
		return true
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() <= 0 {
		return true
	}
	var failure *discoveryCapturedCommandError
	// An empty failed tool invocation proves no source incompatibility. Keep it
	// visible for retry/diagnosis instead of excluding an entire package.
	return errors.As(err, &failure) && strings.TrimSpace(failure.output) == ""
}

func runDiscoveryAsmDecl(ctx context.Context, dir string, env []string, target string, buildTags, patterns []string) error {
	goos, goarch, ok := strings.Cut(target, "/")
	if !ok || goos == "" || goarch == "" {
		return fmt.Errorf("invalid discovery target %q", target)
	}
	targetEnv := replaceEnv(env, map[string]string{
		"CGO_ENABLED": "0",
		"GOENV":       "off",
		"GOOS":        goos,
		"GOARCH":      goarch,
	})
	err := runDiscoveryAsmDeclDirect(ctx, dir, targetEnv, buildTags, patterns, "")
	if err == nil {
		return nil
	}
	// A test-only dependency may fail at the proxy before vet inspects valid
	// production assembly. Retry without tests for transient network errors;
	// resource, integrity, and toolchain failures still stop immediately.
	if isDiscoveryInfrastructureFailure(err) &&
		!isDiscoveryRetryableNetworkFailure(discoveryCommandDiagnostic(err)) {
		return err
	}
	if ctx.Err() != nil {
		return err
	}
	if _, observed := discoveryAsmDeclObservedFailures(err); !observed {
		return errors.Join(err, fmt.Errorf("%w: asmdecl analysis did not finish with plain exit 1", errDiscoveryAsmDeclSourceProof))
	}
	err = filterDiscoveryAsmDeclTextMetadata(ctx, dir, targetEnv, buildTags, patterns, "", err)
	if err == nil || errors.Is(err, errDiscoveryAsmDeclSourceProof) {
		return err
	}
	// Completed actual analysis of a selected test variant must not lose a
	// concrete ABI/result-write obligation when the retry removes its Go
	// declaration. Only the independent typed/source result proof may remove
	// the precise alias RET warning; real typed mismatches remain unchanged.
	if discoveryAsmDeclHasCompletedABIObligation(err) {
		return err
	}
	// go vet type-checks package tests before running asmdecl. Old modules can
	// have tests that no longer compile or import another package with an ABI
	// mismatch even though their production package builds. Retry against
	// temporary module copies with only *_test.go files emptied so unrelated
	// diagnostics cannot hide this package's assembly ABI result.
	// Go forbids overlays beneath GOMODCACHE, hence the explicit module copies.
	retryErr := runDiscoveryAsmDeclWithTestlessModuleCopies(ctx, dir, targetEnv, nil, buildTags, patterns)
	if ctxErr := ctx.Err(); ctxErr != nil {
		if retryErr != nil {
			return retryErr
		}
		return fmt.Errorf("go vet -asmdecl: %w", ctxErr)
	}
	if retryErr != nil && isDiscoveryAsmDeclABIMismatch(discoveryCommandDiagnostic(retryErr)) {
		return retryErr
	}
	if isDiscoveryInfrastructureFailure(retryErr) {
		return retryErr
	}
	if retryErr != nil {
		if discoveryAsmDeclOnlyKnownNonABIWarnings(retryErr) {
			return nil
		}
		if errors.Is(retryErr, errDiscoveryAsmDeclNoSelectedTests) {
			if discoveryAsmDeclOnlyKnownNonABIWarnings(err) {
				return nil
			}
			// No retry ran. Preserve the original source/ABI failure without
			// mislabeling a genuine per-package mismatch as infrastructure.
			return err
		}
		return errors.Join(err, fmt.Errorf("%w: testless go vet did not clear the original failure: %w", errDiscoveryAsmDeclSourceProof, retryErr))
	}
	return nil
}

type discoveryGoListPackage struct {
	ImportPath   string
	Dir          string
	SFiles       []string
	TestGoFiles  []string
	XTestGoFiles []string
	Module       *struct {
		Path    string
		Version string
		Dir     string
		GoMod   string
	}
}

func runDiscoveryAsmDeclWithTestlessModuleCopies(ctx context.Context, dir string, env, _ []string, buildTags, patterns []string) (result error) {
	dir, err := directAsmDeclPhysicalDirectory(dir)
	if err != nil {
		return err
	}
	env = replaceEnv(env, map[string]string{"GOENV": "off"})
	listArgs := []string{"list", "-json"}
	if len(buildTags) != 0 {
		listArgs = append(listArgs, "-tags="+strings.Join(buildTags, ","))
	}
	listArgs = append(listArgs, patterns...)
	output, err := runCapturedCommandOutput(ctx, dir, env, "go", listArgs...)
	if err != nil {
		return err
	}

	goModPath := filepath.Join(dir, "go.mod")
	goModData, err := os.ReadFile(goModPath)
	if err != nil {
		return err
	}
	parsedGoMod, err := modfile.Parse(goModPath, goModData, nil)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(output))
	packages := make([]discoveryGoListPackage, 0)
	for {
		var pkg discoveryGoListPackage
		if err := decoder.Decode(&pkg); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		packages = append(packages, pkg)
	}

	stages := make(map[string]string)
	hasTests := false
	for _, pkg := range packages {
		if len(pkg.TestGoFiles)+len(pkg.XTestGoFiles) == 0 {
			continue
		}
		hasTests = true
		if pkg.Module == nil || pkg.Module.Path == "" || pkg.Module.Dir == "" {
			return fmt.Errorf("cannot create testless asmdecl copy for package %s without module metadata", pkg.Dir)
		}
		stage := stages[pkg.Module.Dir]
		if stage == "" {
			stage, err = os.MkdirTemp("", "plan9asm-vet-module-")
			if err != nil {
				return err
			}
			stage, err = filepath.EvalSymlinks(stage)
			if err != nil {
				return err
			}
			stageInfo, err := os.Lstat(stage)
			if err != nil || !stageInfo.IsDir() {
				return fmt.Errorf("testless asmdecl stage has no physical directory identity: %v", err)
			}
			defer func(stage string, expected os.FileInfo) {
				current, err := os.Lstat(stage)
				if err != nil || !current.IsDir() || !os.SameFile(current, expected) {
					result = errors.Join(result, fmt.Errorf("%w: testless asmdecl directory changed; not removed: %v", errDiscoveryCommandCleanup, err))
					return
				}
				if err := os.RemoveAll(stage); err != nil {
					result = errors.Join(result, fmt.Errorf("%w: remove testless asmdecl directory: %v", errDiscoveryCommandCleanup, err))
				}
			}(stage, stageInfo)
			if err := copyDiscoveryModuleTree(pkg.Module.Dir, stage); err != nil {
				return err
			}
			stagedGoMod := filepath.Join(stage, "go.mod")
			if _, err := os.Stat(stagedGoMod); os.IsNotExist(err) {
				moduleGoMod, readErr := os.ReadFile(pkg.Module.GoMod)
				if readErr != nil {
					return readErr
				}
				if err := os.WriteFile(stagedGoMod, moduleGoMod, 0644); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			if err := parsedGoMod.AddReplace(pkg.Module.Path, pkg.Module.Version, stage, ""); err != nil {
				return err
			}
			stages[pkg.Module.Dir] = stage
		}
		for _, fileName := range append(append([]string(nil), pkg.TestGoFiles...), pkg.XTestGoFiles...) {
			sourcePath := filepath.Join(pkg.Dir, fileName)
			relativePath, err := filepath.Rel(pkg.Module.Dir, sourcePath)
			if err != nil || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
				return fmt.Errorf("test file %s is outside module %s", sourcePath, pkg.Module.Dir)
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), sourcePath, nil, parser.PackageClauseOnly)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(stage, relativePath), []byte("package "+parsed.Name.Name+"\n"), 0644); err != nil {
				return err
			}
		}
	}
	if !hasTests {
		return errDiscoveryAsmDeclNoSelectedTests
	}
	// AddReplace removes superseded version-specific entries by clearing
	// their syntax. Remove those tombstones before rebasing local origins.
	parsedGoMod.Cleanup()
	commandDir := dir
	for _, pkg := range packages {
		if pkg.Module != nil && parsedGoMod.Module != nil && pkg.Module.Path == parsedGoMod.Module.Mod.Path {
			if stage := stages[pkg.Module.Dir]; stage != "" {
				// A replace directive cannot replace the main module itself.
				// Run against its actual testless copy; preserve original
				// relative dependency-replacement origins when moving CWD.
				commandDir = stage
				for _, replacement := range parsedGoMod.Replace {
					if replacement.New.Version == "" && !filepath.IsAbs(replacement.New.Path) {
						origin, err := filepath.Abs(filepath.Join(dir, replacement.New.Path))
						if err != nil {
							return err
						}
						// AddReplace with a wildcard old version removes exact
						// overrides. Rebase this syntax token in place instead,
						// retaining every original old-version selection scope.
						if replacement.Syntax == nil {
							return fmt.Errorf("local replacement has no original syntax")
						}
						arrow := -1
						for index, token := range replacement.Syntax.Token {
							if token == "=>" {
								if arrow >= 0 {
									return fmt.Errorf("local replacement has ambiguous syntax")
								}
								arrow = index
							}
						}
						if arrow < 0 || arrow+2 != len(replacement.Syntax.Token) {
							return fmt.Errorf("local replacement has incomplete syntax")
						}
						replacement.New.Path = origin
						replacement.Syntax.Token[arrow+1] = modfile.AutoQuote(origin)
					}
				}
				break
			}
		}
	}
	formattedGoMod, err := parsedGoMod.Format()
	if err != nil {
		return err
	}
	modfilePath := filepath.Join(commandDir, ".plan9asm-vet.mod")
	if err := os.WriteFile(modfilePath, formattedGoMod, 0644); err != nil {
		return err
	}
	// Go uses the alternate modfile's own .sum, not the original go.sum.
	// Seed it from this invocation's original input, replacing stale retry
	// state without changing the real module's checksum file.
	goSum, err := os.ReadFile(filepath.Join(dir, "go.sum"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	sumfilePath := strings.TrimSuffix(modfilePath, ".mod") + ".sum"
	if err := os.WriteFile(sumfilePath, goSum, 0644); err != nil {
		return err
	}
	err = runDiscoveryAsmDeclDirect(ctx, commandDir, env, buildTags, patterns, modfilePath)
	// Inspect staged sources before their owning temporary modules are removed.
	err = filterDiscoveryAsmDeclTextMetadata(ctx, commandDir, env, buildTags, patterns, modfilePath, err)
	if failures, observed := discoveryAsmDeclObservedFailures(err); observed {
		origins := make(map[string]string, len(stages))
		for original, stage := range stages {
			physicalOriginal, originalErr := filepath.EvalSymlinks(original)
			physicalStage, stageErr := filepath.EvalSymlinks(stage)
			if originalErr != nil || stageErr != nil {
				return errors.Join(err, fmt.Errorf("%w: bind original testless source origins", errDiscoveryAsmDeclSourceProof))
			}
			origins[physicalStage] = physicalOriginal
		}
		for _, failure := range failures {
			failure.asmdeclOrigins = origins
		}
	}
	return err
}

func copyDiscoveryModuleTree(source, destination string) error {
	return filepath.Walk(source, func(sourcePath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relativePath, err := filepath.Rel(source, sourcePath)
		if err != nil {
			return err
		}
		destinationPath := filepath.Join(destination, relativePath)
		if info.IsDir() {
			return os.MkdirAll(destinationPath, info.Mode().Perm()|0700)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-regular module file %s", sourcePath)
		}
		contents, err := os.ReadFile(sourcePath)
		if err != nil {
			return err
		}
		return os.WriteFile(destinationPath, contents, info.Mode().Perm()|0600)
	})
}

func isDiscoveryAsmDeclABIMismatch(diagnostic string) bool {
	diagnostic = strings.ToLower(diagnostic)
	for _, line := range strings.Split(diagnostic, "\n") {
		if strings.Contains(line, "wrong argument size") || strings.Contains(line, "invalid offset") {
			return true
		}
		// asmdecl compares type kinds as well as byte widths. In particular,
		// MOVOU's 16-byte kind differs from asmArray even for [2]uint64.
		// An equal-width type warning must still reach translation; actual
		// width/offset/argument-size failures remain scoped ABI N/A.
		if strings.Contains(line, ": invalid ") && strings.Contains(line, "(fp)") &&
			!isDiscoveryAsmDeclEqualWidthMove(line) {
			return true
		}
	}
	return false
}

func discoveryAsmDeclRejectedFiles(asmFiles []string, diagnostic string) []string {
	diagnostic = filepath.ToSlash(diagnostic)
	rejected := make(map[string]bool)
	for _, line := range strings.Split(diagnostic, "\n") {
		if !isDiscoveryAsmDeclABIMismatch(line) {
			continue
		}
		for _, asmFile := range asmFiles {
			if discoveryAsmDeclLineNamesFile(line, asmFile) {
				rejected[asmFile] = true
			}
		}
	}
	return sortedDiscoverySet(rejected)
}

// go vet -asmdecl reports every file selected in a package, including a
// default-tag file when this corpus configuration was seeded by a tagged file.
// Expand only the diagnostic attribution set. Translation still uses the
// minimal file/target configurations selected by discovery.
func discoveryAsmDeclPackageFiles(
	candidate discoveryCandidate,
	group discoveryPackageGroup,
	moduleDir, target string,
	buildTags []string,
	profiles ...*discoveryTargetFeatures,
) ([]string, error) {
	if len(profiles) > 1 {
		return nil, fmt.Errorf("assembly package selection accepts one actual target profile")
	}
	if len(group.AsmFiles) == 0 {
		return nil, fmt.Errorf("empty assembly package group")
	}
	goos, goarch, ok := strings.Cut(target, "/")
	if !ok || goos == "" || goarch == "" {
		return nil, fmt.Errorf("invalid discovery target %q", target)
	}
	ctx := build.Default
	ctx.GOOS = goos
	ctx.GOARCH = goarch
	ctx.Compiler = "gc"
	ctx.CgoEnabled = false
	if len(profiles) == 1 && profiles[0] != nil {
		if profiles[0].Target != target {
			return nil, fmt.Errorf("assembly package selection profile differs from its target")
		}
		actualContext, err := discoveryContextForFeatureProfile(profiles[0])
		if err != nil {
			return nil, err
		}
		ctx = actualContext
	}
	ctx.BuildTags = buildTags

	dirRel := path.Dir(group.AsmFiles[0])
	dir := filepath.Join(moduleDir, filepath.FromSlash(dirRel))
	for _, asmFile := range group.AsmFiles[1:] {
		if path.Dir(asmFile) != dirRel {
			return nil, fmt.Errorf("assembly package group spans multiple directories")
		}
	}
	selected := make(map[string]bool, len(candidate.AsmFiles))
	for _, asmFile := range candidate.AsmFiles {
		if path.Dir(asmFile) != dirRel {
			continue
		}
		matches, err := ctx.MatchFile(dir, path.Base(asmFile))
		if err != nil {
			return nil, fmt.Errorf("match assembly %s for %s with tags %v: %w",
				asmFile, target, buildTags, err)
		}
		if matches {
			selected[asmFile] = true
		}
	}
	for _, asmFile := range group.AsmFiles {
		if !selected[asmFile] {
			return nil, fmt.Errorf("selected package source %s does not match Go build constraints", asmFile)
		}
	}
	return sortedDiscoverySet(selected), nil
}

func classifyDiscoveryAsmDeclFailure(moduleDir string, asmFiles, candidateFiles []string, err error) ([]string, error) {
	if err == nil {
		return nil, nil
	}
	if isDiscoveryInfrastructureFailure(err) {
		return nil, err
	}
	if discoveryAsmDeclOnlyUnprovedResults(moduleDir, asmFiles, err) &&
		discoveryAsmDeclLocationsBelongToCandidate(moduleDir, candidateFiles, err) {
		return nil, fmt.Errorf("go vet unproved_result_initialization (still failed, not source N/A): %w", err)
	}
	lines, complete := discoveryAsmDeclCompleteABIDiagnostics(candidateFiles, err)
	if !complete || !discoveryAsmDeclLocationsBelongToCandidate(moduleDir, candidateFiles, err) {
		return nil, fmt.Errorf("go vet failed without a complete attributable ABI-only analysis: %w", err)
	}
	rejectedSet := make(map[string]bool)
	for _, line := range lines {
		for _, file := range asmFiles {
			if discoveryAsmDeclLineMatchesOriginalFile(moduleDir, line, file, err) {
				rejectedSet[file] = true
			}
		}
	}
	rejected := sortedDiscoverySet(rejectedSet)
	if len(rejected) == 0 {
		return nil, fmt.Errorf("go vet ABI mismatch does not identify an applicable assembly file: %w", err)
	}
	return rejected, nil
}

// A package's vet action can report an ABI mismatch in another package from
// the same discovered module. That other file has its own package/target
// verification; do not assign its mismatch to the package under inspection.
// Unknown files and infrastructure failures still stop the candidate.
func discoveryAsmDeclOnlyForeignCandidateABI(
	moduleDir string,
	candidateFiles, packageFiles []string,
	err error,
) bool {
	lines, complete := discoveryAsmDeclCompleteABIDiagnostics(candidateFiles, err)
	if !complete || !discoveryAsmDeclLocationsBelongToCandidate(moduleDir, candidateFiles, err) {
		return false
	}
	for _, line := range lines {
		for _, file := range packageFiles {
			if discoveryAsmDeclLineMatchesOriginalFile(moduleDir, line, file, err) {
				return false
			}
		}
	}
	return true
}

func discoveryAsmDeclLineNamesFile(line, asmFile string) bool {
	asmFile = filepath.ToSlash(asmFile)
	end := strings.LastIndex(line, ".s:")
	if end < 0 {
		return false
	}
	reported := strings.TrimSpace(line[:end+2])
	if strings.Contains(reported, "/") {
		return reported == asmFile || strings.HasSuffix(reported, "/"+asmFile)
	}
	return reported == path.Base(asmFile)
}

func discoveryAsmDeclRejectionEvidence(moduleDir string, err error, rejected []string) string {
	if err == nil {
		return ""
	}
	var proof []string
	seen := make(map[string]bool, len(rejected))
	for _, line := range strings.Split(filepath.ToSlash(discoveryCommandDiagnostic(err)), "\n") {
		if !discoveryAsmDeclConcreteABIWarning(strings.TrimSpace(line)) {
			continue
		}
		for _, asmFile := range rejected {
			if !seen[asmFile] && discoveryAsmDeclLineMatchesOriginalFile(moduleDir, strings.TrimSpace(line), asmFile, err) {
				proof = append(proof, line)
				seen[asmFile] = true
			}
		}
	}
	if len(proof) == 0 {
		return "asmdecl failed without physically attributable rejection evidence"
	}
	return limitDiscoveryEvidence(strings.Join(proof, "\n"), 8192)
}

func subtractDiscoveryStrings(values, removed []string) []string {
	removeSet := make(map[string]bool, len(removed))
	for _, value := range removed {
		removeSet[value] = true
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !removeSet[value] {
			out = append(out, value)
		}
	}
	return out
}

func limitDiscoveryEvidence(message string, maxBytes int) string {
	message = strings.TrimSpace(message)
	if maxBytes <= 0 || len(message) <= maxBytes {
		return message
	}
	return message[:maxBytes] + "\n... evidence truncated ..."
}

func collectMatrixNotApplicableItems(report matrixReport) []matrixTargetNotApplicableItem {
	var items []matrixTargetNotApplicableItem
	for _, target := range report.Targets {
		targetName := target.Goos + "/" + target.Goarch
		for _, item := range target.NotApplicableItems {
			items = append(items, matrixTargetNotApplicableItem{Target: targetName, targetNotApplicableItem: item})
		}
	}
	return items
}

func sortedDiscoverySet(set map[string]bool) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func runCapturedCommand(ctx context.Context, dir string, env []string, name string, args ...string) error {
	_, err := runCapturedCommandOutput(ctx, dir, env, name, args...)
	return err
}

const discoveryCommandOutputLimit = 8 << 20

var errDiscoveryCommandOutputExceeded = errors.New("captured output exceeds limit")

var errDiscoveryCommandCleanup = errors.New("terminate discovery command group")

// Keep the bounded complete diagnostic for classification and source-rejection
// reports, while keeping ordinary error displays compact. Trimming display text
// must never change which assembly files are excluded by an ABI error or the
// digest of the original source diagnostic retained in a frozen report.
type discoveryCapturedCommandError struct {
	command string
	cause   error
	output  string
	display string
	// Physical command identity and producer-owned testless aliases are not
	// portable status flags. They prevent basename/suffix-only attribution.
	directory      string
	asmdeclOrigins map[string]string
}

func (failure *discoveryCapturedCommandError) Error() string {
	if failure.display == "" {
		return fmt.Sprintf("%s: %v", failure.command, failure.cause)
	}
	return fmt.Sprintf("%s: %v\n%s", failure.command, failure.cause, failure.display)
}

func (failure *discoveryCapturedCommandError) Unwrap() error {
	return failure.cause
}

func discoveryCommandDiagnostic(err error) string {
	return discoveryCommandDiagnosticDepth(err, 0)
}

func discoveryCommandDiagnosticDepth(err error, depth int) string {
	if err == nil {
		return ""
	}
	if failure, direct := err.(*discoveryCapturedCommandError); direct {
		// Replace the compact display, rather than appending the full output.
		// A tail-only display can start inside an asmdecl error and invent an
		// unattributable ABI diagnostic even though its complete line names
		// an exact file. Preserve surrounding context from wrapped errors.
		return fmt.Sprintf("%s: %v\n%s", failure.command, failure.cause, failure.output)
	}
	message := err.Error()
	if depth >= 64 {
		return message
	}
	var children []error
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children = joined.Unwrap()
	} else if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		children = []error{wrapped.Unwrap()}
	}
	var completeChildren []string
	for _, child := range children {
		if child != nil {
			complete := discoveryCommandDiagnosticDepth(child, depth+1)
			completeChildren = append(completeChildren, complete)
			message = strings.Replace(message, child.Error(), complete, 1)
		}
	}
	// Opaque wrappers need not include their child's Error string. A later
	// replacement can also collide with an earlier complete output. Repair
	// every missing whole child only after all replacements, without granting
	// the arbitrary wrapper any completed-analysis permission.
	for _, complete := range completeChildren {
		if !strings.Contains(message, complete) {
			message += "\n" + complete
		}
	}
	return message
}

// Candidate tools can emit arbitrarily large diagnostics. Bound the capture
// while still draining both pipes so the child cannot block on a full pipe.
// A truncated command is an explicit failure, never a successful inspection.
type boundedDiscoveryCommandOutput struct {
	buffer    bytes.Buffer
	truncated bool
}

func (output *boundedDiscoveryCommandOutput) Len() int {
	return output.buffer.Len()
}

func (output *boundedDiscoveryCommandOutput) Bytes() []byte {
	return output.buffer.Bytes()
}

func (output *boundedDiscoveryCommandOutput) String() string {
	return output.buffer.String()
}

func (output *boundedDiscoveryCommandOutput) Write(data []byte) (int, error) {
	length := len(data)
	available := discoveryCommandOutputLimit - output.Len()
	if length > available {
		output.truncated = true
		data = data[:available]
	}
	if _, err := output.buffer.Write(data); err != nil {
		return 0, err
	}
	return length, nil
}

func runCapturedCommandOutput(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error) {
	directory, err := filepath.Abs(dir)
	if err == nil {
		directory, err = filepath.EvalSymlinks(directory)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: resolve command directory: %w", name, err)
	}
	// On Unix, os.Getwd (and therefore Go's diagnostic shortening) may
	// retain PWD only when it identifies this exact physical directory.
	if runtime.GOOS != "windows" {
		physical, statErr := os.Stat(directory)
		for _, item := range env {
			if pwd, found := strings.CutPrefix(item, "PWD="); found && filepath.IsAbs(pwd) && statErr == nil {
				logical, logicalErr := os.Stat(pwd)
				if logicalErr == nil && os.SameFile(physical, logical) {
					directory = filepath.Clean(pwd)
				}
			}
		}
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	var output boundedDiscoveryCommandOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	// Do not wait indefinitely when an escaped descendant retains an output
	// pipe. ErrWaitDelay is infrastructure failure, never source N/A.
	cmd.WaitDelay = 2 * time.Second
	err = runDiscoveryCommand(cmd)
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s: %w", strings.Join(append([]string{name}, args...), " "), ctx.Err())
	}
	message := strings.TrimSpace(output.String())
	if len(message) > 64<<10 {
		message = "... output truncated ...\n" + message[len(message)-(64<<10):]
	}
	if output.truncated {
		return nil, fmt.Errorf("%s: %w %d bytes (command error: %v)\n%s",
			strings.Join(append([]string{name}, args...), " "),
			errDiscoveryCommandOutputExceeded,
			discoveryCommandOutputLimit,
			err,
			message,
		)
	}
	if err == nil {
		return output.Bytes(), nil
	}
	failure := &discoveryCapturedCommandError{
		command:   strings.Join(append([]string{name}, args...), " "),
		cause:     err,
		output:    output.String(),
		display:   message,
		directory: directory,
	}
	return output.Bytes(), failure
}

func replaceEnv(base []string, replacements map[string]string) []string {
	out := make([]string, 0, len(base)+len(replacements))
	for _, item := range base {
		key, _, ok := strings.Cut(item, "=")
		if ok {
			if _, replace := replacements[key]; replace {
				continue
			}
		}
		out = append(out, item)
	}
	keys := make([]string, 0, len(replacements))
	for key := range replacements {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, key+"="+replacements[key])
	}
	return out
}

func validateDiscoveryReport(targets []string, candidate discoveryCandidate, report matrixReport) error {
	if report.TotalTargets != len(targets) || len(report.Targets) != len(targets) {
		return fmt.Errorf("%s: target coverage changed: got total=%d reports=%d, want %d", candidate.exactKey(), report.TotalTargets, len(report.Targets), len(targets))
	}
	seen := make(map[string]bool, len(targets))
	totalAsm := 0
	totalSuccess := 0
	totalNotApplicable := 0
	for _, actual := range report.Targets {
		target := actual.Goos + "/" + actual.Goarch
		if seen[target] {
			return fmt.Errorf("%s: duplicate target report %s", candidate.exactKey(), target)
		}
		seen[target] = true
		if actual.Failed != 0 || actual.Success+actual.NotApplicable != actual.TotalAsm {
			return fmt.Errorf("%s: %s failed: success=%d not_applicable=%d failed=%d total=%d", candidate.exactKey(), target, actual.Success, actual.NotApplicable, actual.Failed, actual.TotalAsm)
		}
		if err := validateTargetNotApplicableEvidence(actual); err != nil {
			return fmt.Errorf("%s: %s: %w", candidate.exactKey(), target, err)
		}
		totalAsm += actual.TotalAsm
		totalSuccess += actual.Success
		totalNotApplicable += actual.NotApplicable
	}
	for _, target := range targets {
		if !seen[target] {
			return fmt.Errorf("%s: target %s was silently skipped", candidate.exactKey(), target)
		}
	}
	if totalAsm == 0 {
		return fmt.Errorf("%s: no assembly entered translation on the target matrix", candidate.exactKey())
	}
	observed := make(map[string]bool)
	for _, target := range report.Targets {
		for _, actualPath := range target.AsmFiles {
			actualPath = filepath.ToSlash(actualPath)
			for _, expectedPath := range candidate.AsmFiles {
				if actualPath == expectedPath || strings.HasSuffix(actualPath, "/"+expectedPath) {
					observed[expectedPath] = true
				}
			}
		}
	}
	var missing []string
	for _, expectedPath := range candidate.AsmFiles {
		if !observed[expectedPath] {
			missing = append(missing, expectedPath)
		}
	}
	if len(missing) != 0 {
		return fmt.Errorf("%s: %d supported assembly files were not exercised: %v", candidate.exactKey(), len(missing), missing)
	}
	if report.TotalAsm != totalAsm || report.Success != totalSuccess || report.NotApplicable != totalNotApplicable || report.Failed != 0 || report.Success+report.NotApplicable != report.TotalAsm {
		return fmt.Errorf("%s: inconsistent matrix totals: success=%d not_applicable=%d failed=%d total=%d", candidate.exactKey(), report.Success, report.NotApplicable, report.Failed, report.TotalAsm)
	}
	return nil
}

func validateTargetNotApplicableEvidence(report targetReport) error {
	if report.NotApplicable != len(report.NotApplicableItems) {
		return fmt.Errorf("not-applicable accounting mismatch: count=%d items=%d", report.NotApplicable, len(report.NotApplicableItems))
	}
	asmFiles := make(map[string]bool, len(report.AsmFiles))
	for _, asmFile := range report.AsmFiles {
		asmFiles[asmFile] = true
	}
	for _, item := range report.NotApplicableItems {
		if item.Kind != targetNotApplicableGoTextArgSize || item.PkgPath == "" || item.AsmFile == "" || !asmFiles[item.AsmFile] || item.Symbol == "" || item.DeclaredArgSize == item.ExpectedArgSize || item.Reason == "" {
			return fmt.Errorf("invalid not-applicable evidence for %q: kind=%q symbol=%q declared=%d expected=%d", item.AsmFile, item.Kind, item.Symbol, item.DeclaredArgSize, item.ExpectedArgSize)
		}
	}
	return nil
}

func writeDiscoveryCorpusReport(reportPath string, report discoveryCorpusReport) error {
	if reportPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode discovery corpus report: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(reportPath), 0755); err != nil {
		return fmt.Errorf("create discovery report directory: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(reportPath), ".discovery-report-*")
	if err != nil {
		return fmt.Errorf("create temporary discovery report: %w", err)
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write discovery corpus report: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close discovery corpus report: %w", err)
	}
	discoveryReportMu.Lock()
	err = publishDiscoveryReport(file.Name(), reportPath)
	discoveryReportMu.Unlock()
	if err != nil {
		return fmt.Errorf("publish discovery corpus report: %w", err)
	}
	return nil
}
