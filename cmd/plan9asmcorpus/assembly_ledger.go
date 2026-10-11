package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/semver"
)

const assemblyLedgerFormat = "module-hashed-assembly-ledger-v3"

type assemblyLedgerShard struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Count  int    `json:"count"`
}

type assemblyLedgerManifest struct {
	Format               string                `json:"format"`
	SemanticSourceSHA256 string                `json:"semantic_source_sha256"`
	Progress             discoveryProgress     `json:"progress"`
	Shards               []assemblyLedgerShard `json:"shards"`
}

func validateAssemblyLedgerProgress(progress discoveryProgress) error {
	if progress.SchemaVersion != discoveryProgressSchema || progress.ValidationKind != "translation_and_llvm22_object_compilation" {
		return fmt.Errorf("invalid assembly ledger progress schema or validation kind")
	}
	if err := validateDiscoveryFeatureInventory(progress.FeatureInventory); err != nil {
		return err
	}
	if !discoverySHA256Pattern.MatchString(progress.LedgerSHA256) {
		return fmt.Errorf("invalid assembly ledger scan fingerprint")
	}
	if !discoveryRevisionPattern.MatchString(progress.Source.Revision) ||
		!discoverySHA256Pattern.MatchString(progress.Source.SHA256) || progress.Source.Dirty {
		return fmt.Errorf("assembly ledger requires a clean, identified source")
	}
	classified := progress.Passed + progress.Failed + progress.NotApplicable +
		progress.SkippedInvalidSource + progress.SkippedSuperseded +
		progress.SkippedPrivateExtension + progress.SkippedNativeLayout
	if progress.CandidateTotal != len(progress.Candidates) ||
		progress.CandidateTotal != classified+progress.Pending {
		return fmt.Errorf("assembly ledger candidate counts do not balance")
	}
	if progress.Complete != (progress.ShardCount > 0 && progress.ReportedShards == progress.ShardCount && progress.Pending == 0) ||
		progress.Verified != (progress.Complete && progress.Failed == 0) {
		return fmt.Errorf("assembly ledger verified flag disagrees with candidate results")
	}
	if progress.ReportedShards > progress.ShardCount ||
		progress.ReportedShards-len(progress.PartialShards)+len(progress.PendingShards) != progress.ShardCount ||
		progress.PassedShards+progress.FailedShards+len(progress.PartialShards) != progress.ReportedShards {
		return fmt.Errorf("assembly ledger shard counts do not balance")
	}
	if classified > 0 && progress.Provenance == nil {
		return fmt.Errorf("assembly ledger outcomes lack report provenance")
	}
	if progress.Provenance != nil {
		if err := validateDiscoveryProvenance(*progress.Provenance, progress.Source, progress.LedgerSHA256); err != nil {
			return fmt.Errorf("assembly ledger outcomes: %w", err)
		}
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	translations := 0
	modeTranslations := 0
	modeTargetExclusions := 0
	notApplicableTranslations := 0
	for _, candidate := range progress.Candidates {
		if candidate.Module == "" || !semver.IsValid(candidate.Version) {
			return fmt.Errorf("assembly ledger candidate has invalid module or version")
		}
		key := candidate.Module + "@" + candidate.Version
		if seen[key] {
			return fmt.Errorf("duplicate assembly ledger candidate %s", key)
		}
		seen[key] = true
		switch candidate.Status {
		case "pending", discoveryStatusPassed, discoveryStatusFailed,
			discoveryStatusNotApplicable, discoveryStatusSkippedInvalidSource,
			discoveryStatusSkippedSuperseded, discoveryStatusSkippedPrivateExtension,
			discoveryStatusSkippedNativeLayout:
			counts[candidate.Status]++
		default:
			return fmt.Errorf("assembly ledger candidate %s has invalid status %q", key, candidate.Status)
		}
		if candidate.Translations < 0 || candidate.NotApplicableTranslations < 0 || candidate.InstrumentationTranslations < 0 || candidate.InstrumentationTargetExclusions < 0 {
			return fmt.Errorf("assembly ledger candidate %s has negative translation counts", key)
		}
		if candidate.NotApplicableTranslations != len(candidate.NotApplicableItems) {
			return fmt.Errorf("assembly ledger target skips for %s lack per-file evidence", key)
		}
		for _, item := range candidate.NotApplicableItems {
			if err := validateDiscoveryRecord(discoveryRecord{
				Module: candidate.Module, Version: candidate.Version, AsmFiles: []string{item.AsmFile},
			}); err != nil {
				return fmt.Errorf("assembly ledger target skip: %w", err)
			}
			if item.Kind != targetNotApplicableGoTextArgSize || item.Target == "" ||
				item.PkgPath == "" || item.Symbol == "" || item.DeclaredArgSize == item.ExpectedArgSize ||
				item.Reason != discoveryTargetSkipReason(item) {
				return fmt.Errorf("assembly ledger target skip for %s has invalid evidence", key)
			}
		}
		translations += candidate.Translations
		modeTranslations += candidate.InstrumentationTranslations
		modeTargetExclusions += candidate.InstrumentationTargetExclusions
		notApplicableTranslations += candidate.NotApplicableTranslations
		if candidate.Status == discoveryStatusPassed && candidate.Translations == 0 {
			return fmt.Errorf("assembly ledger pass %s lacks compiled translations", key)
		}
		if candidate.Status == discoveryStatusNotApplicable {
			if candidate.Translations != 0 || strings.TrimSpace(candidate.NotApplicableReason) == "" {
				return fmt.Errorf("assembly ledger source skip %s lacks reason or claims translations", key)
			}
		} else if candidate.NotApplicableReason != "" {
			return fmt.Errorf("assembly ledger non-source-skip %s carries source skip reason", key)
		}
		for _, item := range candidate.SourceNotApplicableItems {
			if (item.AsmFile == "" && len(item.AsmFiles) == 0) ||
				len(item.Targets) == 0 || item.Reason == "" ||
				item.Reason != discoverySourceSkipReason(item.Kind) {
				return fmt.Errorf("assembly ledger source skip %s has invalid scope or reason", key)
			}
		}
		if err := validateDiscoverySelectionFailureSummaries(candidate.OrdinarySelectionPlan); err != nil {
			return fmt.Errorf("assembly ledger %s: %w", key, err)
		}
		if candidate.Status == discoveryStatusNotApplicable || candidate.Status == discoveryStatusPassed {
			result := discoveryCorpusResult{
				sourceDiagnosticsCompacted: true,
				Module:                     candidate.Module, Version: candidate.Version, Status: candidate.Status,
				DiscoveredAsmFiles: candidate.DiscoveredAsmFiles, ApplicableAsmFiles: candidate.ApplicableAsmFiles,
				BuildConfigurations: candidate.BuildConfigurations, Translations: candidate.Translations,
				NotApplicableTranslations: candidate.NotApplicableTranslations, NotApplicableItems: candidate.NotApplicableItems,
				OrdinarySelectionPlan: candidate.OrdinarySelectionPlan,
				FeatureProfiles:       candidate.FeatureProfiles, FeatureConsumption: candidate.FeatureConsumption,
				InstrumentationTranslations:     candidate.InstrumentationTranslations,
				InstrumentationTargetExclusions: candidate.InstrumentationTargetExclusions,
				featureInventory:                progress.FeatureInventory,
			}
			for _, item := range candidate.SourceNotApplicableItems {
				result.SourceNotApplicableItems = append(result.SourceNotApplicableItems, discoverySourceNotApplicableItem{
					AsmFile: item.AsmFile, AsmFiles: item.AsmFiles, Targets: item.Targets,
					ProfileID: item.ProfileID, BuildTags: item.BuildTags, Kind: item.Kind, Reason: item.Reason, Diagnostic: item.Diagnostic,
				})
			}
			goVersion := ""
			if progress.Provenance != nil {
				goVersion = progress.Provenance.GoVersion
			}
			if err := validateOrdinaryProfileResult(result, progress.Targets, goVersion); err != nil {
				return fmt.Errorf("assembly ledger ordinary selection %s: %w", key, err)
			}
		}
		modeResult := discoveryCorpusResult{
			Module: candidate.Module, Version: candidate.Version, Status: candidate.Status,
			DiscoveredAsmFiles: candidate.DiscoveredAsmFiles, ApplicableAsmFiles: candidate.ApplicableAsmFiles,
			OrdinarySelectionPlan: candidate.OrdinarySelectionPlan, FeatureProfiles: candidate.FeatureProfiles,
			InstrumentationTranslations:     candidate.InstrumentationTranslations,
			InstrumentationTargetExclusions: candidate.InstrumentationTargetExclusions,
		}
		if err := validateDiscoveryInstrumentationFailure(modeResult, progress.FeatureInventory); err != nil {
			return fmt.Errorf("assembly ledger %s: %w", key, err)
		}
		if plan := candidate.OrdinarySelectionPlan; plan != nil && plan.InstrumentationPlan != nil && !equalDiscoveryStrings(plan.Targets, uniqueSortedDiscoveryStrings(progress.Targets)) {
			return fmt.Errorf("assembly ledger mode denominator target matrix differs from progress")
		}
		if progress.Provenance != nil {
			if err := validateDiscoveryInstrumentationToolProvenance(modeResult, *progress.Provenance); err != nil {
				return fmt.Errorf("assembly ledger %s: %w", key, err)
			}
		} else if candidate.InstrumentationTranslations != 0 || candidate.InstrumentationTargetExclusions != 0 {
			return fmt.Errorf("assembly ledger mode objects lack actual tool provenance")
		}
		if candidate.OrdinarySelectionPlan != nil && candidate.Status != discoveryStatusPassed &&
			candidate.Status != discoveryStatusNotApplicable && candidate.Status != discoveryStatusFailed {
			return fmt.Errorf("assembly ledger non-ordinary outcome carries ordinary selection proof")
		}
		if candidate.Status == discoveryStatusSkippedInvalidSource {
			if strings.TrimSpace(candidate.InvalidSourceReason) == "" || len(candidate.InvalidSourceEvidence) == 0 {
				return fmt.Errorf("assembly ledger skip %s lacks reason or evidence", key)
			}
		} else if candidate.InvalidSourceReason != "" || len(candidate.InvalidSourceEvidence) != 0 {
			return fmt.Errorf("assembly ledger non-skip %s carries skip evidence", key)
		}
		if candidate.Status == discoveryStatusSkippedSuperseded {
			if candidate.Superseded == nil || candidate.Superseded.Module != candidate.Module ||
				candidate.Superseded.Version != candidate.Version ||
				strings.TrimSpace(candidate.Superseded.Reason) == "" ||
				len(candidate.Superseded.EvidenceURLs) == 0 {
				return fmt.Errorf("assembly ledger supersession %s lacks matching evidence", key)
			}
		} else if candidate.Superseded != nil {
			return fmt.Errorf("assembly ledger non-superseded %s carries supersession", key)
		}
		if candidate.Status == discoveryStatusSkippedPrivateExtension {
			if candidate.PrivateExtension == nil || candidate.PrivateExtension.Module != candidate.Module ||
				candidate.PrivateExtension.Version != candidate.Version ||
				strings.TrimSpace(candidate.PrivateExtension.Reason) == "" ||
				len(candidate.PrivateExtension.EvidenceURLs) == 0 {
				return fmt.Errorf("assembly ledger private extension %s lacks matching evidence", key)
			}
		} else if candidate.PrivateExtension != nil {
			return fmt.Errorf("assembly ledger non-private result %s carries private-extension evidence", key)
		}
		if candidate.Status == discoveryStatusSkippedNativeLayout {
			if candidate.NativeLayout == nil || candidate.NativeLayout.Module != candidate.Module ||
				candidate.NativeLayout.Version != candidate.Version ||
				strings.TrimSpace(candidate.NativeLayout.Reason) == "" ||
				len(candidate.NativeLayout.EvidenceURLs) == 0 {
				return fmt.Errorf("assembly ledger native layout %s lacks matching evidence", key)
			}
			result := discoveryCorpusResult{
				Module: candidate.Module, Version: candidate.Version, Status: candidate.Status,
				DiscoveredAsmFiles:         candidate.DiscoveredAsmFiles,
				sourceDiagnosticsCompacted: true,
				ApplicableAsmFiles:         candidate.ApplicableAsmFiles,
				BuildConfigurations:        candidate.BuildConfigurations,
				Translations:               candidate.Translations, NotApplicableTranslations: candidate.NotApplicableTranslations,
				NotApplicableItems: candidate.NotApplicableItems,
				NativeLayout:       candidate.NativeLayout, NativeLayoutPlan: candidate.NativeLayoutPlan,
			}
			for _, item := range candidate.SourceNotApplicableItems {
				result.SourceNotApplicableItems = append(result.SourceNotApplicableItems, discoverySourceNotApplicableItem{
					AsmFile: item.AsmFile, AsmFiles: item.AsmFiles, Targets: item.Targets,
					ProfileID: item.ProfileID, BuildTags: item.BuildTags, Kind: item.Kind, Reason: item.Reason, Diagnostic: item.Diagnostic,
				})
			}
			if err := validateNativeLayoutResult(result); err != nil {
				return fmt.Errorf("assembly ledger native layout %s: %w", key, err)
			}
			if !equalDiscoveryStrings(uniqueSortedDiscoveryStrings(progress.Targets), candidate.NativeLayoutPlan.Targets) {
				return fmt.Errorf("assembly ledger native-layout plan differs from target matrix")
			}
			if progress.Provenance != nil && candidate.NativeLayoutPlan.GoVersion != progress.Provenance.GoVersion {
				return fmt.Errorf("assembly ledger native-layout Go selection version differs from provenance")
			}
		} else if candidate.NativeLayout != nil || candidate.NativeLayoutPlan != nil ||
			candidate.OrdinarySelectionPlan == nil &&
				(len(candidate.DiscoveredAsmFiles) != 0 || len(candidate.ApplicableAsmFiles) != 0 || len(candidate.BuildConfigurations) != 0) {
			return fmt.Errorf("assembly ledger non-native result %s carries native-layout evidence", key)
		}
	}
	if counts["pending"] != progress.Pending || counts[discoveryStatusPassed] != progress.Passed ||
		counts[discoveryStatusFailed] != progress.Failed ||
		counts[discoveryStatusNotApplicable] != progress.NotApplicable ||
		counts[discoveryStatusSkippedInvalidSource] != progress.SkippedInvalidSource ||
		counts[discoveryStatusSkippedSuperseded] != progress.SkippedSuperseded ||
		counts[discoveryStatusSkippedPrivateExtension] != progress.SkippedPrivateExtension ||
		counts[discoveryStatusSkippedNativeLayout] != progress.SkippedNativeLayout {
		return fmt.Errorf("assembly ledger candidate statuses do not match summary")
	}
	if translations != progress.Translations {
		return fmt.Errorf("assembly ledger candidate translations do not match summary")
	}
	if modeTranslations != progress.ModeTranslations {
		return fmt.Errorf("assembly ledger mode object scopes do not match summary")
	}
	if modeTargetExclusions != progress.ModeTargetExclusions {
		return fmt.Errorf("assembly ledger mode target exclusions do not match summary")
	}
	if notApplicableTranslations != progress.NotApplicableTranslations {
		return fmt.Errorf("assembly ledger candidate inapplicable translations do not match summary")
	}
	return nil
}

func requireVerifiedAssemblyLedger(progress discoveryProgress) error {
	// Completion is an evidence gate, not a check of caller-supplied flags.
	// Validate every pass and scoped skip even when the snapshot was already
	// read or its summary claims that all shards are complete.
	if err := validateAssemblyLedgerProgress(progress); err != nil {
		return fmt.Errorf("assembly ledger completion evidence: %w", err)
	}
	if progress.Verified && progress.Complete && progress.Pending == 0 &&
		progress.Failed == 0 && progress.ShardCount > 0 &&
		progress.ReportedShards == progress.ShardCount {
		return nil
	}
	return fmt.Errorf(
		"assembly ledger is not verified: reported_shards=%d/%d pending=%d failed=%d",
		progress.ReportedShards,
		progress.ShardCount,
		progress.Pending,
		progress.Failed,
	)
}

// Reports and the committed snapshot may have different Git revisions when an
// evidence-only commit follows a frozen corpus run. Their semantic source,
// scan inventory, totals and exact candidate outcomes must still agree.
func compareAssemblyLedgerProgress(stored, current discoveryProgress) error {
	if err := requireVerifiedAssemblyLedger(stored); err != nil {
		return fmt.Errorf("committed %w", err)
	}
	if err := requireVerifiedAssemblyLedger(current); err != nil {
		return fmt.Errorf("current reports: %w", err)
	}
	var err error
	stored, err = semanticAssemblyLedgerProgress(stored)
	if err != nil {
		return fmt.Errorf("committed semantic comparison: %w", err)
	}
	current, err = semanticAssemblyLedgerProgress(current)
	if err != nil {
		return fmt.Errorf("current semantic comparison: %w", err)
	}

	storedSummary := stored
	currentSummary := current
	storedSummary.Source.Revision = ""
	currentSummary.Source.Revision = ""
	storedSummary.Candidates = nil
	currentSummary.Candidates = nil
	storedData, err := json.Marshal(storedSummary)
	if err != nil {
		return err
	}
	currentData, err := json.Marshal(currentSummary)
	if err != nil {
		return err
	}
	if !bytes.Equal(storedData, currentData) {
		return fmt.Errorf("committed assembly ledger summary differs from current reports")
	}

	if len(stored.Candidates) != len(current.Candidates) {
		return fmt.Errorf("committed assembly candidate count differs from current reports")
	}
	byKey := make(map[string][]byte, len(stored.Candidates))
	for _, candidate := range stored.Candidates {
		data, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		byKey[candidate.Module+"@"+candidate.Version] = data
	}
	for _, candidate := range current.Candidates {
		key := candidate.Module + "@" + candidate.Version
		data, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		if !bytes.Equal(byKey[key], data) {
			return fmt.Errorf("committed assembly outcome %s differs from current reports", key)
		}
	}
	return nil
}

func compareAssemblyLedgerCandidate(a, b discoveryCandidateProgress) int {
	if compared := strings.Compare(a.Module, b.Module); compared != 0 {
		return compared
	}
	return semver.Compare(a.Version, b.Version)
}

func validateAssemblyLedgerDestination(scanPath, outputDir string) error {
	scan, err := filepath.Abs(scanPath)
	if err != nil {
		return err
	}
	output, err := filepath.Abs(outputDir)
	if err != nil {
		return err
	}
	for _, pair := range [][2]string{{scan, output}, {output, scan}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err != nil {
			return err
		}
		if relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("assembly ledger destination overlaps scan ledger")
		}
	}
	return nil
}

// The scan ledger is an immutable test input. This separate, replaceable
// evidence snapshot is written only after the shard reports have been audited.
func writeAssemblyLedger(outputDir string, progress discoveryProgress, semanticSourceSHA string) error {
	if filepath.Base(filepath.Clean(outputDir)) != "assembly-ledger" {
		return fmt.Errorf("assembly ledger destination must be an explicit assembly-ledger directory")
	}
	if !discoverySHA256Pattern.MatchString(semanticSourceSHA) {
		return fmt.Errorf("invalid semantic source fingerprint")
	}
	if err := validateAssemblyLedgerProgress(progress); err != nil {
		return err
	}
	if info, err := os.Lstat(outputDir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("assembly ledger destination is not a directory")
		}
		data, err := os.ReadFile(filepath.Join(outputDir, "manifest.json"))
		if err != nil {
			return fmt.Errorf("refuse to replace unrecognized assembly ledger: %w", err)
		}
		var existing assemblyLedgerManifest
		if err := json.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("refuse to replace invalid assembly ledger: %w", err)
		}
		if _, err := readAssemblyLedgerSnapshot(outputDir, existing.Progress.LedgerSHA256, existing.SemanticSourceSHA256, true); err != nil {
			return fmt.Errorf("refuse to replace invalid assembly ledger: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(outputDir)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(parent, ".assembly-ledger-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	recordsDir := filepath.Join(temporary, "records")
	if err := os.Mkdir(recordsDir, 0755); err != nil {
		return err
	}
	shards := map[byte][]discoveryCandidateProgress{}
	for _, candidate := range progress.Candidates {
		hash := sha256.Sum256([]byte(candidate.Module))
		shards[hash[0]] = append(shards[hash[0]], candidate)
	}
	manifest := assemblyLedgerManifest{
		Format:               assemblyLedgerFormat,
		SemanticSourceSHA256: semanticSourceSHA,
		Progress:             progress,
		Shards:               []assemblyLedgerShard{},
	}
	manifest.Progress.Candidates = nil
	for number := 0; number < 256; number++ {
		records := shards[byte(number)]
		if len(records) == 0 {
			continue
		}
		sort.Slice(records, func(i, j int) bool {
			return compareAssemblyLedgerCandidate(records[i], records[j]) < 0
		})
		var contents bytes.Buffer
		encoder := json.NewEncoder(&contents)
		for _, record := range records {
			if err := encoder.Encode(record); err != nil {
				return err
			}
		}
		name := fmt.Sprintf("%02x.jsonl", number)
		if err := os.WriteFile(filepath.Join(recordsDir, name), contents.Bytes(), 0644); err != nil {
			return err
		}
		checksum := sha256.Sum256(contents.Bytes())
		manifest.Shards = append(manifest.Shards, assemblyLedgerShard{
			Name: name, SHA256: fmt.Sprintf("%x", checksum), Count: len(records),
		})
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(temporary, "manifest.json"), append(data, '\n'), 0644); err != nil {
		return err
	}
	backup := temporary + ".previous"
	if _, err := os.Stat(outputDir); err == nil {
		if err := os.Rename(outputDir, backup); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(temporary, outputDir); err != nil {
		if _, restoreErr := os.Stat(backup); restoreErr == nil {
			_ = os.Rename(backup, outputDir)
		}
		return err
	}
	return os.RemoveAll(backup)
}

func readAssemblyLedger(outputDir, scanSHA, semanticSourceSHA string) (discoveryProgress, error) {
	return readAssemblyLedgerSnapshot(outputDir, scanSHA, semanticSourceSHA, false)
}

// Replacement alone may recognize the intact legacy pending queue. Its records
// are never upgraded or copied: writeAssemblyLedger publishes only newly
// audited progress. Ordinary status/comparison readers require the current protocol.
func readAssemblyLedgerSnapshot(outputDir, scanSHA, semanticSourceSHA string, allowLegacyPending bool) (discoveryProgress, error) {
	rootEntries, err := os.ReadDir(outputDir)
	if err != nil {
		return discoveryProgress{}, err
	}
	if len(rootEntries) != 2 || rootEntries[0].Name() != "manifest.json" ||
		rootEntries[1].Name() != "records" || !rootEntries[1].IsDir() {
		return discoveryProgress{}, fmt.Errorf("assembly ledger has unexpected root entries")
	}
	data, err := os.ReadFile(filepath.Join(outputDir, "manifest.json"))
	if err != nil {
		return discoveryProgress{}, err
	}
	var manifest assemblyLedgerManifest
	if err := decodeAssemblyLedgerJSON(data, &manifest); err != nil {
		return discoveryProgress{}, err
	}
	legacy := allowLegacyPending && manifest.Format == "module-hashed-assembly-ledger-v1" && manifest.Progress.SchemaVersion == 1
	if manifest.Format != assemblyLedgerFormat && !legacy ||
		manifest.Progress.LedgerSHA256 != scanSHA ||
		manifest.SemanticSourceSHA256 != semanticSourceSHA {
		return discoveryProgress{}, fmt.Errorf("assembly ledger format or source/scan provenance is stale")
	}
	if legacy && (manifest.Progress.ReportedShards != 0 || manifest.Progress.Provenance != nil ||
		manifest.Progress.FeatureInventory != nil || len(manifest.Progress.Candidates) != 0) {
		return discoveryProgress{}, fmt.Errorf("legacy replacement requires an unreported pending queue without evidence")
	}
	entries, err := os.ReadDir(filepath.Join(outputDir, "records"))
	if err != nil {
		return discoveryProgress{}, err
	}
	if len(entries) != len(manifest.Shards) {
		return discoveryProgress{}, fmt.Errorf("assembly ledger shard inventory does not match manifest")
	}
	progress := manifest.Progress
	progress.Candidates = []discoveryCandidateProgress{}
	for index, shard := range manifest.Shards {
		if len(shard.Name) != len("00.jsonl") || !strings.HasSuffix(shard.Name, ".jsonl") ||
			index >= len(entries) || entries[index].Name() != shard.Name || entries[index].IsDir() {
			return discoveryProgress{}, fmt.Errorf("invalid assembly ledger shard %q", shard.Name)
		}
		var number byte
		if _, err := fmt.Sscanf(shard.Name[:2], "%02x", &number); err != nil {
			return discoveryProgress{}, fmt.Errorf("invalid assembly ledger shard name %q", shard.Name)
		}
		contents, err := os.ReadFile(filepath.Join(outputDir, "records", shard.Name))
		if err != nil {
			return discoveryProgress{}, err
		}
		checksum := sha256.Sum256(contents)
		if fmt.Sprintf("%x", checksum) != shard.SHA256 {
			return discoveryProgress{}, fmt.Errorf("assembly ledger shard %s checksum mismatch", shard.Name)
		}
		count := 0
		var previous discoveryCandidateProgress
		// The whole shard is already loaded and checksum-verified. Slice its
		// lines without copying or imposing Scanner's unrelated 64 KiB limit:
		// a single candidate can retain many file/target/profile proofs.
		remaining := contents
		for len(remaining) > 0 {
			line, rest, _ := bytes.Cut(remaining, []byte{'\n'})
			remaining = rest
			var candidate discoveryCandidateProgress
			if err := decodeAssemblyLedgerJSON(line, &candidate); err != nil {
				return discoveryProgress{}, err
			}
			if legacy {
				wanted, _ := json.Marshal(discoveryCandidateProgress{Module: candidate.Module, Version: candidate.Version, Status: "pending"})
				actual, _ := json.Marshal(candidate)
				if !bytes.Equal(actual, wanted) {
					return discoveryProgress{}, fmt.Errorf("legacy replacement cannot consume an outcome or source/profile evidence")
				}
			}
			hash := sha256.Sum256([]byte(candidate.Module))
			if hash[0] != number || count > 0 && compareAssemblyLedgerCandidate(previous, candidate) >= 0 {
				return discoveryProgress{}, fmt.Errorf("assembly ledger shard %s has wrong ownership or ordering", shard.Name)
			}
			progress.Candidates = append(progress.Candidates, candidate)
			previous = candidate
			count++
		}
		if count != shard.Count {
			return discoveryProgress{}, fmt.Errorf("assembly ledger shard %s count mismatch", shard.Name)
		}
	}
	validation := progress
	if legacy {
		validation.SchemaVersion = discoveryProgressSchema
		validation.FeatureInventory = newDiscoveryFeatureInventory()
	}
	if err := validateAssemblyLedgerProgress(validation); err != nil {
		return discoveryProgress{}, err
	}
	return progress, nil
}

func decodeAssemblyLedgerJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("assembly ledger JSON has trailing input")
	}
	return nil
}
