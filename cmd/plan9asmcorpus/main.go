package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

type corpusManifest struct {
	SchemaVersion int               `json:"schema_version"`
	Targets       []string          `json:"targets"`
	Libraries     []libraryManifest `json:"libraries"`
}

type libraryManifest struct {
	ID        string                       `json:"id"`
	Origin    string                       `json:"origin"`
	Issues    []string                     `json:"issues,omitempty"`
	Module    string                       `json:"module"`
	Version   string                       `json:"version"`
	Inventory map[string]expectedInventory `json:"inventory"`
}

type expectedInventory struct {
	AsmFiles int      `json:"asm_files"`
	Packages []string `json:"packages"`
}

type moduleInfo struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
}

type commandInvocation struct {
	Dir  string
	Args []string
}

type matrixReport struct {
	Targets                         []targetReport                     `json:"targets"`
	TotalTargets                    int                                `json:"total_targets"`
	TotalAsm                        int                                `json:"total_asm"`
	Success                         int                                `json:"success"`
	NotApplicable                   int                                `json:"not_applicable"`
	Failed                          int                                `json:"failed"`
	NotApplicableItems              []matrixTargetNotApplicableItem    `json:"not_applicable_items,omitempty"`
	SourceNotApplicableItems        []discoverySourceNotApplicableItem `json:"source_not_applicable_items,omitempty"`
	PrivateExtension                *discoveryPrivateExtensionSkip     `json:"-"`
	NativeLayout                    *discoveryNativeLayoutSkip         `json:"-"`
	NativeLayoutPlan                *discoveryNativeLayoutPlan         `json:"-"`
	OrdinarySelectionPlan           *discoveryOrdinarySelectionPlan    `json:"-"`
	FeatureProfiles                 []discoveryFeatureProfile          `json:"-"`
	FeatureConsumption              []*gotoolprofile.SelectionProof    `json:"-"`
	InstrumentationTranslations     int                                `json:"-"`
	InstrumentationTargetExclusions int                                `json:"-"`
}

const targetNotApplicableGoTextArgSize = "go_text_arg_size_mismatch"

type targetNotApplicableItem struct {
	PkgPath         string `json:"pkg_path"`
	AsmFile         string `json:"asm_file"`
	Kind            string `json:"kind"`
	Symbol          string `json:"symbol"`
	DeclaredArgSize int64  `json:"declared_arg_size"`
	ExpectedArgSize int64  `json:"expected_arg_size"`
	Reason          string `json:"reason"`
}

type matrixTargetNotApplicableItem struct {
	Target    string   `json:"target"`
	ProfileID string   `json:"profile_id,omitempty"`
	BuildTags []string `json:"build_tags,omitempty"`
	targetNotApplicableItem
}

type targetReport struct {
	Goos               string                        `json:"goos"`
	Goarch             string                        `json:"goarch"`
	TotalPkgs          int                           `json:"total_pkgs"`
	AsmPackages        []string                      `json:"asm_packages"`
	AsmFiles           []string                      `json:"asm_files"`
	TotalAsm           int                           `json:"total_asm"`
	Success            int                           `json:"success"`
	NotApplicable      int                           `json:"not_applicable"`
	Failed             int                           `json:"failed"`
	NotApplicableItems []targetNotApplicableItem     `json:"not_applicable_items,omitempty"`
	FeatureSelection   *gotoolprofile.SelectionProof `json:"feature_selection,omitempty"`
}

var (
	issueURLPattern = regexp.MustCompile(`^https://github\.com/xgo-dev/llgo/issues/[1-9][0-9]*$`)
	idPattern       = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

const (
	originLLGoIssue     = "llgo-issue"
	originEcosystemScan = "ecosystem-scan"

	// The deadline is renewed for candidate setup and each target configuration.
	// This bounds stuck tools without penalizing modules that legitimately need
	// several expensive target configurations.
	defaultDiscoveryCandidateTimeout = 60 * time.Minute
)

func main() {
	manifestPath := flag.String("manifest", "testdata/corpus/reported-libraries.json", "third-party library manifest")
	corpusDir := flag.String("corpus-dir", "testdata/corpus", "module used to resolve third-party libraries")
	repoRoot := flag.String("repo-root", ".", "compatibility harness repository root")
	translatorRoot := flag.String("translator-root", "", "pinned plan9asm translator source checkout")
	translator := flag.String("translator", "", "path to the plan9asmll binary")
	llc := flag.String("llc", "", "path to llc")
	suite := flag.String("suite", "all", "suite id to run, or all")
	checkLatest := flag.Bool("check-latest", true, "require each pinned module version to equal @latest")
	list := flag.Bool("list", false, "list suite ids as a JSON array and exit")
	discoveryLedger := flag.String("discovery-ledger", "", "run every matched module@version in a discovery ledger instead of the curated manifest")
	discoveryTargets := flag.String("discovery-targets", "", "comma-separated target subset for replaying matching discovery records")
	discoveryShardIndex := flag.Int("discovery-shard-index", 0, "zero-based discovery candidate shard")
	discoveryShardCount := flag.Int("discovery-shard-count", 1, "number of stable discovery candidate shards")
	var discoveryExactCandidates discoveryExactCandidateFlags
	flag.Var(&discoveryExactCandidates, "discovery-exact-candidate", "execute only this exact module@version in its full shard (repeatable; other candidates remain pending)")
	discoveryTimeout := flag.Duration("candidate-timeout", defaultDiscoveryCandidateTimeout, "timeout for discovery setup and each target configuration")
	discoveryReport := flag.String("discovery-report", "", "write the discovery shard result as JSON")
	discoveryEvents := flag.String("discovery-events", "", "optional new JSONL phase timing file; diagnostic only, never completion evidence")
	discoveryBuildCache := flag.String("discovery-build-cache", "", "existing absolute Go build-cache directory shared by discovery shards; never removed by the runner")
	verifyDiscoveryReports := flag.String("verify-discovery-reports", "", "verify a complete directory of discovery shard reports against -discovery-ledger")
	discoveryProgressOutput := flag.String("discovery-progress-output", "", "publish audited progress to a new assembly-progress.json while verifying reports; failures still exit nonzero")
	discoveryProgressDirectory := flag.String("discovery-progress-directory", "", "read-only canonical output directory preflight; mutually exclusive with execution and other reader modes")
	compareAssemblyLedgerPath := flag.String("compare-assembly-ledger", "", "compare verified shard results with the committed assembly ledger")
	discoveryProgressReports := flag.String("discovery-progress", "", "report pending/passed/N/A/failed candidates from a possibly incomplete directory of frozen shard reports")
	writeAssemblyLedgerPath := flag.String("write-assembly-ledger", "", "persist audited discovery progress in a separate module-hashed assembly ledger")
	assemblyLedgerStatusPath := flag.String("assembly-ledger-status", "", "read and validate persisted assembly results against the current scan and source")
	requireVerifiedAssembly := flag.Bool("require-verified-assembly-ledger", false, "require every assembly candidate to be passed or explicitly skipped by complete reports")
	flag.Parse()
	directoryPreflightSelected := false
	flag.Visit(func(option *flag.Flag) {
		if option.Name == "discovery-progress-directory" {
			directoryPreflightSelected = true
		}
	})
	if directoryPreflightSelected {
		var modeErr error
		flag.Visit(func(option *flag.Flag) {
			switch option.Name {
			case "repo-root", "discovery-ledger", "compare-assembly-ledger", "discovery-progress-directory":
			default:
				modeErr = errors.New("-discovery-progress-directory requires an exclusive directory-preflight mode")
			}
		})
		check(modeErr)
		if *discoveryProgressDirectory == "" || *discoveryLedger == "" || *compareAssemblyLedgerPath == "" {
			check(errors.New("-discovery-progress-directory requires a nonempty directory and both input ledger paths"))
		}
		directory, err := validateDiscoveryProgressDirectory(*repoRoot, *discoveryLedger, *compareAssemblyLedgerPath, *discoveryProgressDirectory)
		check(err)
		fmt.Println(directory)
		return
	}
	check(validateDiscoveryExactCandidateMode(discoveryExactCandidates, *discoveryLedger, *discoveryTargets != "",
		*list || *suite != "all" || *verifyDiscoveryReports != "" || *discoveryProgressReports != "" ||
			*compareAssemblyLedgerPath != "" || *writeAssemblyLedgerPath != "" ||
			*assemblyLedgerStatusPath != "" || *requireVerifiedAssembly || *discoveryProgressOutput != ""))
	if *discoveryProgressOutput != "" && (*verifyDiscoveryReports == "" || *list || *suite != "all") {
		check(errors.New("-discovery-progress-output requires -verify-discovery-reports, not a curated or list mode"))
	}
	if *discoveryEvents != "" && (*discoveryLedger == "" || *list || *suite != "all" || *verifyDiscoveryReports != "" || *discoveryProgressReports != "" ||
		*compareAssemblyLedgerPath != "" || *writeAssemblyLedgerPath != "" || *assemblyLedgerStatusPath != "" || *requireVerifiedAssembly) {
		check(errors.New("-discovery-events requires discovery execution, not a reader or curated mode"))
	}
	if *verifyDiscoveryReports != "" && *discoveryProgressReports != "" {
		check(errors.New("-verify-discovery-reports and -discovery-progress are mutually exclusive"))
	}
	if *compareAssemblyLedgerPath != "" && *verifyDiscoveryReports == "" {
		check(errors.New("-compare-assembly-ledger requires -verify-discovery-reports"))
	}
	if *writeAssemblyLedgerPath != "" && *discoveryProgressReports == "" {
		check(errors.New("-write-assembly-ledger requires -discovery-progress"))
	}
	if *assemblyLedgerStatusPath != "" && (*discoveryProgressReports != "" || *verifyDiscoveryReports != "") {
		check(errors.New("-assembly-ledger-status cannot be combined with report verification or progress"))
	}
	if *requireVerifiedAssembly && *assemblyLedgerStatusPath == "" {
		check(errors.New("-require-verified-assembly-ledger requires -assembly-ledger-status"))
	}

	manifest, err := loadManifest(*manifestPath)
	check(err)
	if *list {
		ids := make([]string, 0, len(manifest.Libraries))
		for _, library := range manifest.Libraries {
			ids = append(ids, library.ID)
		}
		check(json.NewEncoder(os.Stdout).Encode(ids))
		return
	}
	if *verifyDiscoveryReports != "" {
		if *discoveryLedger == "" {
			check(errors.New("-verify-discovery-reports requires -discovery-ledger"))
		}
		if *discoveryProgressOutput != "" {
			if !filepath.IsAbs(*discoveryProgressOutput) || filepath.Base(*discoveryProgressOutput) != "assembly-progress.json" {
				check(errors.New("discovery progress output requires an absolute new assembly-progress.json path"))
			}
			_, err := validateDiscoveryProgressDirectory(*repoRoot, *discoveryLedger, *compareAssemblyLedgerPath, filepath.Dir(*discoveryProgressOutput))
			check(err)
		}
		source, err := collectDiscoverySource(*repoRoot)
		check(err)
		var storedSnapshot discoveryPhysicalSnapshot
		if *compareAssemblyLedgerPath != "" {
			storedSnapshot, err = collectDiscoveryPhysicalSnapshot(*compareAssemblyLedgerPath)
			check(err)
		}
		shardCount := 0 // Preserve inference for the existing verifier command.
		flag.Visit(func(option *flag.Flag) {
			if option.Name == "discovery-shard-count" {
				shardCount = *discoveryShardCount
			}
		})
		current, err := collectDiscoveryProgress(
			*discoveryLedger, *verifyDiscoveryReports, manifest.Targets, source, shardCount, *repoRoot,
		)
		check(err)
		verificationErr := requireCompleteDiscoveryProgress(current, *verifyDiscoveryReports)
		if verificationErr == nil && *compareAssemblyLedgerPath != "" {
			semanticSourceSHA, err := collectDiscoverySemanticSourceSHA(*repoRoot)
			check(err)
			stored, err := readAssemblyLedger(
				*compareAssemblyLedgerPath, current.LedgerSHA256, semanticSourceSHA,
			)
			if err != nil {
				verificationErr = err
			} else {
				verificationErr = compareAssemblyLedgerProgress(stored, current)
			}
		}
		var prepared *preparedDiscoveryProgress
		if *discoveryProgressOutput != "" {
			prepared, err = prepareDiscoveryProgressOutput(*discoveryProgressOutput, current)
			check(err)
		}
		finalErr := verifyDiscoveryAggregateInputs(*repoRoot, *discoveryLedger, *compareAssemblyLedgerPath,
			source, current.LedgerSHA256, storedSnapshot)
		if prepared != nil {
			if finalErr == nil {
				finalErr = prepared.publish()
			}
			finalErr = errors.Join(finalErr, prepared.discard())
		}
		check(finalErr)
		check(verificationErr)
		fmt.Printf("verified discovery corpus reports against %s\n", *discoveryLedger)
		return
	}
	if *assemblyLedgerStatusPath != "" {
		if *discoveryLedger == "" {
			check(errors.New("-assembly-ledger-status requires -discovery-ledger"))
		}
		ledgerSHA, err := discoveryLedgerFingerprint(*discoveryLedger)
		check(err)
		semanticSourceSHA, err := collectDiscoverySemanticSourceSHA(*repoRoot)
		check(err)
		progress, err := readAssemblyLedger(*assemblyLedgerStatusPath, ledgerSHA, semanticSourceSHA)
		check(err)
		if *requireVerifiedAssembly {
			check(requireVerifiedAssemblyLedger(progress))
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		check(encoder.Encode(progress))
		return
	}
	if *discoveryProgressReports != "" {
		if *discoveryLedger == "" || *discoveryShardCount <= 0 {
			check(errors.New("-discovery-progress requires -discovery-ledger and a positive -discovery-shard-count"))
		}
		source, err := collectDiscoverySource(*repoRoot)
		check(err)
		progress, err := collectDiscoveryProgress(*discoveryLedger, *discoveryProgressReports, manifest.Targets, source, *discoveryShardCount, *repoRoot)
		check(err)
		finalSource, err := collectDiscoverySource(*repoRoot)
		check(err)
		if finalSource != source {
			check(errors.New("discovery source changed while reading progress"))
		}
		if *writeAssemblyLedgerPath != "" {
			check(validateAssemblyLedgerDestination(*discoveryLedger, *writeAssemblyLedgerPath))
			semanticSourceSHA, err := collectDiscoverySemanticSourceSHA(*repoRoot)
			check(err)
			check(writeAssemblyLedger(*writeAssemblyLedgerPath, progress, semanticSourceSHA))
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		check(encoder.Encode(progress))
		return
	}
	if *translator == "" {
		check(errors.New("-translator is required"))
	}
	if *llc == "" {
		check(errors.New("-llc is required"))
	}
	if *discoveryLedger != "" {
		targets := manifest.Targets
		filterTargets := false
		if *discoveryTargets != "" {
			targets, err = parseDiscoveryTargets(*discoveryTargets)
			check(err)
			filterTargets = true
		}
		check(runDiscoveryCorpus(discoveryCorpusConfig{
			LedgerPath:       *discoveryLedger,
			RepoRoot:         *repoRoot,
			TranslatorRoot:   *translatorRoot,
			Translator:       *translator,
			LLC:              *llc,
			Targets:          targets,
			FilterTargets:    filterTargets,
			ShardIndex:       *discoveryShardIndex,
			ShardCount:       *discoveryShardCount,
			ExactCandidates:  discoveryExactCandidates,
			CandidateTimeout: *discoveryTimeout,
			ReportPath:       *discoveryReport,
			EventsPath:       *discoveryEvents,
			buildCache:       *discoveryBuildCache,
		}))
		return
	}

	libraries, err := selectLibraries(manifest.Libraries, *suite)
	check(err)
	for _, library := range libraries {
		check(runLibrary(manifest, library, *corpusDir, *translatorRoot, *translator, *llc, *checkLatest))
	}
}

func parseDiscoveryTargets(value string) ([]string, error) {
	var targets []string
	seen := make(map[string]bool)
	for _, target := range strings.Split(value, ",") {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, errors.New("-discovery-targets contains an empty target")
		}
		if err := validateTarget(target); err != nil {
			return nil, err
		}
		if seen[target] {
			return nil, fmt.Errorf("duplicate discovery target %q", target)
		}
		seen[target] = true
		targets = append(targets, target)
	}
	if len(targets) == 0 {
		return nil, errors.New("-discovery-targets must not be empty")
	}
	return targets, nil
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadManifest(path string) (corpusManifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return corpusManifest{}, fmt.Errorf("open manifest: %w", err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var manifest corpusManifest
	if err := dec.Decode(&manifest); err != nil {
		return corpusManifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return corpusManifest{}, err
	}
	if err := validateManifest(manifest); err != nil {
		return corpusManifest{}, err
	}
	return manifest, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra interface{}
	if err := dec.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing manifest data: %w", err)
	}
	return errors.New("manifest contains more than one JSON value")
}

func validateManifest(manifest corpusManifest) error {
	if manifest.SchemaVersion != 1 {
		return fmt.Errorf("unsupported manifest schema_version %d", manifest.SchemaVersion)
	}
	if len(manifest.Targets) == 0 {
		return errors.New("manifest has no targets")
	}
	targets := make(map[string]bool, len(manifest.Targets))
	for _, target := range manifest.Targets {
		if err := validateTarget(target); err != nil {
			return err
		}
		if targets[target] {
			return fmt.Errorf("duplicate target %q", target)
		}
		targets[target] = true
	}
	if len(manifest.Libraries) == 0 {
		return errors.New("manifest has no libraries")
	}
	ids := make(map[string]bool, len(manifest.Libraries))
	modules := make(map[string]bool, len(manifest.Libraries))
	for _, library := range manifest.Libraries {
		if !idPattern.MatchString(library.ID) {
			return fmt.Errorf("invalid library id %q", library.ID)
		}
		if ids[library.ID] {
			return fmt.Errorf("duplicate library id %q", library.ID)
		}
		ids[library.ID] = true
		if library.Module == "" || library.Version == "" {
			return fmt.Errorf("library %q requires module and version", library.ID)
		}
		if modules[library.Module] {
			return fmt.Errorf("duplicate library module %q", library.Module)
		}
		modules[library.Module] = true
		switch library.Origin {
		case originLLGoIssue:
			if len(library.Issues) == 0 {
				return fmt.Errorf("library %q has no source issue", library.ID)
			}
		case originEcosystemScan:
			if len(library.Issues) != 0 {
				return fmt.Errorf("ecosystem-scan library %q must not claim a source issue", library.ID)
			}
		default:
			return fmt.Errorf("library %q has invalid origin %q", library.ID, library.Origin)
		}
		seenIssues := make(map[string]bool, len(library.Issues))
		for _, issue := range library.Issues {
			if !issueURLPattern.MatchString(issue) {
				return fmt.Errorf("library %q has invalid issue URL %q", library.ID, issue)
			}
			if seenIssues[issue] {
				return fmt.Errorf("library %q repeats source issue %q", library.ID, issue)
			}
			seenIssues[issue] = true
		}
		totalAsm := 0
		for target, inventory := range library.Inventory {
			if !targets[target] {
				return fmt.Errorf("library %q inventory has unknown target %q", library.ID, target)
			}
			if inventory.AsmFiles <= 0 {
				return fmt.Errorf("library %q target %q has non-positive asm_files", library.ID, target)
			}
			if len(inventory.Packages) == 0 || inventory.AsmFiles < len(inventory.Packages) {
				return fmt.Errorf("library %q target %q has inconsistent package/file inventory", library.ID, target)
			}
			if !sort.StringsAreSorted(inventory.Packages) {
				return fmt.Errorf("library %q target %q packages are not sorted", library.ID, target)
			}
			for i, pkg := range inventory.Packages {
				if pkg != library.Module && !strings.HasPrefix(pkg, library.Module+"/") {
					return fmt.Errorf("library %q target %q package %q is outside module", library.ID, target, pkg)
				}
				if i > 0 && inventory.Packages[i-1] == pkg {
					return fmt.Errorf("library %q target %q repeats package %q", library.ID, target, pkg)
				}
			}
			totalAsm += inventory.AsmFiles
		}
		if totalAsm == 0 {
			return fmt.Errorf("library %q contains no assembly on the target matrix", library.ID)
		}
	}
	return nil
}

func validateTarget(target string) error {
	parts := strings.Split(target, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid target %q", target)
	}
	switch parts[1] {
	case "386", "amd64", "arm", "arm64", "wasm":
		return nil
	default:
		return fmt.Errorf("target %q uses unsupported Plan 9 architecture", target)
	}
}

func selectLibraries(libraries []libraryManifest, suite string) ([]libraryManifest, error) {
	if suite == "all" {
		return libraries, nil
	}
	for _, library := range libraries {
		if library.ID == suite {
			return []libraryManifest{library}, nil
		}
	}
	return nil, fmt.Errorf("unknown third-party library suite %q", suite)
}

func runLibrary(manifest corpusManifest, library libraryManifest, corpusDir, repoRoot, translator, llc string, checkLatest bool) error {
	fmt.Printf("== third-party library %s (%s@%s; %s) ==\n", library.ID, library.Module, library.Version, library.Origin)
	pinned, err := queryModule(corpusDir, library.Module)
	if err != nil {
		return fmt.Errorf("%s: resolve pinned module: %w", library.ID, err)
	}
	if pinned.Path != library.Module || pinned.Version != library.Version {
		return fmt.Errorf("%s: corpus go.mod resolves %s@%s, manifest requires %s@%s", library.ID, pinned.Path, pinned.Version, library.Module, library.Version)
	}
	if checkLatest {
		latest, err := queryModule(corpusDir, library.Module+"@latest")
		if err != nil {
			return fmt.Errorf("%s: resolve latest module: %w", library.ID, err)
		}
		if latest.Path != library.Module || latest.Version != library.Version {
			return fmt.Errorf("%s: latest version is %s@%s; update the pinned corpus and inventory from %s@%s", library.ID, latest.Path, latest.Version, library.Module, library.Version)
		}
		fmt.Printf("latest version confirmed: %s@%s\n", latest.Path, latest.Version)
	}
	if err := runCommand(corpusDir, "go", "mod", "download", library.Module+"@"+library.Version); err != nil {
		return fmt.Errorf("%s: download module: %w", library.ID, err)
	}
	tmpDir, err := os.MkdirTemp("", "plan9asm-third-party-"+library.ID+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	reportPath := filepath.Join(tmpDir, "report.json")
	invocation := makeTranslatorInvocation(corpusDir, library.Module, filepath.Join(tmpDir, "out"), repoRoot, llc, reportPath)
	if err := runCommand(invocation.Dir, translator, invocation.Args...); err != nil {
		return fmt.Errorf("%s: translate and compile corpus: %w", library.ID, err)
	}
	report, err := loadReport(reportPath)
	if err != nil {
		return fmt.Errorf("%s: %w", library.ID, err)
	}
	if err := validateReport(manifest.Targets, library, report); err != nil {
		return err
	}
	fmt.Printf("%s: all %d assembly translations passed or were evidence-backed N/A across %d targets\n", library.ID, report.TotalAsm, report.TotalTargets)
	return nil
}

func makeTranslatorInvocation(corpusDir, modulePath, outDir, repoRoot, llc, reportPath string) commandInvocation {
	invocation := makeTranslatorInvocationForPatterns(corpusDir, modulePath, []string{modulePath + "/..."}, outDir, repoRoot, llc, reportPath)
	invocation.Args = append(invocation.Args, "-strict-load")
	return invocation
}

func makeTranslatorInvocationForPatterns(corpusDir, modulePath string, patterns []string, outDir, repoRoot, llc, reportPath string) commandInvocation {
	return makeTranslatorInvocationForPatternsAndTags(corpusDir, modulePath, patterns, nil, outDir, repoRoot, llc, reportPath)
}

func makeTranslatorInvocationForPatternsAndTags(corpusDir, modulePath string, patterns, buildTags []string, outDir, repoRoot, llc, reportPath string) commandInvocation {
	return makeTranslatorInvocationForTargetsAndTags(corpusDir, modulePath, patterns, buildTags, nil, nil, outDir, repoRoot, llc, reportPath)
}

func makeTranslatorInvocationForTargetsAndTags(corpusDir, modulePath string, patterns, buildTags, targets, asmFiles []string, outDir, repoRoot, llc, reportPath string) commandInvocation {
	args := []string{
		"-patterns=" + strings.Join(patterns, ","),
		"-module-path=" + modulePath,
	}
	if len(targets) == 0 {
		args = append([]string{"-all-targets"}, args...)
	} else {
		args = append([]string{"-targets=" + strings.Join(targets, ",")}, args...)
	}
	if len(buildTags) != 0 {
		args = append(args, "-tags="+strings.Join(buildTags, ","))
	}
	if len(asmFiles) != 0 {
		args = append(args, "-asm-files="+strings.Join(asmFiles, ","))
	}
	args = append(args,
		"-out="+outDir,
		"-compile",
		"-llc="+llc,
		// Curated and discovery suites both verify real LLVM 22 objects.
		// Optimization adds no instruction coverage and is prohibitively slow
		// for some generated megabyte-scale assembly files.
		"-llc-opt-level=0",
		"-report="+reportPath,
		"-repo-root="+repoRoot,
	)
	return commandInvocation{Dir: corpusDir, Args: args}
}

func makeDiscoveryTranslatorInvocation(corpusDir, modulePath string, patterns, buildTags, targets, asmFiles []string, outDir, repoRoot, llc, reportPath string) commandInvocation {
	return makeTranslatorInvocationForTargetsAndTags(
		corpusDir, modulePath, patterns, buildTags, targets, asmFiles,
		outDir, repoRoot, llc, reportPath,
	)
}

func queryModule(dir, query string) (moduleInfo, error) {
	cmd := exec.Command("go", "list", "-m", "-json", query)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return moduleInfo{}, fmt.Errorf("go list %s: %w: %s", query, err, strings.TrimSpace(stderr.String()))
	}
	var info moduleInfo
	if err := json.Unmarshal(stdout.Bytes(), &info); err != nil {
		return moduleInfo{}, fmt.Errorf("decode go list %s: %w", query, err)
	}
	return info, nil
}

func runCommand(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func loadReport(path string) (matrixReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return matrixReport{}, fmt.Errorf("read report: %w", err)
	}
	var report matrixReport
	if err := json.Unmarshal(data, &report); err != nil {
		return matrixReport{}, fmt.Errorf("decode report: %w", err)
	}
	return report, nil
}

func validateReport(targets []string, library libraryManifest, report matrixReport) error {
	if report.TotalTargets != len(targets) || len(report.Targets) != len(targets) {
		return fmt.Errorf("%s: target coverage changed: got total=%d reports=%d, want %d", library.ID, report.TotalTargets, len(report.Targets), len(targets))
	}
	seen := make(map[string]bool, len(targets))
	totalAsm := 0
	totalSuccess := 0
	totalNotApplicable := 0
	for _, actual := range report.Targets {
		target := actual.Goos + "/" + actual.Goarch
		if seen[target] {
			return fmt.Errorf("%s: duplicate target report %s", library.ID, target)
		}
		seen[target] = true
		expected := library.Inventory[target]
		packages := append([]string(nil), actual.AsmPackages...)
		sort.Strings(packages)
		if actual.TotalAsm != expected.AsmFiles || !equalStrings(packages, expected.Packages) {
			return fmt.Errorf("%s: %s assembly inventory changed: got files=%d packages=%v, want files=%d packages=%v", library.ID, target, actual.TotalAsm, packages, expected.AsmFiles, expected.Packages)
		}
		if actual.TotalPkgs != len(actual.AsmPackages) {
			return fmt.Errorf("%s: %s inconsistent package count: total_pkgs=%d asm_packages=%v", library.ID, target, actual.TotalPkgs, actual.AsmPackages)
		}
		if actual.Failed != 0 || actual.Success+actual.NotApplicable != actual.TotalAsm {
			return fmt.Errorf("%s: %s failed: success=%d not_applicable=%d failed=%d total=%d", library.ID, target, actual.Success, actual.NotApplicable, actual.Failed, actual.TotalAsm)
		}
		if err := validateTargetNotApplicableEvidence(actual); err != nil {
			return fmt.Errorf("%s: %s: %w", library.ID, target, err)
		}
		totalAsm += actual.TotalAsm
		totalSuccess += actual.Success
		totalNotApplicable += actual.NotApplicable
	}
	for _, target := range targets {
		if !seen[target] {
			return fmt.Errorf("%s: target %s was silently skipped", library.ID, target)
		}
	}
	if report.TotalAsm != totalAsm || report.Success != totalSuccess || report.NotApplicable != totalNotApplicable || report.Failed != 0 || report.Success+report.NotApplicable != report.TotalAsm {
		return fmt.Errorf("%s: inconsistent matrix totals: success=%d not_applicable=%d failed=%d total=%d", library.ID, report.Success, report.NotApplicable, report.Failed, report.TotalAsm)
	}
	return nil
}

func equalStrings(a, b []string) bool {
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
