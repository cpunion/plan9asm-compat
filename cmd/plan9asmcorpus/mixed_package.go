package main

import (
	"context"
	"errors"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

const discoveryMixedPackageProtocol = "original_mixed_package_loader_rejection_v1"
const discoverySourceNotApplicableMixedPackage = "go_mixed_package_clauses_rejected_package_target"
const discoveryMixedPackageRulesProtocol = "registered_go1271_mixed_package_loader_sources_v1"

// The original directory and every Go selection header already belong to the
// exact ZIP plan. Readers replay the first package-clause conflict, including
// external tests, instead of inferring a source exclusion from an error string.
// Stderr/LoaderError use a module-relative directory only after capture checks
// the complete original diagnostic against the actual downloaded directory.
type discoveryMixedPackageRejection struct {
	Protocol                 string                        `json:"protocol"`
	Directory                string                        `json:"directory"`
	DirectorySHA256          string                        `json:"directory_sha256"`
	ProfileID                string                        `json:"profile_id"`
	Target                   string                        `json:"target"`
	BuildTags                []string                      `json:"build_tags,omitempty"`
	AsmFiles                 []string                      `json:"asm_files"`
	CGOEnabled               string                        `json:"cgo_enabled"`
	PackageName              string                        `json:"package_name"`
	Package                  gotoolprofile.PackageProof    `json:"package"`
	ConflictPackages         [2]string                     `json:"conflict_packages"`
	ConflictFiles            [2]string                     `json:"conflict_files"`
	TestGoFiles              []string                      `json:"test_go_files,omitempty"`
	XTestGoFiles             []string                      `json:"external_test_go_files,omitempty"`
	IgnoredGoFiles           []string                      `json:"ignored_go_files,omitempty"`
	InvalidGoFiles           []string                      `json:"invalid_go_files"`
	LoaderError              discoveryRejectedPackageError `json:"loader_error"`
	Invocation               []string                      `json:"invocation"`
	ExitCode                 int                           `json:"exit_code"`
	Stdout                   string                        `json:"stdout"`
	Stderr                   string                        `json:"portable_stderr"`
	OriginalDiagnosticSHA256 string                        `json:"original_diagnostic_sha256"`
	DriverSHA256             string                        `json:"driver_sha256"`
	Rules                    discoveryGoLoaderRules        `json:"go_loader_rules"`
}

func mixedPackageError(directory string, packages, files [2]string) string {
	failure := build.MultiplePackageError{Dir: directory, Packages: packages[:], Files: files[:]}
	return failure.Error()
}

func validateMixedPackageCommand(directory string, packages, files [2]string, code int, stdout, stderr string) error {
	if packages[0] == "" || packages[1] == "" || packages[0] == packages[1] ||
		files[0] == "" || files[1] == "" || files[0] == files[1] ||
		code != 1 || stdout != "" || stderr != mixedPackageError(directory, packages, files)+"\n" ||
		isDiscoveryGoBuildInfrastructureFailure(stderr) {
		return fmt.Errorf("mixed-package rejection lacks the complete unique original diagnostic/exit")
	}
	return nil
}

func isPotentialMixedPackageFailure(failure error) bool {
	var captured *discoveryCapturedCommandError
	return errors.As(failure, &captured) && strings.HasPrefix(captured.output, "found packages ")
}

type discoveryMixedPackageSelection struct {
	Packages       [2]string
	Files          [2]string
	GoFiles        []string
	SFiles         []string
	TestGoFiles    []string
	XTestGoFiles   []string
	IgnoredGoFiles []string
	InvalidGoFiles []string
	SourceSHA256   map[string]string
}

// MatchFile supplies the registered filename/constraint grammar. Directory
// entries, not an untrusted source-list order, determine the first conflict.
// Both Go loaders ignore documentation and normalize external test names.
func replayMixedPackageSelection(plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile,
	directory string, tags []string) (discoveryMixedPackageSelection, error) {
	selection := discoveryMixedPackageSelection{SourceSHA256: make(map[string]string)}
	inputs, _, err := ordinarySelectionBytes(plan)
	if err != nil {
		return selection, err
	}
	ctx, err := discoveryContextForFeatureProfile(profile.Observed)
	if err != nil {
		return selection, err
	}
	ctx.BuildTags = tags
	ctx.OpenFile = func(filename string) (io.ReadCloser, error) {
		data, present := inputs[filepath.ToSlash(filename)]
		if !present {
			return nil, fmt.Errorf("mixed-package selection lacks original header %s", filename)
		}
		return io.NopCloser(strings.NewReader(string(data))), nil
	}
	sources := make(map[string]ordinarySelectionSource)
	for _, source := range plan.Sources {
		sources[source.File] = source
	}
	var entries []ordinarySelectionEntry
	for _, dir := range plan.Directories {
		if dir.Directory == directory {
			entries = dir.Entries
		}
	}
	firstPackage, firstFile := "", ""
	for _, entry := range entries {
		name, file := entry.Name, path.Join(directory, entry.Name)
		if entry.Kind != "file" || !strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".s") {
			continue
		}
		source, present := sources[file]
		if !present {
			return selection, fmt.Errorf("mixed-package proof omitted complete original source %s", file)
		}
		if strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".") {
			continue
		}
		// modindex processes import/package parse errors before target
		// filtering. Do not use the more permissive fallback ordering to
		// hide a malformed target-ignored Go source.
		var packageName string
		usesCgo := false
		if strings.HasSuffix(name, ".go") {
			parsed, err := parser.ParseFile(token.NewFileSet(), file, source.Header, parser.ImportsOnly)
			if err != nil || source.PackageDiagnostic != "" {
				return selection, fmt.Errorf("mixed-package source also has an import/package parse failure: %s", file)
			}
			packageName = parsed.Name.Name
			for _, imp := range parsed.Imports {
				importPath, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					return selection, fmt.Errorf("mixed-package source also has an invalid import: %s", file)
				}
				usesCgo = usesCgo || importPath == "C"
			}
		}
		selected, err := ctx.MatchFile(filepath.FromSlash(directory), name)
		if err != nil {
			return selection, err
		}
		if !selected {
			if strings.HasSuffix(name, ".go") {
				selection.IgnoredGoFiles = append(selection.IgnoredGoFiles, file)
			}
			continue
		}
		if strings.HasSuffix(name, ".s") {
			selection.SFiles = append(selection.SFiles, file)
			selection.SourceSHA256[file] = source.SHA256
			continue
		}
		pkg := packageName
		if pkg == "documentation" {
			selection.IgnoredGoFiles = append(selection.IgnoredGoFiles, file)
			continue
		}
		isTest := strings.HasSuffix(name, "_test.go")
		isXTest := isTest && strings.HasSuffix(pkg, "_test") && firstPackage != pkg
		if isXTest {
			pkg = strings.TrimSuffix(pkg, "_test")
		}
		if firstPackage == "" {
			firstPackage, firstFile = pkg, name
		} else if pkg != firstPackage {
			selection.InvalidGoFiles = append(selection.InvalidGoFiles, file)
			if selection.Packages[0] == "" {
				selection.Packages, selection.Files = [2]string{firstPackage, pkg}, [2]string{firstFile, name}
			}
		}
		if usesCgo {
			return selection, fmt.Errorf("mixed-package proof lacks an independently modeled cgo role: %s", file)
		}
		switch {
		case isXTest:
			selection.XTestGoFiles = append(selection.XTestGoFiles, file)
		case isTest:
			selection.TestGoFiles = append(selection.TestGoFiles, file)
		default:
			selection.GoFiles = append(selection.GoFiles, file)
			selection.SourceSHA256[file] = source.SHA256
		}
	}
	if selection.Packages[0] == "" {
		return selection, fmt.Errorf("original selected Go headers contain no mixed-package conflict")
	}
	return selection, nil
}

// Exact module-cache packages use cmd/go's modindex route. Other directories
// use go/build. Pin both complete name/constraint/import readers, the sorted
// directory/index construction and the actual non-e list error formatting.
var discoveryMixedPackageRuleSources = map[string]string{
	"src/go/build/build.go":                      "a8b066521d73f2b1c1f01d65588483e416deeab9b2139991645da0dc89dd7d49",
	"src/go/build/read.go":                       "6e319d4ccc52e5a968a85cd5066948234a061c3ae958c77c07d0f943121b5c29",
	"src/go/build/constraint/expr.go":            "96f51c3c0e5e9c6844d7ffb7ba36eee0076239710c3520e527f06f35d8734058",
	"src/cmd/go/internal/load/pkg.go":            "d6e1adb610ec55f2e8bc0afd361eedd6e38689684bca122b02873da1d0ed1584",
	"src/cmd/go/internal/modindex/read.go":       "c79698b8bb8075f7dd4c8ac8a7f30a7b93cdb3cac8a8c4641ec0b0d96b39fcad",
	"src/cmd/go/internal/modindex/build.go":      "f75d94b743539b7b275870327e23b7af63c9c8af74dd9ce8692048d2936efde4",
	"src/cmd/go/internal/modindex/scan.go":       "751915000cd027a051928ee9b5bce6857e54259b0270fdde2e33d1e498a15916",
	"src/cmd/go/internal/modindex/build_read.go": "30057658fad607095965df8bce7456922935c03cc014200077c17c3d3bc0866f",
	"src/cmd/go/internal/modindex/write.go":      "f627d32df265399d206e353cf3a0ddd97edee2dc6fd530c412511b179bb72136",
	"src/cmd/go/internal/list/list.go":           "d5044d409044ec858dab308de9843b162385f0c276532095cff83b807f50fc7e",
	"src/cmd/go/internal/fsys/fsys.go":           "fb2a4ad0fcb9a4be756001a2123eae5273c7fdc7190f7544e8bb560f1c7eb458",
}

func captureMixedPackageRules(root string, observed *discoveryTargetFeatures) (discoveryGoLoaderRules, error) {
	rules := discoveryGoLoaderRules{
		Protocol: discoveryMixedPackageRulesProtocol, GoVersion: observed.GoVersion,
		VersionSHA256: observed.ToolSourceSHA256["VERSION"], SourceSHA256: make(map[string]string),
	}
	for name := range discoveryMixedPackageRuleSources {
		digest, err := discoveryFeatureFileSHA256(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return rules, err
		}
		rules.SourceSHA256[name] = digest
	}
	return rules, validateMixedPackageRules(rules, observed)
}

func validateMixedPackageRules(rules discoveryGoLoaderRules, observed *discoveryTargetFeatures) error {
	if rules.Protocol != discoveryMixedPackageRulesProtocol || rules.GoVersion != "go1.27.1" ||
		rules.GoVersion != observed.GoVersion || rules.VersionSHA256 != observed.ToolSourceSHA256["VERSION"] ||
		!discoverySHA256Pattern.MatchString(rules.VersionSHA256) ||
		!reflect.DeepEqual(rules.SourceSHA256, discoveryMixedPackageRuleSources) {
		return fmt.Errorf("unregistered mixed-package Go loader source rules")
	}
	return nil
}

func validateMixedPackageRejection(plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile,
	proof discoveryMixedPackageRejection) error {
	if proof.Protocol != discoveryMixedPackageProtocol || proof.CGOEnabled != "0" ||
		proof.DirectorySHA256 == "" || proof.DirectorySHA256 != fortranDirectorySHA256(plan, proof.Directory) ||
		proof.ProfileID != profile.ID || proof.Target != profile.Observed.Target ||
		proof.DriverSHA256 != profile.Observed.DriverSHA256 ||
		!discoverySHA256Pattern.MatchString(proof.OriginalDiagnosticSHA256) ||
		!equalDiscoveryStrings(proof.BuildTags, uniqueSortedDiscoveryStrings(proof.BuildTags)) ||
		len(proof.AsmFiles) == 0 || !equalDiscoveryStrings(proof.AsmFiles, uniqueSortedDiscoveryStrings(proof.AsmFiles)) ||
		proof.LoaderError.Pos != "" || len(proof.LoaderError.ImportStack) != 0 ||
		proof.LoaderError.Err != mixedPackageError(proof.Directory, proof.ConflictPackages, proof.ConflictFiles) ||
		!reflect.DeepEqual(proof.Invocation, fortranLoaderInvocation(proof.Package.PackagePath, proof.BuildTags)) {
		return fmt.Errorf("mixed-package proof lacks its exact source/package/profile/diagnostic/invocation")
	}
	for _, file := range proof.AsmFiles {
		if path.Dir(file) != proof.Directory {
			return fmt.Errorf("mixed-package proof claims foreign package assembly")
		}
	}
	if err := validateMixedPackageRules(proof.Rules, profile.Observed); err != nil {
		return err
	}
	declared, err := ordinaryProfileDeclaredModule(plan)
	if err != nil {
		return err
	}
	wantedPackage := declared
	if proof.Directory != "." {
		wantedPackage += "/" + proof.Directory
	}
	input := ordinaryProfileConsumerInput(plan, profile, declared, "", proof.AsmFiles, proof.BuildTags)
	if proof.Package.PackagePath != wantedPackage || len(proof.Package.CompiledGoFiles) != 0 {
		return fmt.Errorf("mixed-package rejection lacks its exact ordinary module role")
	}
	if err := gotoolprofile.ValidatePackageModule(input, proof.Package); err != nil {
		return err
	}
	if err := gotoolprofile.ValidateOrdinaryAssemblerMacros(proof.Package.Macros, profile.Observed, wantedPackage); err != nil {
		return err
	}
	selection, err := replayMixedPackageSelection(plan, profile, proof.Directory, proof.BuildTags)
	if err != nil || selection.Packages != proof.ConflictPackages || selection.Files != proof.ConflictFiles ||
		proof.PackageName != selection.Packages[0] ||
		!equalDiscoveryStrings(selection.GoFiles, proof.Package.GoFiles) ||
		!equalDiscoveryStrings(selection.SFiles, proof.Package.SFiles) ||
		!equalDiscoveryStrings(selection.TestGoFiles, proof.TestGoFiles) ||
		!equalDiscoveryStrings(selection.XTestGoFiles, proof.XTestGoFiles) ||
		!equalDiscoveryStrings(selection.IgnoredGoFiles, proof.IgnoredGoFiles) ||
		!equalDiscoveryStrings(selection.InvalidGoFiles, proof.InvalidGoFiles) ||
		!reflect.DeepEqual(selection.SourceSHA256, proof.Package.SourceSHA256) {
		return fmt.Errorf("mixed-package diagnostic differs from the complete original Go selection: %v", err)
	}
	if err := validateRejectedPackageCPPBindings(plan, proof.AsmFiles, proof.Package.Macros.Defines); err != nil {
		return err
	}
	return validateMixedPackageCommand(proof.Directory, selection.Packages, selection.Files, proof.ExitCode, proof.Stdout, proof.Stderr)
}

func captureMixedPackageRejection(ctx context.Context, plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile,
	root, workDir, goRoot string, env []string, group discoveryPackageGroup, tags []string,
	originalErr error) (discoveryMixedPackageRejection, error) {
	var proof discoveryMixedPackageRejection
	var captured *discoveryCapturedCommandError
	var originalExit *exec.ExitError
	if len(group.AsmFiles) == 0 || !errors.As(originalErr, &captured) ||
		!errors.As(originalErr, &originalExit) || originalExit.ExitCode() != 1 || isDiscoveryInfrastructureFailure(originalErr) {
		return proof, fmt.Errorf("mixed-package proof requires an actual complete original Go export failure")
	}
	proof = discoveryMixedPackageRejection{
		Protocol: discoveryMixedPackageProtocol, Directory: path.Dir(group.AsmFiles[0]),
		ProfileID: profile.ID, Target: profile.Observed.Target, BuildTags: append([]string(nil), tags...),
		AsmFiles: append([]string(nil), group.AsmFiles...), CGOEnabled: "0", DriverSHA256: profile.Observed.DriverSHA256,
	}
	proof.DirectorySHA256 = fortranDirectorySHA256(plan, proof.Directory)
	var err error
	selection, err := replayMixedPackageSelection(plan, profile, proof.Directory, tags)
	if err != nil {
		return proof, err
	}
	var pkg discoveryRejectedPackage
	proof.ConflictPackages, proof.ConflictFiles = selection.Packages, selection.Files
	proof.Package, pkg, err = captureRejectedPackageMetadata(ctx, plan, profile, workDir, env,
		discoveryPreCPPRejection{File: group.AsmFiles[0], BuildTags: tags})
	if err != nil || pkg.Error == nil || pkg.selectionStderr != "" {
		return proof, fmt.Errorf("mixed-package rejection lacks complete original package metadata: %v", err)
	}
	// Bind the physical diagnostic before discarding its private cache prefix.
	wantedDirectory := filepath.Join(root, filepath.FromSlash(proof.Directory))
	if filepath.Clean(pkg.Dir) != filepath.Clean(wantedDirectory) ||
		pkg.Error.Pos != "" || len(pkg.Error.ImportStack) != 0 ||
		pkg.Error.Err != mixedPackageError(pkg.Dir, proof.ConflictPackages, proof.ConflictFiles) {
		return proof, fmt.Errorf("mixed-package loader error references a foreign directory/package/source pair")
	}
	proof.PackageName, proof.LoaderError = pkg.Name, *pkg.Error
	proof.TestGoFiles = mixedPackageRelativeFiles(proof.Directory, pkg.TestGoFiles)
	proof.XTestGoFiles = mixedPackageRelativeFiles(proof.Directory, pkg.XTestGoFiles)
	proof.IgnoredGoFiles = mixedPackageRelativeFiles(proof.Directory, pkg.IgnoredGoFiles)
	proof.InvalidGoFiles = mixedPackageRelativeFiles(proof.Directory, pkg.InvalidGoFiles)
	proof.LoaderError.Err = mixedPackageError(proof.Directory, proof.ConflictPackages, proof.ConflictFiles)
	proof.Rules, err = captureMixedPackageRules(goRoot, profile.Observed)
	if err != nil {
		return proof, err
	}
	selectionEnv := replaceEnv(ordinaryProfileEnvironment(env, profile.Observed), map[string]string{"CGO_ENABLED": "0"})
	actualCGO, stderr, err := runDiscoveryMachineCommand(ctx, workDir, selectionEnv, "go", "env", "CGO_ENABLED")
	if err != nil || string(actualCGO) != "0\n" || len(stderr) != 0 {
		return proof, fmt.Errorf("mixed-package CGO0 environment observation failed: %v", err)
	}
	proof.Invocation = fortranLoaderInvocation(group.Pattern, tags)
	stdout, stderr, failure := runDiscoveryMachineCommand(ctx, workDir, selectionEnv, "go", proof.Invocation...)
	var exit *exec.ExitError
	if !errors.As(failure, &exit) || isDiscoveryInfrastructureFailure(failure) || captured.output != string(stderr) {
		return proof, fmt.Errorf("mixed-package independent original export rejection changed: %v", failure)
	}
	if err := validateMixedPackageCommand(pkg.Dir, proof.ConflictPackages, proof.ConflictFiles,
		exit.ExitCode(), string(stdout), string(stderr)); err != nil {
		return proof, err
	}
	proof.ExitCode, proof.Stdout = exit.ExitCode(), string(stdout)
	proof.Stderr = proof.LoaderError.Err + "\n"
	proof.OriginalDiagnosticSHA256 = discoveryFeatureBytesSHA256(stderr)
	return proof, validateMixedPackageRejection(plan, profile, proof)
}

func mixedPackageRelativeFiles(directory string, files []string) []string {
	var relative []string
	for _, file := range files {
		relative = append(relative, path.Join(directory, file))
	}
	return relative
}

func validateDiscoveryMixedPackageRejections(plan *discoveryOrdinarySelectionPlan, profiles []discoveryFeatureProfile,
	remaining map[discoveryProfileScope]bool) (map[discoveryProfileScope]discoveryMixedPackageRejection, error) {
	if len(plan.MixedPackageRejections) > 4096 {
		return nil, fmt.Errorf("mixed-package source exclusions exceed the explicit scope bound")
	}
	byProfile := make(map[string]discoveryFeatureProfile)
	for _, profile := range profiles {
		byProfile[profile.ID] = profile
	}
	rejected := make(map[discoveryProfileScope]discoveryMixedPackageRejection)
	for _, proof := range plan.MixedPackageRejections {
		profile, present := byProfile[proof.ProfileID]
		if !present {
			return nil, fmt.Errorf("mixed-package proof references an unknown target/profile")
		}
		if err := validateMixedPackageRejection(plan, profile, proof); err != nil {
			return nil, err
		}
		var expected []string
		for key := range remaining {
			if path.Dir(key.File) == proof.Directory && key.Target == proof.Target && key.ProfileID == proof.ProfileID &&
				key.Tags == strings.Join(proof.BuildTags, "\x00") {
				expected = append(expected, key.File)
			}
		}
		if !equalDiscoveryStrings(proof.AsmFiles, uniqueSortedDiscoveryStrings(expected)) {
			return nil, fmt.Errorf("mixed-package exclusion differs from the complete remaining package/profile scope")
		}
		for _, file := range proof.AsmFiles {
			key := discoveryProfileScope{File: file, Target: proof.Target, ProfileID: proof.ProfileID, Tags: strings.Join(proof.BuildTags, "\x00")}
			if _, duplicate := rejected[key]; duplicate {
				return nil, fmt.Errorf("duplicate mixed-package source/profile exclusion")
			}
			rejected[key] = proof
		}
	}
	return rejected, nil
}

func verifyDiscoveryMixedPackageSources(plan *discoveryOrdinarySelectionPlan, goRoot string) error {
	// verifyOrdinarySelectionUnchanged already rechecks every original file and
	// header. These additional full SDK files guard the registered loader loop.
	for _, proof := range plan.MixedPackageRejections {
		for name, wanted := range proof.Rules.SourceSHA256 {
			actual, err := discoveryFeatureFileSHA256(filepath.Join(goRoot, filepath.FromSlash(name)))
			if err != nil || actual != wanted {
				return fmt.Errorf("mixed-package original Go loader rules changed: %s: %v", name, err)
			}
		}
	}
	return nil
}
