package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

const discoveryFortranLoaderProtocol = "original_cgo0_fortran_loader_rejection_v1"
const discoverySourceNotApplicableFortranLoader = "go_cgo0_fortran_loader_rejected_package_target"
const discoveryFortranLoaderMessage = "Fortran source files not allowed when not using cgo or SWIG: "

// This is a source-role exclusion, not an assembly exception or object pass.
// Full original directory hashes bind every FF resource. The complete minimal
// headers let readers replay their filename/constraint selection independently
// of the actual Go FFiles list and the exact non-e export diagnostic.
type discoveryFortranLoaderRejection struct {
	Protocol        string                        `json:"protocol"`
	Directory       string                        `json:"directory"`
	DirectorySHA256 string                        `json:"directory_sha256"`
	ProfileID       string                        `json:"profile_id"`
	Target          string                        `json:"target"`
	BuildTags       []string                      `json:"build_tags,omitempty"`
	AsmFiles        []string                      `json:"asm_files"`
	CGOEnabled      string                        `json:"cgo_enabled"`
	PackageName     string                        `json:"package_name"`
	Package         gotoolprofile.PackageProof    `json:"package"`
	FFiles          []string                      `json:"fortran_files"`
	Inputs          []ordinarySelectionSource     `json:"fortran_selection_inputs"`
	CgoFiles        []string                      `json:"cgo_files,omitempty"`
	SwigFiles       []string                      `json:"swig_files,omitempty"`
	SwigCXXFiles    []string                      `json:"swig_cxx_files,omitempty"`
	DepsErrors      []string                      `json:"dependency_errors,omitempty"`
	LoaderError     discoveryRejectedPackageError `json:"loader_error"`
	Invocation      []string                      `json:"invocation"`
	ExitCode        int                           `json:"exit_code"`
	Stdout          string                        `json:"stdout"`
	Stderr          string                        `json:"stderr"`
	DriverSHA256    string                        `json:"driver_sha256"`
	Rules           discoveryFortranLoaderRules   `json:"go_loader_rules"`
}

// These complete source-file registrations are from the pinned current Go
// 1.27.1 sources: fileListForExt, MatchFile/readComments/shouldBuild and the
// actual cmd/go CGO clearing + UsesCgo/UsesSwig + FF rejection all remain bound.
// They are tool grammar guards, not a translator classification baseline.
var discoveryFortranRuleSources = map[string]string{
	"src/go/build/build.go":           "a8b066521d73f2b1c1f01d65588483e416deeab9b2139991645da0dc89dd7d49",
	"src/go/build/read.go":            "6e319d4ccc52e5a968a85cd5066948234a061c3ae958c77c07d0f943121b5c29",
	"src/go/build/constraint/expr.go": "96f51c3c0e5e9c6844d7ffb7ba36eee0076239710c3520e527f06f35d8734058",
	"src/cmd/go/internal/load/pkg.go": "d6e1adb610ec55f2e8bc0afd361eedd6e38689684bca122b02873da1d0ed1584",
}

type discoveryGoLoaderRules struct {
	Protocol      string            `json:"protocol"`
	GoVersion     string            `json:"go_version"`
	VersionSHA256 string            `json:"version_sha256"`
	SourceSHA256  map[string]string `json:"source_sha256"`
}

type discoveryFortranLoaderRules = discoveryGoLoaderRules

func captureFortranLoaderRules(root string, observed *discoveryTargetFeatures) (discoveryFortranLoaderRules, error) {
	proof := discoveryFortranLoaderRules{Protocol: "registered_go1271_fortran_loader_sources_v1",
		GoVersion: observed.GoVersion, VersionSHA256: observed.ToolSourceSHA256["VERSION"], SourceSHA256: make(map[string]string)}
	for name := range discoveryFortranRuleSources {
		digest, err := discoveryFeatureFileSHA256(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return proof, err
		}
		proof.SourceSHA256[name] = digest
	}
	return proof, validateFortranLoaderRules(proof, observed)
}

func validateFortranLoaderRules(proof discoveryFortranLoaderRules, observed *discoveryTargetFeatures) error {
	if proof.Protocol != "registered_go1271_fortran_loader_sources_v1" || proof.GoVersion != "go1.27.1" ||
		proof.GoVersion != observed.GoVersion || proof.VersionSHA256 != observed.ToolSourceSHA256["VERSION"] ||
		!discoverySHA256Pattern.MatchString(proof.VersionSHA256) || !reflect.DeepEqual(proof.SourceSHA256, discoveryFortranRuleSources) {
		return fmt.Errorf("unregistered or changed actual Go Fortran loader source rules")
	}
	return nil
}

func isDiscoveryFortranFile(file string) bool {
	switch path.Ext(file) {
	case ".f", ".F", ".for", ".f90":
		return true
	}
	return false
}

func fortranLoaderInvocation(pkg string, tags []string) []string {
	args := []string{"list", "-export", "-mod=mod"}
	if len(tags) != 0 {
		args = append(args, "-tags="+strings.Join(tags, ","))
	}
	return append(args, pkg)
}

func fortranLoaderError(files []string) string {
	return discoveryFortranLoaderMessage + strings.Join(files, " ")
}

func validateFortranLoaderCommand(pkg string, files []string, code int, stdout, stderr string) error {
	if len(files) == 0 || !equalDiscoveryStrings(files, uniqueSortedDiscoveryStrings(files)) || code != 1 || stdout != "" ||
		stderr != "package "+pkg+": "+fortranLoaderError(files)+"\n" || isDiscoveryGoBuildInfrastructureFailure(stderr) {
		return fmt.Errorf("Fortran loader rejection lacks complete unique original export diagnostic/exit")
	}
	return nil
}

func isPotentialFortranLoaderFailure(pkg string, failure error) bool {
	var captured *discoveryCapturedCommandError
	if !errors.As(failure, &captured) {
		return false
	}
	prefix := "package " + pkg + ": " + discoveryFortranLoaderMessage
	return strings.HasPrefix(captured.output, prefix) || strings.Contains(captured.output, "\n"+prefix)
}

func fortranSelectionInput(file string, data []byte) (ordinarySelectionSource, error) {
	header, err := fortranSelectionPrefix(data)
	if err != nil {
		return ordinarySelectionSource{}, err
	}
	return ordinarySelectionSource{File: file, SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Header: header,
		HeaderSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(header)))}, nil
}

// Bound the leading input supplied to stock Go MatchFile, not its selection
// rules. Preserve original BOM, whitespace, semicolons, comment terminators,
// EOF and the first non-comment byte. Go's registered readComments then makes
// the actual lexical/build-constraint decision, including malformed prefixes.
func fortranSelectionPrefix(data []byte) (string, error) {
	index := 0
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		index = 3
	}
	for index < len(data) {
		if index >= 64<<10 {
			return "", fmt.Errorf("Fortran selection header exceeds the explicit 64 KiB bound")
		}
		switch data[index] {
		case ' ', '\f', '\t', '\r', '\n', ';':
			index++
			continue
		}
		if data[index] == '/' && index+1 < len(data) {
			switch data[index+1] {
			case '/':
				end := bytes.IndexByte(data[index:], '\n')
				if end < 0 {
					index = len(data)
				} else {
					index += end + 1
				}
				continue
			case '*':
				end := bytes.Index(data[index+2:], []byte("*/"))
				if end < 0 {
					index = len(data)
				} else {
					index += end + 4
				}
				continue
			}
			index++ // Preserve both bytes of a malformed leading slash.
		}
		index++
		break
	}
	if index > 64<<10 {
		return "", fmt.Errorf("Fortran selection header exceeds the explicit 64 KiB bound")
	}
	return string(data[:index]), nil
}

func fortranDirectoryInputs(plan *discoveryOrdinarySelectionPlan, directory string) map[string]string {
	files := make(map[string]string)
	for _, dir := range plan.Directories {
		if dir.Directory == directory {
			for _, entry := range dir.Entries {
				if entry.Kind == "file" && isDiscoveryFortranFile(entry.Name) {
					files[path.Join(directory, entry.Name)] = entry.SHA256
				}
			}
		}
	}
	return files
}

func fortranDirectorySHA256(plan *discoveryOrdinarySelectionPlan, directory string) string {
	for _, dir := range plan.Directories {
		if dir.Directory == directory {
			data, err := json.Marshal(dir)
			if err == nil {
				return discoveryFeatureBytesSHA256(data)
			}
		}
	}
	return ""
}

func replayFortranFiles(plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile, proof discoveryFortranLoaderRejection) ([]string, error) {
	wanted := fortranDirectoryInputs(plan, proof.Directory)
	if len(wanted) == 0 || len(wanted) > 4096 || len(proof.Inputs) != len(wanted) {
		return nil, fmt.Errorf("Fortran loader proof omitted its complete original FF directory inventory")
	}
	inputs := make(map[string][]byte)
	previous := ""
	for _, input := range proof.Inputs {
		if !ordinarySelectionLocalPath(input.File) || input.File <= previous || wanted[input.File] != input.SHA256 ||
			input.HeaderSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(input.Header))) || len(input.Header) > 64<<10 || input.PackageDiagnostic != "" {
			return nil, fmt.Errorf("Fortran loader selection input differs from the complete original directory")
		}
		inputs[input.File], previous = []byte(input.Header), input.File
	}
	ctx, err := discoveryContextForFeatureProfile(profile.Observed)
	if err != nil {
		return nil, err
	}
	ctx.BuildTags = proof.BuildTags
	ctx.OpenFile = func(file string) (io.ReadCloser, error) {
		data, present := inputs[filepath.ToSlash(file)]
		if !present {
			return nil, fmt.Errorf("Fortran loader source selection lacks header %s", file)
		}
		return io.NopCloser(strings.NewReader(string(data))), nil
	}
	var selected []string
	for _, input := range proof.Inputs {
		match, err := ctx.MatchFile(filepath.FromSlash(proof.Directory), path.Base(input.File))
		if err != nil {
			return nil, err
		}
		if match {
			selected = append(selected, path.Base(input.File))
		}
	}
	return selected, nil
}

func validateFortranLoaderRejection(plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile, proof discoveryFortranLoaderRejection) error {
	if proof.Protocol != discoveryFortranLoaderProtocol || proof.CGOEnabled != "0" || proof.PackageName == "" ||
		!discoverySHA256Pattern.MatchString(proof.DirectorySHA256) || proof.DirectorySHA256 != fortranDirectorySHA256(plan, proof.Directory) ||
		proof.ProfileID != profile.ID || proof.Target != profile.Observed.Target || proof.DriverSHA256 != profile.Observed.DriverSHA256 ||
		len(proof.CgoFiles)+len(proof.SwigFiles)+len(proof.SwigCXXFiles)+len(proof.DepsErrors) != 0 ||
		!equalDiscoveryStrings(proof.BuildTags, uniqueSortedDiscoveryStrings(proof.BuildTags)) ||
		len(proof.AsmFiles) == 0 || !equalDiscoveryStrings(proof.AsmFiles, uniqueSortedDiscoveryStrings(proof.AsmFiles)) ||
		proof.LoaderError.Pos != "" || !equalDiscoveryStrings(proof.LoaderError.ImportStack, []string{proof.Package.PackagePath}) ||
		proof.LoaderError.Err != fortranLoaderError(proof.FFiles) ||
		!reflect.DeepEqual(proof.Invocation, fortranLoaderInvocation(proof.Package.PackagePath, proof.BuildTags)) {
		return fmt.Errorf("Fortran loader proof lacks exact package/profile/CGO0/source error/invocation")
	}
	for _, file := range proof.AsmFiles {
		if path.Dir(file) != proof.Directory {
			return fmt.Errorf("Fortran loader proof claims a foreign package assembly file")
		}
	}
	if err := validateFortranLoaderRules(proof.Rules, profile.Observed); err != nil {
		return err
	}
	if err := validatePreCPPPackage(plan, profile, discoveryPreCPPRejection{File: proof.AsmFiles[0], BuildTags: proof.BuildTags, Package: proof.Package}); err != nil {
		return err
	}
	for _, file := range proof.Package.GoFiles {
		for _, source := range plan.Sources {
			if source.File == file {
				parsed, err := parser.ParseFile(token.NewFileSet(), file, source.Header, parser.PackageClauseOnly)
				if err != nil || parsed.Name.Name != proof.PackageName {
					return fmt.Errorf("Fortran loader actual package name differs from original selected Go source")
				}
			}
		}
	}
	files, err := replayFortranFiles(plan, profile, proof)
	if err != nil || !equalDiscoveryStrings(files, proof.FFiles) {
		return fmt.Errorf("actual Go FFiles differs from original filename/constraint selection: %v", err)
	}
	if err := validateFortranCPPBindings(plan, proof); err != nil {
		return err
	}
	return validateFortranLoaderCommand(proof.Package.PackagePath, files, proof.ExitCode, proof.Stdout, proof.Stderr)
}

func validateFortranCPPBindings(plan *discoveryOrdinarySelectionPlan, proof discoveryFortranLoaderRejection) error {
	return validateRejectedPackageCPPBindings(plan, proof.AsmFiles, proof.Package.Macros.Defines)
}

func validateRejectedPackageCPPBindings(plan *discoveryOrdinarySelectionPlan, asmFiles, defines []string) error {
	if plan.CPPInputs == nil {
		return fmt.Errorf("loader exclusion lacks its independently registered original CPP graph")
	}
	units := make(map[string]discoveryCPPUnit)
	for _, unit := range plan.CPPInputs.Units {
		units[unit.File] = unit
	}
	for _, file := range asmFiles {
		unit, present := units[file]
		if !present {
			return fmt.Errorf("loader scope lacks its original CPP registration: %s", file)
		}
		if plan.CPPInputs.Protocol == discoveryDeferredCPPInputsProtocol {
			// A loader refusal cannot provide compiler-generated definitions.
			// Replay with the actual ordinary CPU macros and no invented header:
			// active missing/generated includes fail, inactive edges stay inactive.
			if _, err := discoveryDeferredCPPConsumption(plan.CPPInputs, unit, nil, defines); err != nil {
				return fmt.Errorf("loader cannot hide an unproved active CPP binding: %s: %w", file, err)
			}
		}
	}
	return nil
}

func captureFortranLoaderRejection(ctx context.Context, plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile,
	root, workDir, goRoot string, env []string, group discoveryPackageGroup, tags []string, originalErr error) (discoveryFortranLoaderRejection, error) {
	if len(group.AsmFiles) == 0 {
		return discoveryFortranLoaderRejection{}, fmt.Errorf("Fortran loader capture lacks its selected package assembly scope")
	}
	proof := discoveryFortranLoaderRejection{Protocol: discoveryFortranLoaderProtocol, Directory: path.Dir(group.AsmFiles[0]),
		ProfileID: profile.ID, Target: profile.Observed.Target, BuildTags: append([]string(nil), tags...),
		AsmFiles: append([]string(nil), group.AsmFiles...), CGOEnabled: "0", DriverSHA256: profile.Observed.DriverSHA256}
	proof.DirectorySHA256 = fortranDirectorySHA256(plan, proof.Directory)
	var captured *discoveryCapturedCommandError
	var originalExit *exec.ExitError
	if !errors.As(originalErr, &captured) || !errors.As(originalErr, &originalExit) || originalExit.ExitCode() != 1 ||
		isDiscoveryInfrastructureFailure(originalErr) {
		return proof, fmt.Errorf("Fortran source proof requires an actual complete Go export failure")
	}
	var err error
	var pkg discoveryRejectedPackage
	proof.Package, pkg, err = captureRejectedOrdinaryPackage(ctx, plan, profile, workDir, env,
		discoveryPreCPPRejection{File: group.AsmFiles[0], BuildTags: tags})
	if err != nil || pkg.Error == nil {
		return proof, fmt.Errorf("Fortran loader lacks actual package-role/error metadata: %v", err)
	}
	proof.PackageName, proof.FFiles = pkg.Name, pkg.FFiles
	proof.CgoFiles, proof.SwigFiles, proof.SwigCXXFiles = pkg.CgoFiles, pkg.SwigFiles, pkg.SwigCXXFiles
	proof.LoaderError = *pkg.Error
	for _, failure := range pkg.DepsErrors {
		proof.DepsErrors = append(proof.DepsErrors, failure.Err)
	}
	selectionEnv := replaceEnv(ordinaryProfileEnvironment(env, profile.Observed), map[string]string{"CGO_ENABLED": "0"})
	actualCGO, stderr, err := runDiscoveryMachineCommand(ctx, workDir, selectionEnv, "go", "env", "CGO_ENABLED")
	if err != nil || string(actualCGO) != "0\n" || len(stderr) != 0 {
		return proof, fmt.Errorf("Fortran loader CGO0 environment observation failed: %v", err)
	}
	proof.Rules, err = captureFortranLoaderRules(goRoot, profile.Observed)
	if err != nil {
		return proof, err
	}
	for _, file := range sortedFortranSourceKeys(fortranDirectoryInputs(plan, proof.Directory)) {
		filename := filepath.Join(root, filepath.FromSlash(file))
		if err := discoveryCPPRegularSource(root, filename); err != nil {
			return proof, err
		}
		data, err := readDiscoveryChecksumFile(filename, 64<<20)
		if err != nil {
			return proof, err
		}
		input, err := fortranSelectionInput(file, data)
		if err != nil {
			return proof, err
		}
		proof.Inputs = append(proof.Inputs, input)
	}
	proof.Invocation = fortranLoaderInvocation(group.Pattern, tags)
	stdout, stderr, failure := runDiscoveryMachineCommand(ctx, workDir, selectionEnv, "go", proof.Invocation...)
	var exit *exec.ExitError
	if !errors.As(failure, &exit) || exit.ExitCode() != 1 || captured.output != string(stderr) {
		return proof, fmt.Errorf("Fortran loader independent exact export rejection changed: %v", failure)
	}
	proof.ExitCode, proof.Stdout, proof.Stderr = exit.ExitCode(), string(stdout), string(stderr)
	return proof, validateFortranLoaderRejection(plan, profile, proof)
}

func sortedFortranSourceKeys(values map[string]string) []string {
	keys := make(map[string]bool, len(values))
	for key := range values {
		keys[key] = true
	}
	return sortedDiscoverySet(keys)
}

func validateDiscoveryFortranRejections(plan *discoveryOrdinarySelectionPlan, profiles []discoveryFeatureProfile,
	remaining map[discoveryProfileScope]bool) (map[discoveryProfileScope]discoveryFortranLoaderRejection, error) {
	byProfile := make(map[string]discoveryFeatureProfile)
	for _, profile := range profiles {
		byProfile[profile.ID] = profile
	}
	rejected := make(map[discoveryProfileScope]discoveryFortranLoaderRejection)
	if len(plan.FortranRejections) > 4096 {
		return nil, fmt.Errorf("Fortran loader rejected scopes exceed the explicit 4096 bound")
	}
	for _, proof := range plan.FortranRejections {
		profile, present := byProfile[proof.ProfileID]
		if !present {
			return nil, fmt.Errorf("Fortran loader proof references an unknown target/profile")
		}
		if err := validateFortranLoaderRejection(plan, profile, proof); err != nil {
			return nil, err
		}
		var expected []string
		for key := range remaining {
			if path.Dir(key.File) == proof.Directory && key.Target == proof.Target && key.ProfileID == proof.ProfileID && key.Tags == strings.Join(proof.BuildTags, "\x00") {
				expected = append(expected, key.File)
			}
		}
		if !equalDiscoveryStrings(proof.AsmFiles, uniqueSortedDiscoveryStrings(expected)) {
			return nil, fmt.Errorf("Fortran loader exclusion differs from the complete remaining package/profile scope")
		}
		for _, file := range proof.AsmFiles {
			key := discoveryProfileScope{File: file, Target: proof.Target, ProfileID: proof.ProfileID, Tags: strings.Join(proof.BuildTags, "\x00")}
			if _, duplicate := rejected[key]; duplicate {
				return nil, fmt.Errorf("duplicate Fortran loader rejected source/profile scope")
			}
			rejected[key] = proof
		}
	}
	return rejected, nil
}

func verifyDiscoveryFortranOriginalSources(plan *discoveryOrdinarySelectionPlan, root, goRoot string) error {
	for _, proof := range plan.FortranRejections {
		for name, wanted := range proof.Rules.SourceSHA256 {
			actual, err := discoveryFeatureFileSHA256(filepath.Join(goRoot, filepath.FromSlash(name)))
			if err != nil || actual != wanted {
				return fmt.Errorf("Fortran loader original Go source rules changed: %s: %v", name, err)
			}
		}
		for _, input := range proof.Inputs {
			filename := filepath.Join(root, filepath.FromSlash(input.File))
			if err := discoveryCPPRegularSource(root, filename); err != nil {
				return err
			}
			data, err := readDiscoveryChecksumFile(filename, 64<<20)
			if err != nil {
				return err
			}
			actual, err := fortranSelectionInput(input.File, data)
			if err != nil || actual != input {
				return fmt.Errorf("Fortran loader original resource/header changed: %s: %v", input.File, err)
			}
		}
	}
	return nil
}
