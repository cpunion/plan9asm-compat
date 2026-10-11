package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

const discoveryDocumentationProtocol = "original_always_documentation_role_v1"
const discoveryDocumentationKind = "go_always_documentation_package"
const discoveryDocumentationReason = "stock Go ignores every original non-test Go source in package documentation; no current Go package exists"

// These are complete stock Go 1.27.1 source registrations, not selected
// conditions or an error-text allowlist. Both go/build and the module index
// ignore documentation, and load converts their typed build.NoGoError into
// the driver diagnostic. Index scanning/serialization and both header readers
// remain bound along with filename/build-constraint selection.
var discoveryDocumentationRuleSources = map[string]string{
	"src/go/build/build.go":                      "a8b066521d73f2b1c1f01d65588483e416deeab9b2139991645da0dc89dd7d49",
	"src/go/build/read.go":                       "6e319d4ccc52e5a968a85cd5066948234a061c3ae958c77c07d0f943121b5c29",
	"src/go/build/constraint/expr.go":            "96f51c3c0e5e9c6844d7ffb7ba36eee0076239710c3520e527f06f35d8734058",
	"src/cmd/go/internal/modindex/build.go":      "f75d94b743539b7b275870327e23b7af63c9c8af74dd9ce8692048d2936efde4",
	"src/cmd/go/internal/modindex/build_read.go": "30057658fad607095965df8bce7456922935c03cc014200077c17c3d3bc0866f",
	"src/cmd/go/internal/modindex/read.go":       "c79698b8bb8075f7dd4c8ac8a7f30a7b93cdb3cac8a8c4641ec0b0d96b39fcad",
	"src/cmd/go/internal/modindex/scan.go":       "751915000cd027a051928ee9b5bce6857e54259b0270fdde2e33d1e498a15916",
	"src/cmd/go/internal/modindex/write.go":      "f627d32df265399d206e353cf3a0ddd97edee2dc6fd530c412511b179bb72136",
	"src/cmd/go/internal/load/pkg.go":            "d6e1adb610ec55f2e8bc0afd361eedd6e38689684bca122b02873da1d0ed1584",
}

type discoveryDocumentationRules struct {
	Protocol      string            `json:"protocol"`
	GoVersion     string            `json:"go_version"`
	VersionSHA256 string            `json:"version_sha256"`
	SourceSHA256  map[string]string `json:"source_sha256"`
}

// Source contents live in the existing ZIP-bound shared inventory. Each
// query references one whole directory and one actual profile/tag scope; it
// does not relabel ignored Go files as compiled ordinary sources or emit an
// assembly object. SFiles includes all actual selected siblings, even empty.
type discoveryDocumentationPackage struct {
	Directory       string                        `json:"directory"`
	DirectorySHA256 string                        `json:"directory_sha256"`
	ProfileID       string                        `json:"profile_id"`
	Target          string                        `json:"target"`
	BuildTags       []string                      `json:"build_tags,omitempty"`
	AsmFiles        []string                      `json:"asm_files"`
	IgnoredGoFiles  []string                      `json:"ignored_go_files"`
	Package         gotoolprofile.PackageProof    `json:"package"`
	LoaderErrorKind string                        `json:"loader_error_kind"`
	LoaderError     discoveryRejectedPackageError `json:"loader_error"`
	DriverSHA256    string                        `json:"driver_sha256"`
	Invocation      []string                      `json:"invocation"`
}

func documentationNormalGo(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") &&
		!strings.HasPrefix(name, "_") && !strings.HasPrefix(name, ".")
}

// Missing, invalid, or ordinary Go files cannot authorize this role. Headers
// and hashes are already checked against every complete directory entry.
func alwaysDocumentationDirectory(directory string, sources map[string][]byte, entries map[string]string) bool {
	count := 0
	for name, kind := range entries {
		if kind != "file" || !documentationNormalGo(name) {
			continue
		}
		count++
		file := path.Join(directory, name)
		data, present := sources[file]
		parsed, err := parser.ParseFile(token.NewFileSet(), file, data, parser.PackageClauseOnly)
		if !present || err != nil || parsed.Name.Name != "documentation" {
			return false
		}
	}
	return count > 0
}

// A cheap syntax prefilter only avoids unnecessary full inventory replay for
// ordinary CPP pairs. It never supplies exclusion evidence; a possible match
// still has to pass alwaysDocumentationDirectory and actual role queries.
func possibleDocumentationDirectory(plan *discoveryOrdinarySelectionPlan, directory string) bool {
	count := 0
	for _, source := range plan.Sources {
		if path.Dir(source.File) != directory || !documentationNormalGo(path.Base(source.File)) {
			continue
		}
		count++
		parsed, err := parser.ParseFile(token.NewFileSet(), source.File, source.Header, parser.PackageClauseOnly)
		if err != nil || parsed.Name.Name != "documentation" {
			return false
		}
	}
	return count > 0
}

func documentationDirectorySHA256(plan *discoveryOrdinarySelectionPlan, directory string) string {
	for _, inventory := range plan.Directories {
		if inventory.Directory == directory {
			data, err := json.Marshal(inventory)
			if err == nil {
				return discoveryFeatureBytesSHA256(data)
			}
		}
	}
	return ""
}

func captureDocumentationRules(root string, observed *discoveryTargetFeatures) (*discoveryDocumentationRules, error) {
	proof := &discoveryDocumentationRules{Protocol: discoveryDocumentationProtocol,
		GoVersion: observed.GoVersion, VersionSHA256: observed.ToolSourceSHA256["VERSION"], SourceSHA256: make(map[string]string)}
	for file := range discoveryDocumentationRuleSources {
		name := filepath.Join(root, filepath.FromSlash(file))
		if err := discoveryCPPRegularSource(root, name); err != nil {
			return nil, err
		}
		digest, err := discoveryFeatureFileSHA256(name)
		if err != nil {
			return nil, err
		}
		proof.SourceSHA256[file] = digest
	}
	return proof, validateDocumentationRules(proof, observed)
}

func validateDocumentationRules(proof *discoveryDocumentationRules, observed *discoveryTargetFeatures) error {
	if proof == nil || proof.Protocol != discoveryDocumentationProtocol || proof.GoVersion != "go1.27.1" ||
		proof.GoVersion != observed.GoVersion || proof.VersionSHA256 != observed.ToolSourceSHA256["VERSION"] ||
		!discoverySHA256Pattern.MatchString(proof.VersionSHA256) || !reflect.DeepEqual(proof.SourceSHA256, discoveryDocumentationRuleSources) {
		return fmt.Errorf("documentation role lacks both complete registered stock Go ignore/error source rules")
	}
	return nil
}

func documentationInvocation(pkg string, tags []string) []string {
	args := []string{"list", "-e", "-json", "-mod=mod"}
	if len(tags) != 0 {
		args = append(args, "-tags="+strings.Join(tags, ","))
	}
	return append(args, pkg)
}

// Readers recompute the required scope set from the original directory and
// actual source/profile/tag planner. A missing, new, or duplicate query is not
// allowed to fall back to a historical source-only selection decision.
func documentationRequiredPackages(decisions []ordinaryProfileDecision) []discoveryDocumentationPackage {
	type key struct{ directory, profile, target, tags string }
	groups := make(map[key][]string)
	for _, decision := range decisions {
		if decision.Kind != discoveryDocumentationKind {
			continue
		}
		for _, file := range decision.AsmFiles {
			for _, target := range decision.Targets {
				k := key{path.Dir(file), decision.ProfileID, target, strings.Join(decision.BuildTags, "\x00")}
				groups[k] = append(groups[k], file)
			}
		}
	}
	var packages []discoveryDocumentationPackage
	for k, files := range groups {
		proof := discoveryDocumentationPackage{Directory: k.directory, ProfileID: k.profile,
			Target: k.target, AsmFiles: uniqueSortedDiscoveryStrings(files)}
		if k.tags != "" {
			proof.BuildTags = strings.Split(k.tags, "\x00")
		}
		packages = append(packages, proof)
	}
	sort.Slice(packages, func(i, j int) bool {
		a, b := packages[i], packages[j]
		return documentationPackageKey(a) < documentationPackageKey(b)
	})
	return packages
}

func documentationPackageKey(proof discoveryDocumentationPackage) string {
	return strings.Join([]string{proof.Directory, proof.ProfileID, proof.Target, strings.Join(proof.BuildTags, "\x00")}, "\n")
}

func replayDocumentationFiles(plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile,
	proof discoveryDocumentationPackage) ([]string, []string, error) {
	sources, directories, err := ordinarySelectionBytes(plan)
	if err != nil {
		return nil, nil, err
	}
	if !alwaysDocumentationDirectory(proof.Directory, sources, directories[proof.Directory]) {
		return nil, nil, fmt.Errorf("documentation role does not cover every original nonhidden/nontest Go file")
	}
	ctx, err := discoveryContextForFeatureProfile(profile.Observed)
	if err != nil {
		return nil, nil, err
	}
	ctx.BuildTags = proof.BuildTags
	ctx.OpenFile = func(file string) (io.ReadCloser, error) {
		data, present := sources[filepath.ToSlash(file)]
		if !present {
			return nil, fmt.Errorf("documentation role lacks original selection input %s", file)
		}
		return io.NopCloser(strings.NewReader(string(data))), nil
	}
	var ignored, assembly []string
	for name, kind := range directories[proof.Directory] {
		if kind != "file" || strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".") ||
			!strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".s") {
			continue
		}
		file := path.Join(proof.Directory, name)
		selected, err := ctx.MatchFile(filepath.FromSlash(proof.Directory), name)
		if err != nil {
			return nil, nil, err
		}
		if strings.HasSuffix(name, ".s") {
			if selected {
				assembly = append(assembly, file)
			}
			continue
		}
		if !selected {
			ignored = append(ignored, file)
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, sources[file], parser.PackageClauseOnly)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid selected documentation-role Go package clause: %w", err)
		}
		if parsed.Name.Name == "documentation" {
			ignored = append(ignored, file)
		} else {
			return nil, nil, fmt.Errorf("selected ordinary/test Go source cannot produce a typed documentation NoGoError")
		}
	}
	return uniqueSortedDiscoveryStrings(ignored), uniqueSortedDiscoveryStrings(assembly), nil
}

func validateDocumentationPackage(plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile, proof discoveryDocumentationPackage) error {
	declared, err := ordinaryProfileDeclaredModule(plan)
	if err != nil {
		return err
	}
	pkgPath := declared
	if proof.Directory != "." {
		pkgPath += "/" + proof.Directory
	}
	if proof.ProfileID != profile.ID || proof.Target != profile.Observed.Target || proof.DriverSHA256 != profile.Observed.DriverSHA256 ||
		proof.DirectorySHA256 != documentationDirectorySHA256(plan, proof.Directory) || !discoverySHA256Pattern.MatchString(proof.DirectorySHA256) ||
		proof.LoaderErrorKind != "go/build.NoGoError" || proof.LoaderError.Pos != "" ||
		!equalDiscoveryStrings(proof.LoaderError.ImportStack, []string{pkgPath}) ||
		proof.LoaderError.Err != "build constraints exclude all Go files in module/"+proof.Directory ||
		!reflect.DeepEqual(proof.Invocation, documentationInvocation(pkgPath, proof.BuildTags)) ||
		len(proof.Package.GoFiles) != 0 || len(proof.Package.CompiledGoFiles) != 0 || proof.Package.PackagePath != pkgPath ||
		!equalDiscoveryStrings(proof.BuildTags, uniqueSortedDiscoveryStrings(proof.BuildTags)) {
		return fmt.Errorf("documentation role lacks its exact typed NoGoError/package/profile/invocation")
	}
	input := ordinaryProfileConsumerInput(plan, profile, declared, "", proof.AsmFiles, proof.BuildTags)
	if err := gotoolprofile.ValidatePackageModule(input, proof.Package); err != nil {
		return err
	}
	if err := gotoolprofile.ValidateOrdinaryAssemblerMacros(proof.Package.Macros, profile.Observed, pkgPath); err != nil {
		return err
	}
	ignored, assembly, err := replayDocumentationFiles(plan, profile, proof)
	if err != nil || len(ignored) == 0 || !equalDiscoveryStrings(ignored, proof.IgnoredGoFiles) ||
		!equalDiscoveryStrings(assembly, proof.Package.SFiles) {
		return fmt.Errorf("actual documentation IgnoredGoFiles/SFiles differ from complete original inventory: %v", err)
	}
	wanted := make(map[string]string)
	for _, source := range plan.Sources {
		if containsTargetFeature(ignored, source.File) || containsTargetFeature(assembly, source.File) {
			wanted[source.File] = source.SHA256
		}
	}
	if !reflect.DeepEqual(wanted, proof.Package.SourceSHA256) {
		return fmt.Errorf("documentation role source hashes do not cover complete ignored-Go/selected-assembly inputs")
	}
	return validateDocumentationRules(plan.DocumentationRules, profile.Observed)
}

func validateDiscoveryDocumentationPackages(plan *discoveryOrdinarySelectionPlan, profiles []discoveryFeatureProfile,
	decisions []ordinaryProfileDecision) error {
	if plan.DocumentationSourceProtocol == "" {
		if plan.DocumentationRules != nil || len(plan.DocumentationPackages) != 0 {
			return fmt.Errorf("documentation evidence cannot downgrade to historical selection")
		}
		return nil
	}
	if plan.DocumentationSourceProtocol != discoveryDocumentationProtocol {
		return fmt.Errorf("unknown documentation-source protocol")
	}
	expected := documentationRequiredPackages(decisions)
	if len(expected) != len(plan.DocumentationPackages) || len(expected) > 4096 ||
		len(expected) == 0 && plan.DocumentationRules != nil {
		return fmt.Errorf("documentation source proof omitted or added required directory/profile/tag scopes")
	}
	byProfile := make(map[string]discoveryFeatureProfile)
	for _, profile := range profiles {
		byProfile[profile.ID] = profile
	}
	for index, proof := range plan.DocumentationPackages {
		wanted := expected[index]
		if documentationPackageKey(proof) != documentationPackageKey(wanted) || !equalDiscoveryStrings(proof.AsmFiles, wanted.AsmFiles) {
			return fmt.Errorf("documentation source proof has a foreign/duplicate/missing original scope")
		}
		if err := validateDocumentationPackage(plan, byProfile[proof.ProfileID], proof); err != nil {
			return err
		}
	}
	return nil
}

func captureDiscoveryDocumentationPackages(ctx context.Context, plan *discoveryOrdinarySelectionPlan, profiles []discoveryFeatureProfile,
	decisions []ordinaryProfileDecision, dir, root string, env []string, markers string, cache *discoveryFeatureObservationCache) (operationErr error) {
	plan.DocumentationPackages = documentationRequiredPackages(decisions)
	if len(plan.DocumentationPackages) > 4096 {
		return fmt.Errorf("documentation directory/profile/tag queries exceed the explicit 4096 bound")
	}
	if len(plan.DocumentationPackages) == 0 {
		return nil
	}
	byProfile := make(map[string]discoveryFeatureProfile)
	for _, profile := range profiles {
		byProfile[profile.ID] = profile
	}
	usedProfiles := make(map[string]bool)
	defer func() {
		for _, profile := range profiles {
			if usedProfiles[profile.ID] {
				if err := verifyDiscoveryProfileCurrent(ctx, markers, env, profile, cache); err != nil {
					operationErr = errors.Join(operationErr, err)
				}
			}
		}
		if err := verifyDiscoveryDocumentationSources(plan, root); err != nil {
			operationErr = errors.Join(operationErr, err)
		}
	}()
	for index := range plan.DocumentationPackages {
		proof := &plan.DocumentationPackages[index]
		profile := byProfile[proof.ProfileID]
		if !usedProfiles[profile.ID] {
			if err := verifyDiscoveryProfileCurrent(ctx, markers, env, profile, cache); err != nil {
				return err
			}
			usedProfiles[profile.ID] = true
		}
		if plan.DocumentationRules == nil {
			var err error
			plan.DocumentationRules, err = captureDocumentationRules(root, profile.Observed)
			if err != nil {
				return err
			}
		}
		captured, pkg, err := captureRejectedPackageMetadata(ctx, plan, profile, dir, env,
			discoveryPreCPPRejection{File: proof.AsmFiles[0], BuildTags: proof.BuildTags})
		if err != nil || pkg.Error == nil || pkg.selectionStderr != "" || len(pkg.GoFiles)+len(pkg.CgoFiles)+len(pkg.SwigFiles)+len(pkg.SwigCXXFiles)+len(pkg.DepsErrors) != 0 ||
			pkg.Error.Pos != "" || pkg.Error.Err != "build constraints exclude all Go files in "+pkg.Dir {
			return fmt.Errorf("actual documentation query did not produce only stock Go NoGoError: %v; error=%+v Go=%v cgo=%v SWIG=%v/%v dependencies=%v stderr=%q",
				err, pkg.Error, pkg.GoFiles, pkg.CgoFiles, pkg.SwigFiles, pkg.SwigCXXFiles, pkg.DepsErrors, pkg.selectionStderr)
		}
		// The JSON error text alone is not a typed rejection. Independently
		// observe build.NoGoError from the same Go-version library on the real
		// original directory, with this exact target/profile/tag context.
		if runtime.Version() != profile.Observed.GoVersion {
			return fmt.Errorf("typed documentation observer differs from actual Go driver version")
		}
		buildContext, err := discoveryContextForFeatureProfile(profile.Observed)
		if err != nil {
			return err
		}
		buildContext.BuildTags = proof.BuildTags
		selected, selectionError := buildContext.ImportDir(pkg.Dir, 0)
		var noGo *build.NoGoError
		if !errors.As(selectionError, &noGo) || noGo.Dir != pkg.Dir || selected == nil ||
			len(selected.GoFiles)+len(selected.CgoFiles) != 0 || !equalDiscoveryStrings(selected.IgnoredGoFiles, pkg.IgnoredGoFiles) ||
			!equalDiscoveryStrings(selected.SFiles, pkg.SFiles) {
			return fmt.Errorf("actual documentation observer lacks typed build.NoGoError or disagrees with stock module-index selection: %v", selectionError)
		}
		for _, file := range pkg.IgnoredGoFiles {
			filename := filepath.Join(pkg.Dir, file)
			if path.Base(file) != file {
				return fmt.Errorf("documentation ignored source is not package-local: %s", file)
			}
			if err := discoveryCPPRegularSource(pkg.Module.Dir, filename); err != nil {
				return fmt.Errorf("documentation ignored source is not original regular module input: %s: %w", file, err)
			}
			relative, err := filepath.Rel(pkg.Module.Dir, filename)
			if err != nil || !ordinarySelectionLocalPath(filepath.ToSlash(relative)) {
				return fmt.Errorf("documentation ignored source escapes original module")
			}
			relative = filepath.ToSlash(relative)
			captured.SourceSHA256[relative], err = discoveryFeatureFileSHA256(filename)
			if err != nil {
				return err
			}
			proof.IgnoredGoFiles = append(proof.IgnoredGoFiles, relative)
		}
		proof.IgnoredGoFiles = uniqueSortedDiscoveryStrings(proof.IgnoredGoFiles)
		proof.Package = captured
		proof.DriverSHA256 = profile.Observed.DriverSHA256
		proof.DirectorySHA256 = documentationDirectorySHA256(plan, proof.Directory)
		proof.LoaderErrorKind = "go/build.NoGoError"
		proof.LoaderError = *pkg.Error
		proof.LoaderError.Err = "build constraints exclude all Go files in module/" + proof.Directory
		proof.Invocation = documentationInvocation(captured.PackagePath, proof.BuildTags)
	}
	return validateDiscoveryDocumentationPackages(plan, profiles, decisions)
}

func verifyDiscoveryDocumentationSources(plan *discoveryOrdinarySelectionPlan, goRoot string) error {
	if plan.DocumentationRules == nil {
		return nil
	}
	version, err := discoveryFeatureFileSHA256(filepath.Join(goRoot, "VERSION"))
	if err != nil || version != plan.DocumentationRules.VersionSHA256 {
		return fmt.Errorf("documentation actual Go VERSION changed: %v", err)
	}
	for file, wanted := range plan.DocumentationRules.SourceSHA256 {
		name := filepath.Join(goRoot, filepath.FromSlash(file))
		if err := discoveryCPPRegularSource(goRoot, name); err != nil {
			return err
		}
		actual, err := discoveryFeatureFileSHA256(name)
		if err != nil || actual != wanted {
			return fmt.Errorf("documentation actual Go source rule changed: %s: %v", file, err)
		}
	}
	return nil
}
