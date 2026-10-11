package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

const discoveryPreCPPRejectionProtocol = "original_first_cpp_control_asm_rejection_v1"
const discoveryPreCPPFirstTokenProtocol = "original_first_asm_token_rejection_v1"

const discoveryPreCPPControlPrefixLimit = 64 << 10

// Like ordinary CPP controls, these compact witnesses are checked against the
// real ZIP by the producer. Offline readers validate their complete source,
// role, invocation and scope relationships under frozen producer provenance;
// a hash/flag alone is not a rejection and does not authenticate source bytes.
type discoveryPreCPPRejection struct {
	Protocol      string                     `json:"protocol"`
	File          string                     `json:"file"`
	SHA256        string                     `json:"sha256"`
	Line          int                        `json:"line"`
	Directive     string                     `json:"directive"`
	FirstToken    string                     `json:"first_token,omitempty"`
	ControlPrefix string                     `json:"control_prefix"`
	ProfileID     string                     `json:"profile_id"`
	Target        string                     `json:"target"`
	BuildTags     []string                   `json:"build_tags,omitempty"`
	DriverSHA256  string                     `json:"driver_sha256"`
	AsmToolSHA256 string                     `json:"asm_tool_sha256"`
	Invocation    []string                   `json:"invocation"`
	Package       gotoolprofile.PackageProof `json:"package"`
	Reason        string                     `json:"reason"`
}

func (proof discoveryPreCPPRejection) scope() discoveryProfileScope {
	return discoveryProfileScope{File: proof.File, Target: proof.Target, ProfileID: proof.ProfileID, Tags: strings.Join(proof.BuildTags, "\x00")}
}

func preCPPUnsupportedDirective(name string) bool {
	if !validDiscoveryCPPMacroName(name) {
		return false
	}
	switch name {
	case "define", "undef", "ifdef", "ifndef", "include", "line", "else", "endif":
		return false
	}
	return true
}

func preCPPInvocation(file, pkg string, defines []string) []string {
	args := []string{"tool", "asm", "-p", pkg}
	for _, define := range defines {
		args = append(args, "-D", define)
	}
	return append(args, "-I", "module/"+path.Dir(file), "-I", "tool/pkg/include", "-o", "discard", "module/"+file)
}

func preCPPExactSourceDiagnostic(proof discoveryPreCPPRejection) bool {
	if captureDiscoverySourceDiagnostic(proof.Reason) == nil {
		return false
	}
	wanted := proof.File + ":" + strconv.Itoa(proof.Line) + ": unexpected token after '#': " + proof.Directive
	if proof.Protocol == discoveryPreCPPFirstTokenProtocol {
		wanted = fmt.Sprintf("%s:%d: expected identifier, found %q", proof.File, proof.Line, proof.FirstToken)
	}
	for _, line := range strings.Split(proof.Reason, "\n") {
		if strings.TrimSpace(line) == wanted {
			return true
		}
	}
	return false
}

// Preserve the actual physical prefix, including the unknown control's whole
// line. Readers can replay unconditionality instead of trusting a producer flag.
// The complete source hash remains bound separately to the original ZIP plan.
func preCPPControlPrefix(data []byte, line int) (string, error) {
	if line <= 0 {
		return "", fmt.Errorf("pre-CPP control lacks its physical source line")
	}
	end := 0
	for current := 1; current <= line; current++ {
		if end >= len(data) {
			return "", fmt.Errorf("pre-CPP control line is absent from original source")
		}
		next := bytes.IndexByte(data[end:], '\n')
		if next < 0 {
			if current != line {
				return "", fmt.Errorf("pre-CPP control line is absent from original source")
			}
			end = len(data)
		} else {
			end += next + 1
		}
		if end > discoveryPreCPPControlPrefixLimit {
			return "", fmt.Errorf("pre-CPP original control prefix exceeds the explicit 64 KiB bound")
		}
	}
	return string(data[:end]), nil
}

func validatePreCPPControlPrefix(proof discoveryPreCPPRejection) error {
	prefix, err := preCPPControlPrefix([]byte(proof.ControlPrefix), proof.Line)
	if err != nil || prefix != proof.ControlPrefix {
		return fmt.Errorf("pre-CPP rejection lacks its exact bounded original control prefix")
	}
	syntaxErr := preCPPSourceSyntax(proof.File, []byte(prefix))
	var unsupported *discoveryUnsupportedCPPError
	if !errors.As(syntaxErr, &unsupported) || unsupported.Line != proof.Line || !preCPPRejectionMatchesToken(proof, unsupported) {
		return fmt.Errorf("pre-CPP original prefix does not prove its first unconditional unknown control")
	}
	return nil
}

func preCPPRejectionMatchesToken(proof discoveryPreCPPRejection, source *discoveryUnsupportedCPPError) bool {
	if source.FirstToken {
		return proof.Protocol == discoveryPreCPPFirstTokenProtocol && proof.Directive == "" &&
			proof.FirstToken != "" && proof.FirstToken == source.Directive
	}
	return proof.Protocol == discoveryPreCPPRejectionProtocol && proof.FirstToken == "" &&
		proof.Directive == source.Directive && preCPPUnsupportedDirective(proof.Directive)
}

func validatePreCPPPackage(plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile, proof discoveryPreCPPRejection) error {
	declared, err := ordinaryProfileDeclaredModule(plan)
	if err != nil {
		return err
	}
	dir := path.Dir(proof.File)
	pkg := proof.Package
	wantedPath := declared
	if dir != "." {
		wantedPath += "/" + dir
	}
	input := ordinaryProfileConsumerInput(plan, profile, declared, "", []string{proof.File}, proof.BuildTags)
	if pkg.PackagePath != wantedPath || len(pkg.CompiledGoFiles) != 0 {
		return fmt.Errorf("pre-CPP source rejection lacks its exact ordinary package role")
	}
	if err := gotoolprofile.ValidatePackageModule(input, pkg); err != nil {
		return err
	}
	if err := gotoolprofile.ValidateOrdinaryAssemblerMacros(pkg.Macros, profile.Observed, pkg.PackagePath); err != nil {
		return err
	}
	sources, _, err := ordinarySelectionBytes(plan)
	if err != nil {
		return err
	}
	ctx, err := discoveryContextForFeatureProfile(profile.Observed)
	if err != nil {
		return err
	}
	ctx.BuildTags = proof.BuildTags
	ctx.OpenFile = func(file string) (io.ReadCloser, error) {
		data, found := sources[filepath.ToSlash(file)]
		if !found {
			return nil, fmt.Errorf("pre-CPP role lacks source header %s", file)
		}
		return io.NopCloser(strings.NewReader(string(data))), nil
	}
	var goFiles, asmFiles []string
	expectedHashes := make(map[string]string)
	for _, source := range plan.Sources {
		if path.Dir(source.File) != dir || strings.HasSuffix(source.File, "_test.go") ||
			strings.HasPrefix(path.Base(source.File), "_") || strings.HasPrefix(path.Base(source.File), ".") ||
			!strings.HasSuffix(source.File, ".go") && !strings.HasSuffix(source.File, ".s") {
			continue
		}
		selected, err := ctx.MatchFile(filepath.FromSlash(dir), path.Base(source.File))
		if err != nil {
			return err
		}
		if !selected {
			continue
		}
		if strings.HasSuffix(source.File, ".go") {
			goFiles = append(goFiles, source.File)
		} else {
			asmFiles = append(asmFiles, source.File)
		}
		expectedHashes[source.File] = source.SHA256
	}
	sort.Strings(goFiles)
	sort.Strings(asmFiles)
	if len(goFiles) == 0 || !reflect.DeepEqual(pkg.GoFiles, goFiles) || !reflect.DeepEqual(pkg.SFiles, asmFiles) ||
		!reflect.DeepEqual(pkg.SourceSHA256, expectedHashes) || !containsTargetFeature(asmFiles, proof.File) {
		return fmt.Errorf("pre-CPP actual package selection differs from original complete source headers")
	}
	return nil
}

func validateDiscoveryPreCPPRejections(plan *discoveryOrdinarySelectionPlan, profiles []discoveryFeatureProfile, eligible map[discoveryProfileScope]bool) (map[discoveryProfileScope]bool, error) {
	rejected := make(map[discoveryProfileScope]bool)
	byProfile := make(map[string]discoveryFeatureProfile)
	for _, profile := range profiles {
		byProfile[profile.ID] = profile
	}
	if len(plan.PreCPPRejections) > 4096 {
		return nil, fmt.Errorf("pre-CPP source rejections exceed the explicit scope bound")
	}
	files := make(map[string]bool)
	for _, proof := range plan.PreCPPRejections {
		key := proof.scope()
		profile, present := byProfile[proof.ProfileID]
		if !present || !eligible[key] || rejected[key] || proof.Line <= 0 ||
			!equalDiscoveryStrings(proof.BuildTags, uniqueSortedDiscoveryStrings(proof.BuildTags)) ||
			proof.Target != profile.Observed.Target || proof.DriverSHA256 != profile.Observed.DriverSHA256 ||
			proof.AsmToolSHA256 != profile.Observed.ToolBinarySHA256["asm"] || !preCPPExactSourceDiagnostic(proof) {
			return nil, fmt.Errorf("pre-CPP rejection lacks exact source/directive/profile/tool/diagnostic scope")
		}
		found := false
		for _, source := range plan.Sources {
			found = found || source.File == proof.File && source.SHA256 == proof.SHA256
		}
		if !found || !discoverySHA256Pattern.MatchString(proof.SHA256) {
			return nil, fmt.Errorf("pre-CPP rejected source is detached from original ZIP selection")
		}
		if err := validatePreCPPControlPrefix(proof); err != nil {
			return nil, err
		}
		if err := validatePreCPPPackage(plan, profile, proof); err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(proof.Invocation, preCPPInvocation(proof.File, proof.Package.PackagePath, proof.Package.Macros.Defines)) {
			return nil, fmt.Errorf("pre-CPP actual assembler invocation differs from original package/profile")
		}
		rejected[key], files[proof.File] = true, true
	}
	// A file without a registered CPP unit must be concretely rejected under
	// every required source/profile/custom-tag configuration, not only baseline.
	for key := range eligible {
		if files[key.File] && !rejected[key] {
			return nil, fmt.Errorf("pre-CPP rejection omitted a selected sibling target/profile/tag scope")
		}
	}
	return rejected, nil
}

func preCPPRemainingScopes(eligible, rejected map[discoveryProfileScope]bool) map[discoveryProfileScope]bool {
	remaining := make(map[discoveryProfileScope]bool)
	for key := range eligible {
		if !rejected[key] {
			remaining[key] = true
		}
	}
	return remaining
}

func verifyDiscoveryPreCPPOriginalSources(plan *discoveryOrdinarySelectionPlan, root string) error {
	for _, proof := range plan.PreCPPRejections {
		filename := filepath.Join(root, filepath.FromSlash(proof.File))
		if err := discoveryCPPRegularSource(root, filename); err != nil {
			return err
		}
		data, err := readDiscoveryChecksumFile(filename, 64<<20)
		if err != nil {
			return err
		}
		syntaxErr := preCPPSourceSyntax(proof.File, data)
		var unsupported *discoveryUnsupportedCPPError
		if !errors.As(syntaxErr, &unsupported) || unsupported.SHA256 != proof.SHA256 ||
			unsupported.File != proof.File || unsupported.Line != proof.Line || !preCPPRejectionMatchesToken(proof, unsupported) {
			return fmt.Errorf("pre-CPP original source/control differs from actual ZIP-bound syntax: %s", proof.File)
		}
		prefix, err := preCPPControlPrefix(data, proof.Line)
		if err != nil || prefix != proof.ControlPrefix {
			return fmt.Errorf("pre-CPP original control prefix changed: %s", proof.File)
		}
	}
	return nil
}

func captureDiscoveryPreCPPRejections(ctx context.Context, plan *discoveryOrdinarySelectionPlan, profiles []discoveryFeatureProfile,
	eligible map[discoveryProfileScope]bool, download moduleDownloadInfo, dir, goRoot, goBinary string, env []string, newFiles ...string) (map[discoveryProfileScope]bool, error) {
	byProfile := make(map[string]discoveryFeatureProfile)
	for _, profile := range profiles {
		byProfile[profile.ID] = profile
	}
	old := make(map[discoveryProfileScope]discoveryPreCPPRejection)
	files := make(map[string]bool)
	for _, proof := range plan.PreCPPRejections {
		old[proof.scope()] = proof
		files[proof.File] = true
	}
	for _, file := range newFiles {
		files[file] = true
	}
	plan.PreCPPRejections = nil
	for _, file := range sortedDiscoverySet(files) {
		filename := filepath.Join(download.Dir, filepath.FromSlash(file))
		data, err := readDiscoveryChecksumFile(filename, 64<<20)
		if err != nil {
			return nil, err
		}
		syntaxErr := preCPPSourceSyntax(file, data)
		var unsupported *discoveryUnsupportedCPPError
		if !errors.As(syntaxErr, &unsupported) {
			return nil, fmt.Errorf("previous CPP source rejection changed or lacks its exact first unknown control: %s", file)
		}
		prefix, err := preCPPControlPrefix(data, unsupported.Line)
		if err != nil {
			return nil, err
		}
		for _, key := range sortedPreCPPScopes(eligible) {
			if key.File != file {
				continue
			}
			if previous, exists := old[key]; exists {
				plan.PreCPPRejections = append(plan.PreCPPRejections, previous)
				continue
			}
			profile := byProfile[key.ProfileID]
			proof := discoveryPreCPPRejection{Protocol: discoveryPreCPPRejectionProtocol, File: file,
				SHA256: unsupported.SHA256, Line: unsupported.Line, Directive: unsupported.Directive,
				ControlPrefix: prefix,
				ProfileID:     key.ProfileID, Target: key.Target, DriverSHA256: profile.Observed.DriverSHA256,
				AsmToolSHA256: profile.Observed.ToolBinarySHA256["asm"]}
			if unsupported.FirstToken {
				proof.Protocol = discoveryPreCPPFirstTokenProtocol
				proof.FirstToken, proof.Directive = unsupported.Directive, ""
			}
			if key.Tags != "" {
				proof.BuildTags = strings.Split(key.Tags, "\x00")
			}
			pkg, err := capturePreCPPPackage(ctx, plan, profile, dir, env, proof)
			if err != nil {
				return nil, err
			}
			proof.Package = pkg
			parts := strings.Split(key.Target, "/")
			commandProfile := &discoveryAsmCommandProfile{Context: ctx, Observed: profile.Observed,
				GoBinary: goBinary, GoRoot: goRoot, PackagePath: pkg.PackagePath, Environment: env}
			probe, err := probeAssemblySourceForTarget(ctx, filename, parts[0], parts[1], goRoot, commandProfile)
			if err != nil {
				return nil, err
			}
			proof.Reason = strings.ReplaceAll(probe.reason, filename, file)
			if !probe.conclusive || probe.accepted || !preCPPExactSourceDiagnostic(proof) {
				return nil, syntaxErr // Do not reinterpret accepted/inconclusive source or unrelated asm failure.
			}
			proof.Invocation = preCPPInvocation(file, pkg.PackagePath, pkg.Macros.Defines)
			plan.PreCPPRejections = append(plan.PreCPPRejections, proof)
		}
	}
	return validateDiscoveryPreCPPRejections(plan, profiles, eligible)
}

func sortedPreCPPScopes(scopes map[discoveryProfileScope]bool) []discoveryProfileScope {
	var sorted []discoveryProfileScope
	for key := range scopes {
		sorted = append(sorted, key)
	}
	sort.Slice(sorted, func(i, j int) bool {
		left, right := sorted[i], sorted[j]
		if left.File != right.File {
			return left.File < right.File
		}
		if left.Target != right.Target {
			return left.Target < right.Target
		}
		if left.ProfileID != right.ProfileID {
			return left.ProfileID < right.ProfileID
		}
		return left.Tags < right.Tags
	})
	return sorted
}

func capturePreCPPPackage(ctx context.Context, plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile,
	dir string, env []string, rejection discoveryPreCPPRejection) (gotoolprofile.PackageProof, error) {
	proof, _, err := captureRejectedOrdinaryPackage(ctx, plan, profile, dir, env, rejection)
	return proof, err
}

// Ordinary loader and pre-CPP rejections share the same actual Go selection,
// authenticated source-module role and complete Go/assembly source binding.
// Extra loader fields are retained separately, never inferred from stderr.
type discoveryRejectedPackage struct {
	ImportPath, Dir, Name             string
	GoFiles, SFiles, FFiles           []string
	IgnoredGoFiles                    []string
	TestGoFiles, XTestGoFiles         []string
	InvalidGoFiles                    []string
	CgoFiles, SwigFiles, SwigCXXFiles []string
	Error                             *discoveryRejectedPackageError
	DepsErrors                        []discoveryRejectedPackageError
	Module                            *discoveryRejectedModule
	selectionStderr                   string
}

type discoveryRejectedPackageError struct {
	ImportStack []string
	Pos, Err    string
}

type discoveryRejectedModule struct {
	Path, Version, Dir, GoMod, Sum string
	Main                           bool
	Replace                        *struct{ Path, Version, GoMod, Sum string }
}

func captureRejectedOrdinaryPackage(ctx context.Context, plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile,
	dir string, env []string, rejection discoveryPreCPPRejection) (gotoolprofile.PackageProof, discoveryRejectedPackage, error) {
	proof, pkg, err := captureRejectedPackageMetadata(ctx, plan, profile, dir, env, rejection)
	if err != nil {
		return proof, pkg, err
	}
	return proof, pkg, validatePreCPPPackage(plan, profile, discoveryPreCPPRejection{File: rejection.File, BuildTags: rejection.BuildTags, Package: proof})
}

// Capture actual module/driver metadata without assigning an ordinary-package
// role. Each role-specific consumer must validate the complete selection.
func captureRejectedPackageMetadata(ctx context.Context, plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile,
	dir string, env []string, rejection discoveryPreCPPRejection) (gotoolprofile.PackageProof, discoveryRejectedPackage, error) {
	var proof gotoolprofile.PackageProof
	var pkg discoveryRejectedPackage
	declared, err := ordinaryProfileDeclaredModule(plan)
	if err != nil {
		return proof, pkg, err
	}
	candidate := discoveryCandidate{Module: plan.Module, Version: plan.Version, AsmFiles: []string{rejection.File}}
	execution, err := makeDiscoveryExecutionPlan(candidate, declared)
	if err != nil {
		return proof, pkg, err
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(execution.GoMod), 0600); err != nil {
		return proof, pkg, err
	}
	args := []string{"list", "-e", "-json", "-mod=mod"}
	if len(rejection.BuildTags) != 0 {
		args = append(args, "-tags="+strings.Join(rejection.BuildTags, ","))
	}
	args = append(args, execution.Patterns...)
	selectionEnv := replaceEnv(ordinaryProfileEnvironment(env, profile.Observed), map[string]string{"CGO_ENABLED": "0"})
	output, stderr, err := runDiscoveryMachineCommand(ctx, dir, selectionEnv, "go", args...)
	if err != nil || isDiscoveryGoBuildInfrastructureFailure(string(stderr)) {
		return proof, pkg, fmt.Errorf("actual rejected-package source selection: %v: %s", err, stderr)
	}
	if err := json.Unmarshal(output, &pkg); err != nil || pkg.Module == nil || pkg.Module.Main ||
		len(pkg.DepsErrors) != 0 || pkg.Error != nil && isDiscoveryGoBuildInfrastructureFailure(pkg.Error.Err) {
		return proof, pkg, fmt.Errorf("actual rejected-package role is missing or contains tool/dependency failure: %v", err)
	}
	pkg.selectionStderr = string(stderr)
	proof = gotoolprofile.PackageProof{PackagePath: pkg.ImportPath, ModulePath: pkg.Module.Path, ModuleVersion: pkg.Module.Version,
		SourceModule: pkg.Module.Path, SourceVersion: pkg.Module.Version, SourceRole: "module", SourceSHA256: make(map[string]string)}
	sum, goMod := pkg.Module.Sum, pkg.Module.GoMod
	if replacement := pkg.Module.Replace; replacement != nil {
		proof.SourceModule, proof.SourceVersion, proof.SourceRole = replacement.Path, replacement.Version, "version_replace"
		sum, goMod = replacement.Sum, replacement.GoMod
	}
	if sum != plan.ModuleSum {
		return proof, pkg, fmt.Errorf("actual rejected-package source differs from original ZIP h1")
	}
	if metadata := plan.ProxyGoMod; metadata != nil {
		actual, err := discoveryFeatureFileSHA256(goMod)
		if err != nil || actual != metadata.SHA256 {
			return proof, pkg, fmt.Errorf("actual rejected-package used different authenticated proxy metadata")
		}
		proof.GoModOrigin, proof.GoModSHA256, proof.GoModSum = metadata.Protocol, metadata.SHA256, metadata.GoModSum
	}
	for _, files := range [][]string{pkg.GoFiles, pkg.SFiles} {
		for _, file := range files {
			filename := filepath.Join(pkg.Dir, file)
			if err := discoveryCPPRegularSource(pkg.Module.Dir, filename); err != nil {
				return proof, pkg, err
			}
			relative, err := filepath.Rel(pkg.Module.Dir, filename)
			relative = filepath.ToSlash(relative)
			if err != nil || !ordinarySelectionLocalPath(relative) {
				return proof, pkg, fmt.Errorf("actual rejected-package selected an escaping source")
			}
			proof.SourceSHA256[relative], err = discoveryFeatureFileSHA256(filename)
			if err != nil {
				return proof, pkg, err
			}
			if strings.HasSuffix(relative, ".go") {
				proof.GoFiles = append(proof.GoFiles, relative)
			} else {
				proof.SFiles = append(proof.SFiles, relative)
			}
		}
	}
	sort.Strings(proof.GoFiles)
	sort.Strings(proof.SFiles)
	rootOutput, _, err := runDiscoveryMachineCommand(ctx, dir, ordinaryProfileEnvironment(env, profile.Observed), "go", "env", "GOROOT")
	if err != nil {
		return proof, pkg, err
	}
	proof.Macros, err = captureDiscoveryAssemblerMacros(strings.TrimSpace(string(rootOutput)), profile.Observed, proof.PackagePath)
	if err != nil {
		return proof, pkg, err
	}
	return proof, pkg, nil
}
