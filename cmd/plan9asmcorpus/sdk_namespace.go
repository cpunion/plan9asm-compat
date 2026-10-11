package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/mod/module"
)

const discoverySDKNamespaceProtocol = "original_module_sdk_namespace_rejection_v1"
const discoverySDKNamespaceRulesProtocol = "registered_go1271_module_sdk_namespace_sources_v1"
const discoverySourceNotApplicableSDKNamespace = "go_module_sdk_namespace_rejected_package_target"

// This is a refusal before package loading, not a manufactured PackageProof.
// The two directories have distinct roles: original ZIP module and stock SDK.
// Physical paths are checked before recording their portable role names.
type discoverySDKNamespaceRejection struct {
	Protocol             string                         `json:"protocol"`
	Directory            string                         `json:"directory"`
	DirectorySHA256      string                         `json:"directory_sha256"`
	ProfileID            string                         `json:"profile_id"`
	Target               string                         `json:"target"`
	BuildTags            []string                       `json:"build_tags,omitempty"`
	AsmFiles             []string                       `json:"asm_files"`
	PackagePath          string                         `json:"package_path"`
	SDKDirectory         ordinarySelectionDirectory     `json:"sdk_directory"`
	CGOEnabled           string                         `json:"cgo_enabled"`
	Invocation           []string                       `json:"invocation"`
	ModuleInvocation     []string                       `json:"module_invocation"`
	ExecutionGoModSHA256 string                         `json:"execution_go_mod_sha256"`
	ModuleStdoutSHA256   string                         `json:"portable_module_stdout_sha256"`
	ModuleStdout         string                         `json:"portable_module_stdout"`
	ExitCode             int                            `json:"exit_code"`
	Stdout               string                         `json:"stdout"`
	Stderr               string                         `json:"portable_stderr"`
	StderrSHA256         string                         `json:"portable_stderr_sha256"`
	DriverSHA256         string                         `json:"driver_sha256"`
	Macros               *gotoolprofile.AssemblerMacros `json:"assembler_macros"`
	Rules                discoveryGoLoaderRules         `json:"go_loader_rules"`
}

func sdkNamespaceDiagnostic(pkg, module, version, moduleDir, sdkDir string) string {
	return fmt.Sprintf("ambiguous import: found package %s in multiple modules:\n\t%s %s (%s)\n\t (%s)\n", pkg, module, version, moduleDir, sdkDir)
}

func validateSDKNamespaceCommand(pkg, module, version, moduleDir, sdkDir string, code int, stdout, stderr string) error {
	if code != 1 || stdout != "" || stderr != sdkNamespaceDiagnostic(pkg, module, version, moduleDir, sdkDir) ||
		isDiscoveryGoBuildInfrastructureFailure(stderr) {
		return fmt.Errorf("SDK namespace rejection lacks the complete unique two-root diagnostic/exit")
	}
	return nil
}

func isPotentialSDKNamespaceFailure(failure error) bool {
	var captured *discoveryCapturedCommandError
	return errors.As(failure, &captured) && strings.HasPrefix(captured.output, "ambiguous import: found package ")
}

var discoverySDKNamespaceRuleSources = func() map[string]string {
	m := make(map[string]string)
	for file, hash := range discoveryMixedPackageRuleSources {
		m[file] = hash
	}
	m["src/cmd/go/internal/modload/import.go"] = "2d714ab34ae05550efe5d983dfde6371dfd608e0396f0efca1d8bdc3449107c8"
	m["src/cmd/go/internal/modload/init.go"] = "5040e805a75a74d54efd77dec873d7658e70a4ef1798cb174a7fffdc723f1382"
	m["src/cmd/go/internal/modload/build.go"] = "4f31ecbeceae4a50b0a56ee989d00ce64af449774edc1160c4dcaa3717da5c6b"
	m["src/cmd/go/internal/search/search.go"] = "ff88e61e99ed982a207beb43e531437c59652051091c8dc295719b9b94a0adea"
	m["src/internal/goroot/gc.go"] = "142bc996759447359b7bfdc3b9a35c8307d3274f009179014a2be59761030f20"
	m["src/cmd/go/internal/modinfo/info.go"] = "00f9f50ed29686734903d96c70a3da381c0aa4da607377b8aca143a5718b4aec"
	return m
}()

func validateSDKNamespaceRules(rules discoveryGoLoaderRules, observed *discoveryTargetFeatures) error {
	if observed == nil || rules.Protocol != discoverySDKNamespaceRulesProtocol || rules.GoVersion != "go1.27.1" || rules.GoVersion != observed.GoVersion ||
		rules.VersionSHA256 != observed.ToolSourceSHA256["VERSION"] || !discoverySHA256Pattern.MatchString(rules.VersionSHA256) ||
		!reflect.DeepEqual(rules.SourceSHA256, discoverySDKNamespaceRuleSources) {
		return fmt.Errorf("SDK namespace rejection lacks the registered complete Go loader rules")
	}
	return nil
}

// IsGoDir/IsStandardPackage look for a .go member before target filtering.
// Restrict this certificate to regular members: unknown symlink roles fail.
func validateSDKNamespaceDirectory(directory ordinarySelectionDirectory) error {
	if directory.Directory == "" || path.Clean(directory.Directory) != directory.Directory ||
		strings.HasPrefix(directory.Directory, "/") || strings.Contains(directory.Directory, "\\") ||
		strings.HasPrefix(directory.Directory, "../") || len(directory.Entries) == 0 || len(directory.Entries) > 4096 {
		return fmt.Errorf("SDK namespace directory lacks a bounded canonical membership")
	}
	previous, hasGo := "", false
	for _, entry := range directory.Entries {
		if entry.Name == "" || entry.Name == "." || entry.Name == ".." || path.Base(entry.Name) != entry.Name ||
			strings.Contains(entry.Name, "\\") || entry.Name <= previous ||
			(entry.Kind != "file" && entry.Kind != "directory") ||
			(entry.Kind == "file" && !discoverySHA256Pattern.MatchString(entry.SHA256)) ||
			(entry.Kind == "directory" && entry.SHA256 != "") {
			return fmt.Errorf("SDK namespace directory has unknown, duplicate or unbound members")
		}
		previous = entry.Name
		hasGo = hasGo || entry.Kind == "file" && strings.HasSuffix(entry.Name, ".go")
	}
	if !hasGo {
		return fmt.Errorf("SDK namespace directory has no original Go member")
	}
	return nil
}

func captureSDKNamespaceDirectory(root, directory string) (ordinarySelectionDirectory, error) {
	result := ordinarySelectionDirectory{Directory: directory}
	if !strings.HasPrefix(directory, "src/") || path.Clean(directory) != directory || strings.Contains(directory, "\\") {
		return result, fmt.Errorf("SDK namespace directory escapes its exact source role")
	}
	full := filepath.Join(root, filepath.FromSlash(directory))
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return result, err
	}
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil || resolved != filepath.Join(resolvedRoot, filepath.FromSlash(directory)) {
		return result, fmt.Errorf("SDK namespace directory has an unmodeled redirect: %v", err)
	}
	info, err := os.Lstat(full)
	if err != nil || !info.IsDir() {
		return result, fmt.Errorf("SDK namespace origin is not a directory: %v", err)
	}
	entries, err := os.ReadDir(full)
	if err != nil || len(entries) > 4096 {
		return result, fmt.Errorf("read bounded SDK namespace directory: %v", err)
	}
	var bytes int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return result, err
		}
		member := ordinarySelectionEntry{Name: entry.Name()}
		switch {
		case info.IsDir():
			member.Kind = "directory"
		case info.Mode().IsRegular():
			bytes += info.Size()
			if bytes > 64<<20 {
				return result, fmt.Errorf("SDK namespace package exceeds the explicit byte bound")
			}
			member.Kind = "file"
			member.SHA256, err = discoveryFeatureFileSHA256(filepath.Join(full, entry.Name()))
			if err != nil {
				return result, err
			}
		default:
			return result, fmt.Errorf("SDK namespace package has an unmodeled member: %s", entry.Name())
		}
		result.Entries = append(result.Entries, member)
	}
	return result, validateSDKNamespaceDirectory(result)
}

func sdkNamespaceExecution(plan *discoveryOrdinarySelectionPlan, directory string) (discoveryExecutionPlan, string, error) {
	if plan == nil {
		return discoveryExecutionPlan{}, "", fmt.Errorf("SDK namespace proof lacks its original source plan")
	}
	declared, err := ordinaryProfileDeclaredModule(plan)
	if err != nil {
		return discoveryExecutionPlan{}, "", err
	}
	// This class is only a standard import prefix, not vendor/local/multi-module
	// ambiguity. The ZIP go.mod must itself establish the declared module.
	first := strings.Split(declared, "/")[0]
	if first == "" || strings.Contains(first, ".") {
		return discoveryExecutionPlan{}, "", fmt.Errorf("module does not own a standard import prefix")
	}
	found := false
	for _, source := range plan.Sources {
		if source.File == "go.mod" {
			module, err := parseDeclaredModulePath([]byte(source.Header))
			if err == nil && module == declared {
				found = true
			}
		}
	}
	if !found {
		return discoveryExecutionPlan{}, "", fmt.Errorf("SDK collision lacks an original ZIP module declaration")
	}
	var original ordinarySelectionDirectory
	for _, dir := range plan.Directories {
		if dir.Directory == directory {
			original = dir
		}
	}
	if err := validateSDKNamespaceDirectory(original); err != nil {
		return discoveryExecutionPlan{}, "", err
	}
	execution, err := makeDiscoveryExecutionPlan(discoveryCandidate{Module: plan.Module, Version: plan.Version}, declared)
	if err != nil {
		return execution, "", err
	}
	pkg := declared
	if directory != "." {
		pkg += "/" + directory
	}
	return execution, pkg, nil
}

func validateSDKNamespaceRejection(plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile, proof discoverySDKNamespaceRejection) error {
	if profile.Observed == nil {
		return fmt.Errorf("SDK namespace proof lacks its actual target observation")
	}
	execution, pkg, err := sdkNamespaceExecution(plan, proof.Directory)
	if err != nil {
		return err
	}
	if proof.Protocol != discoverySDKNamespaceProtocol || proof.CGOEnabled != "0" || proof.ProfileID != profile.ID ||
		proof.Target != profile.Observed.Target || proof.DriverSHA256 != profile.Observed.DriverSHA256 ||
		proof.DirectorySHA256 == "" || proof.DirectorySHA256 != fortranDirectorySHA256(plan, proof.Directory) ||
		proof.PackagePath != pkg || proof.SDKDirectory.Directory != "src/"+pkg ||
		proof.ExecutionGoModSHA256 != discoveryFeatureBytesSHA256([]byte(execution.GoMod)) ||
		proof.ModuleStdoutSHA256 != discoveryFeatureBytesSHA256([]byte(proof.ModuleStdout)) ||
		proof.StderrSHA256 != discoveryFeatureBytesSHA256([]byte(proof.Stderr)) ||
		!equalDiscoveryStrings(proof.BuildTags, uniqueSortedDiscoveryStrings(proof.BuildTags)) || len(proof.AsmFiles) == 0 ||
		!equalDiscoveryStrings(proof.AsmFiles, uniqueSortedDiscoveryStrings(proof.AsmFiles)) ||
		!reflect.DeepEqual(proof.Invocation, fortranLoaderInvocation(pkg, proof.BuildTags)) ||
		!reflect.DeepEqual(proof.ModuleInvocation, []string{"list", "-m", "-json", "-mod=mod", execution.ModulePath}) {
		return fmt.Errorf("SDK namespace proof lacks exact source/module/package/profile/command bindings")
	}
	for _, file := range proof.AsmFiles {
		if path.Dir(file) != proof.Directory {
			return fmt.Errorf("SDK namespace proof claims a foreign package")
		}
	}
	if err := validateSDKNamespaceDirectory(proof.SDKDirectory); err != nil {
		return err
	}
	if err := validateSDKNamespaceRules(proof.Rules, profile.Observed); err != nil {
		return err
	}
	goMod, err := sdkNamespaceGoModPath("module-cache", plan.Module, plan.Version)
	if err != nil {
		return err
	}
	if _, err := validateSDKNamespaceModule(plan, execution, proof.ModuleStdout, "module", filepath.ToSlash(goMod)); err != nil {
		return err
	}
	if err := gotoolprofile.ValidateOrdinaryAssemblerMacros(proof.Macros, profile.Observed, pkg); err != nil {
		return err
	}
	if err := validateRejectedPackageCPPBindings(plan, proof.AsmFiles, proof.Macros.Defines); err != nil {
		return err
	}
	return validateSDKNamespaceCommand(pkg, execution.ModulePath, plan.Version, path.Join("module", proof.Directory),
		path.Join("tool", proof.SDKDirectory.Directory), proof.ExitCode, proof.Stdout, proof.Stderr)
}

// Registered list.go/modload/build.go select this ModulePublic subset for our
// exact `list -m -json -mod=mod <selected-module>` command: no version query,
// -u, -versions, -retracted, -reuse or provenance request. Query/Versions,
// Update/Retracted/Deprecated, Origin/Reuse and load Error are not successful
// outcomes of that command. Unknown fields therefore fail, not source N/A.
// Keep field order and omission identical to modinfo/info.go's full type.
type sdkNamespaceModule struct {
	Path      string              `json:",omitempty"`
	Version   string              `json:",omitempty"`
	Replace   *sdkNamespaceModule `json:",omitempty"`
	Time      *time.Time          `json:",omitempty"`
	Main      bool                `json:",omitempty"`
	Indirect  bool                `json:",omitempty"`
	Dir       string              `json:",omitempty"`
	GoMod     string              `json:",omitempty"`
	GoVersion string              `json:",omitempty"`
	Sum       string              `json:",omitempty"`
	GoModSum  string              `json:",omitempty"`
}

func sdkNamespaceGoModPath(cache, modulePath, version string) (string, error) {
	escapedModule, err := module.EscapePath(modulePath)
	if err != nil {
		return "", err
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, "cache", "download", filepath.FromSlash(escapedModule), "@v", escapedVersion+".mod"), nil
}

func validateSDKNamespaceModule(plan *discoveryOrdinarySelectionPlan, execution discoveryExecutionPlan, stdout, root, goMod string) (sdkNamespaceModule, error) {
	var selected sdkNamespaceModule
	if plan == nil {
		return selected, fmt.Errorf("SDK namespace module query lacks its original source plan")
	}
	if len(stdout) == 0 || len(stdout) > 64<<10 {
		return selected, fmt.Errorf("SDK namespace module query is missing or unbounded")
	}
	decoder := json.NewDecoder(strings.NewReader(stdout))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&selected); err != nil {
		return selected, fmt.Errorf("decode SDK namespace selected module: %w", err)
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return selected, fmt.Errorf("SDK namespace selected module has trailing data: %v", err)
	}
	// Stock cmd/go uses this complete formatter and member order. Comparing
	// it also rejects duplicate/case-aliased fields and explicit nulls that
	// encoding/json would otherwise silently normalize or overwrite.
	canonical, err := json.MarshalIndent(selected, "", "\t")
	if err != nil || stdout != string(canonical)+"\n" {
		return selected, fmt.Errorf("SDK namespace module query is not the complete stock Go JSON record: %v", err)
	}
	if selected.Main || selected.Indirect || selected.Path != execution.ModulePath || selected.Version != plan.Version {
		return selected, fmt.Errorf("SDK namespace selected module identity differs")
	}
	physical := &selected
	if execution.ModulePath != plan.Module {
		if selected.Replace == nil || selected.Replace.Path != plan.Module || selected.Replace.Version != plan.Version || selected.Replace.Replace != nil || selected.Replace.Main || selected.Replace.Indirect {
			return selected, fmt.Errorf("SDK namespace replacement differs from the original candidate")
		}
		physical = selected.Replace
	} else if selected.Replace != nil {
		return selected, fmt.Errorf("SDK namespace has an unmodeled replacement")
	}
	if selected.Dir != root || physical.Dir != root || selected.GoMod != goMod || physical.GoMod != goMod || physical.Sum != plan.ModuleSum {
		return selected, fmt.Errorf("SDK namespace selected module is not the authenticated original root/checksum")
	}
	return selected, nil
}

func captureSDKNamespaceRejection(ctx context.Context, plan *discoveryOrdinarySelectionPlan, profile discoveryFeatureProfile,
	root, workDir, goRoot string, env []string, group discoveryPackageGroup, tags []string, originalErr error) (discoverySDKNamespaceRejection, error) {
	var proof discoverySDKNamespaceRejection
	var captured *discoveryCapturedCommandError
	var originalExit *exec.ExitError
	if plan == nil || profile.Observed == nil || len(group.AsmFiles) == 0 || !errors.As(originalErr, &captured) || !errors.As(originalErr, &originalExit) ||
		originalExit.ExitCode() != 1 || isDiscoveryInfrastructureFailure(originalErr) {
		return proof, fmt.Errorf("SDK namespace proof requires the complete actual original export failure")
	}
	proof = discoverySDKNamespaceRejection{Protocol: discoverySDKNamespaceProtocol, Directory: path.Dir(group.AsmFiles[0]),
		ProfileID: profile.ID, Target: profile.Observed.Target, BuildTags: append([]string(nil), tags...),
		AsmFiles: append([]string(nil), group.AsmFiles...), CGOEnabled: "0", DriverSHA256: profile.Observed.DriverSHA256}
	execution, pkg, err := sdkNamespaceExecution(plan, proof.Directory)
	if err != nil || pkg != group.Pattern {
		return proof, fmt.Errorf("SDK namespace original package binding failed: %v", err)
	}
	proof.DirectorySHA256, proof.PackagePath = fortranDirectorySHA256(plan, proof.Directory), pkg
	proof.Invocation = fortranLoaderInvocation(pkg, tags)
	physicalWorkDir, err := filepath.EvalSymlinks(workDir)
	if err != nil || filepath.Clean(captured.directory) != filepath.Clean(physicalWorkDir) ||
		captured.command != strings.Join(append([]string{"go"}, proof.Invocation...), " ") {
		return proof, fmt.Errorf("SDK namespace original command/directory differs: %v", err)
	}
	proof.ModuleInvocation = []string{"list", "-m", "-json", "-mod=mod", execution.ModulePath}
	proof.ExecutionGoModSHA256 = discoveryFeatureBytesSHA256([]byte(execution.GoMod))
	selectionEnv := replaceEnv(ordinaryProfileEnvironment(env, profile.Observed), map[string]string{"CGO_ENABLED": "0"})
	// Bind source roots, the generated exact require/replace and actual selected
	// module both before and after the independent unchanged export command.
	observe := func() (string, error) {
		data, err := os.ReadFile(filepath.Join(workDir, "go.mod"))
		if err != nil || string(data) != execution.GoMod {
			return "", fmt.Errorf("SDK namespace execution module changed: %v", err)
		}
		out, stderr, err := runDiscoveryMachineCommand(ctx, workDir, selectionEnv, "go", "env", "-json", "GOROOT", "CGO_ENABLED", "GOMODCACHE")
		var actual map[string]string
		if err != nil || json.Unmarshal(out, &actual) != nil || len(actual) != 3 || actual["GOROOT"] != goRoot || actual["CGO_ENABLED"] != "0" || !filepath.IsAbs(actual["GOMODCACHE"]) || len(stderr) != 0 {
			return "", fmt.Errorf("SDK namespace actual tool root/CGO0 differs: %v", err)
		}
		wantedGoMod, err := sdkNamespaceGoModPath(actual["GOMODCACHE"], plan.Module, plan.Version)
		if err != nil {
			return "", err
		}
		if err := discoveryCPPRegularSource(actual["GOMODCACHE"], wantedGoMod); err != nil {
			return "", err
		}
		modBytes, err := os.ReadFile(wantedGoMod)
		if err != nil {
			return "", err
		}
		wantedModSHA := ""
		for _, source := range plan.Sources {
			if source.File == "go.mod" {
				wantedModSHA = source.SHA256
			}
		}
		if discoveryFeatureBytesSHA256(modBytes) != wantedModSHA {
			return "", fmt.Errorf("SDK namespace proxy metadata differs from original ZIP go.mod")
		}
		out, stderr, err = runDiscoveryMachineCommand(ctx, workDir, selectionEnv, "go", proof.ModuleInvocation...)
		if err != nil || len(stderr) != 0 {
			return "", fmt.Errorf("SDK namespace actual module query failed: %v", err)
		}
		if _, err := validateSDKNamespaceModule(plan, execution, string(out), root, wantedGoMod); err != nil {
			return "", err
		}
		portableGoMod, err := sdkNamespaceGoModPath("module-cache", plan.Module, plan.Version)
		if err != nil {
			return "", err
		}
		// Preserve complete JSON formatting and all modeled fields. Replace only
		// the two exact, already-validated JSON path values with portable roles.
		portable := string(out)
		for physical, role := range map[string]string{root: "module", wantedGoMod: filepath.ToSlash(portableGoMod)} {
			from, _ := json.Marshal(physical)
			to, _ := json.Marshal(role)
			portable = strings.ReplaceAll(portable, string(from), string(to))
		}
		return portable, nil
	}
	proof.ModuleStdout, err = observe()
	if err != nil {
		return proof, err
	}
	proof.SDKDirectory, err = captureSDKNamespaceDirectory(goRoot, "src/"+pkg)
	if err != nil {
		return proof, err
	}
	proof.Rules = discoveryGoLoaderRules{Protocol: discoverySDKNamespaceRulesProtocol, GoVersion: profile.Observed.GoVersion,
		VersionSHA256: profile.Observed.ToolSourceSHA256["VERSION"], SourceSHA256: make(map[string]string)}
	for name := range discoverySDKNamespaceRuleSources {
		proof.Rules.SourceSHA256[name], err = discoveryFeatureFileSHA256(filepath.Join(goRoot, filepath.FromSlash(name)))
		if err != nil {
			return proof, err
		}
	}
	proof.Macros, err = gotoolprofile.CaptureAssemblerMacros(goRoot, profile.Observed, pkg)
	if err != nil {
		return proof, err
	}
	stdout, stderr, failure := runDiscoveryMachineCommand(ctx, workDir, selectionEnv, "go", proof.Invocation...)
	var exit *exec.ExitError
	if !errors.As(failure, &exit) || isDiscoveryInfrastructureFailure(failure) || captured.output != string(stderr) {
		return proof, fmt.Errorf("SDK namespace independent original export changed: %v", failure)
	}
	if err := validateSDKNamespaceCommand(pkg, execution.ModulePath, plan.Version, filepath.Join(root, filepath.FromSlash(proof.Directory)),
		filepath.Join(goRoot, filepath.FromSlash(proof.SDKDirectory.Directory)), exit.ExitCode(), string(stdout), string(stderr)); err != nil {
		return proof, err
	}
	proof.ExitCode, proof.Stdout = exit.ExitCode(), string(stdout)
	proof.Stderr = sdkNamespaceDiagnostic(pkg, execution.ModulePath, plan.Version, path.Join("module", proof.Directory), path.Join("tool", proof.SDKDirectory.Directory))
	// Hash retained portable bytes, not absent private command output. Capture
	// validated the complete physical bytes and their exact root roles above.
	proof.StderrSHA256 = discoveryFeatureBytesSHA256([]byte(proof.Stderr))
	proof.ModuleStdoutSHA256 = discoveryFeatureBytesSHA256([]byte(proof.ModuleStdout))
	after, err := observe()
	if err != nil || after != proof.ModuleStdout {
		return proof, fmt.Errorf("SDK namespace module query changed: %v", err)
	}
	if err := verifyDiscoverySDKNamespaceSources(&discoveryOrdinarySelectionPlan{SDKNamespaceRejections: []discoverySDKNamespaceRejection{proof}}, goRoot); err != nil {
		return proof, err
	}
	return proof, validateSDKNamespaceRejection(plan, profile, proof)
}

func validateDiscoverySDKNamespaceRejections(plan *discoveryOrdinarySelectionPlan, profiles []discoveryFeatureProfile,
	remaining map[discoveryProfileScope]bool) (map[discoveryProfileScope]discoverySDKNamespaceRejection, error) {
	if plan == nil {
		return nil, fmt.Errorf("SDK namespace scopes lack their original source plan")
	}
	if len(plan.SDKNamespaceRejections) > 4096 {
		return nil, fmt.Errorf("SDK namespace exclusions exceed the scope bound")
	}
	byProfile := make(map[string]discoveryFeatureProfile)
	for _, profile := range profiles {
		byProfile[profile.ID] = profile
	}
	rejected := make(map[discoveryProfileScope]discoverySDKNamespaceRejection)
	for _, proof := range plan.SDKNamespaceRejections {
		profile, present := byProfile[proof.ProfileID]
		if !present {
			return nil, fmt.Errorf("SDK namespace proof has an unknown profile")
		}
		if err := validateSDKNamespaceRejection(plan, profile, proof); err != nil {
			return nil, err
		}
		var expected []string
		for key := range remaining {
			if path.Dir(key.File) == proof.Directory && key.Target == proof.Target && key.ProfileID == proof.ProfileID && key.Tags == strings.Join(proof.BuildTags, "\x00") {
				expected = append(expected, key.File)
			}
		}
		if !equalDiscoveryStrings(proof.AsmFiles, uniqueSortedDiscoveryStrings(expected)) {
			return nil, fmt.Errorf("SDK namespace exclusion is not the complete package/profile scope")
		}
		for _, file := range proof.AsmFiles {
			key := discoveryProfileScope{File: file, Target: proof.Target, ProfileID: proof.ProfileID, Tags: strings.Join(proof.BuildTags, "\x00")}
			if _, present := rejected[key]; present {
				return nil, fmt.Errorf("duplicate SDK namespace scope")
			}
			rejected[key] = proof
		}
	}
	return rejected, nil
}

func verifyDiscoverySDKNamespaceSources(plan *discoveryOrdinarySelectionPlan, goRoot string) error {
	if plan == nil {
		return fmt.Errorf("SDK namespace physical guard lacks its original source plan")
	}
	for _, proof := range plan.SDKNamespaceRejections {
		actual, err := captureSDKNamespaceDirectory(goRoot, proof.SDKDirectory.Directory)
		if err != nil || !reflect.DeepEqual(actual, proof.SDKDirectory) {
			return fmt.Errorf("SDK namespace original membership/content changed: %v", err)
		}
		for name, wanted := range proof.Rules.SourceSHA256 {
			actual, err := discoveryFeatureFileSHA256(filepath.Join(goRoot, filepath.FromSlash(name)))
			if err != nil || actual != wanted {
				return fmt.Errorf("SDK namespace original Go rule changed: %s: %v", name, err)
			}
		}
	}
	return nil
}
