package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
)

const ordinarySelectionProtocol = "exact_source_matchfile_v1"

const (
	ordinarySelectionFilename        = "go_filename_target"
	ordinarySelectionIgnoredFilename = "go_ignored_filename"
	ordinarySelectionCgoDisabled     = "go_cgo_disabled"
	ordinarySelectionInvalidPath     = "go_invalid_package_import_path"
)

// A source-selection proof is not a claim that Go rejects an explicitly named
// package. Ignored directories and nested modules are recursive corpus-walk
// boundaries. Constraints and source diagnostics are separate decisions.
type discoveryOrdinarySelectionPlan struct {
	CPPSourceProtocol            string                          `json:"cpp_source_protocol"`
	DocumentationSourceProtocol  string                          `json:"documentation_source_protocol,omitempty"`
	DocumentationRules           *discoveryDocumentationRules    `json:"documentation_rules,omitempty"`
	DocumentationPackages        []discoveryDocumentationPackage `json:"documentation_packages,omitempty"`
	SignatureSourceProtocol      string                          `json:"signature_source_protocol,omitempty"`
	TestDependencySourceProtocol string                          `json:"test_dependency_source_protocol,omitempty"`
	InstrumentationPlan          *discoveryInstrumentationPlan   `json:"instrumentation_plan,omitempty"`
	Protocol                     string                          `json:"protocol"`
	Module                       string                          `json:"module"`
	Version                      string                          `json:"version"`
	ModuleSum                    string                          `json:"module_sum"`
	ZipSHA256                    string                          `json:"zip_sha256"`
	GoVersion                    string                          `json:"go_version"`
	Targets                      []string                        `json:"targets"`
	ReleaseTags                  []string                        `json:"release_tags"`
	ToolTags                     []string                        `json:"tool_tags"`
	TestedAsmFiles               []string                        `json:"tested_asm_files,omitempty"`
	Sources                      []ordinarySelectionSource       `json:"sources"`
	Directories                  []ordinarySelectionDirectory    `json:"directories"`
	Decisions                    []ordinarySelectionDecision     `json:"decisions"`
	CPPInputs                    *discoveryCPPInputs             `json:"cpp_inputs,omitempty"`
	ProfileDecisions             []ordinaryProfileDecision       `json:"profile_decisions,omitempty"`
	ProxyGoMod                   *gotoolprofile.ProxyGoModProof  `json:"proxy_go_mod,omitempty"`
	GeneratedHeaders             []discoveryGeneratedHeaderQuery `json:"generated_headers,omitempty"`
	GeneratedGoSources           map[string]string               `json:"generated_go_sources,omitempty"`
	ordinaryDependencyGuards     []discoveryOrdinaryDependencyGuard
	ordinaryDependencyContext    context.Context
	HeaderPlanning               *discoveryCPPHeaderPlanning       `json:"header_planning,omitempty"`
	PreCPPRejections             []discoveryPreCPPRejection        `json:"pre_cpp_rejections,omitempty"`
	FortranRejections            []discoveryFortranLoaderRejection `json:"fortran_loader_rejections,omitempty"`
	MixedPackageRejections       []discoveryMixedPackageRejection  `json:"mixed_package_rejections,omitempty"`
	SDKNamespaceRejections       []discoverySDKNamespaceRejection  `json:"sdk_namespace_rejections,omitempty"`
	TestDeclarationSources       []ordinarySelectionSource         `json:"test_declaration_go_sources,omitempty"`
	TestDeclarationDirectories   []ordinarySelectionDirectory      `json:"test_declaration_directories,omitempty"`
	TestDeclarationQueries       []discoveryTestDeclarationQuery   `json:"test_declaration_queries,omitempty"`
	proxyGoModPath               string
	instrumentationGoRoot        string
	testDependencyContext        context.Context
	testDependencyModuleCaptures map[*gotoolprofile.TestDependencyProof]map[string]*discoveryTestModuleCapture
	headerPlanningInventory      *discoveryFeatureInventory
	headerPlanningCapture        func(discoveryFeatureProfileRequest, string, []string) (*gotoolprofile.GeneratedHeaderProof, error)
	headerPlanningUsed           map[string]bool
	headerPlanningRecheck        func() error
	headerPlanningQueryStarts    int // Diagnostic count only; never serialized or validated as authority.
}

// Full sources remain in disposable caches or ignored audit artifacts. The
// frozen producer records the exact source SHA and the minimal selection input
// once, not a compressed copy of third-party source in the committed ledger.
type ordinarySelectionSource struct {
	File              string `json:"file"`
	SHA256            string `json:"sha256"`
	Header            string `json:"constraint_header,omitempty"`
	HeaderSHA256      string `json:"selection_header_sha256"`
	PackageDiagnostic string `json:"package_clause_diagnostic,omitempty"`
}

type ordinarySelectionDirectory struct {
	Directory string                   `json:"directory"`
	Entries   []ordinarySelectionEntry `json:"entries"`
}

type ordinarySelectionEntry struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256,omitempty"`
}

type ordinarySelectionDecision struct {
	AsmFiles   []string `json:"asm_files"`
	Targets    []string `json:"targets"`
	BuildTags  []string `json:"build_tags,omitempty"`
	Kind       string   `json:"kind"`
	Boundary   string   `json:"boundary,omitempty"`
	Diagnostic string   `json:"diagnostic"`
}

func captureOrdinarySelectionPlan(candidate discoveryCandidate, moduleDir string, targets []string) (*discoveryOrdinarySelectionPlan, error) {
	plan, err := captureOrdinarySelectionInputs(candidate, moduleDir, targets)
	if err != nil {
		return nil, err
	}
	scope, err := ordinarySelectionTestedAssembly(plan, candidate.AsmFiles)
	if err != nil {
		return nil, err
	}
	decisions, _, err := replayOrdinarySelection(plan, scope)
	if err != nil {
		return nil, err
	}
	plan.Decisions = decisions
	return plan, nil
}

// Capture bytes and directory inventory before selecting profiles. Source
// stability rechecks need only these inputs, not a second host-context replay.
func captureOrdinarySelectionInputs(candidate discoveryCandidate, moduleDir string, targets []string) (*discoveryOrdinarySelectionPlan, error) {
	plan := &discoveryOrdinarySelectionPlan{
		CPPSourceProtocol:            discoveryReplayCPPInputsProtocol,
		DocumentationSourceProtocol:  discoveryDocumentationProtocol,
		SignatureSourceProtocol:      gotoolprofile.SignatureSourceProtocol,
		TestDependencySourceProtocol: gotoolprofile.TestDependencyProtocol,
		Protocol:                     ordinarySelectionScopeProtocol, Module: candidate.Module, Version: candidate.Version,
		GoVersion: runtime.Version(), Targets: uniqueSortedDiscoveryStrings(targets),
		ReleaseTags: append([]string(nil), build.Default.ReleaseTags...),
		ToolTags:    append([]string(nil), build.Default.ToolTags...),
	}
	dirs, files, packageDirs := make(map[string]bool), make(map[string]bool), make(map[string]bool)
	for _, file := range candidate.AsmFiles {
		if !ordinarySelectionLocalPath(file) || !strings.HasSuffix(file, ".s") {
			return nil, fmt.Errorf("invalid ordinary selection assembly path %q", file)
		}
		files[file] = true
		packageDirs[path.Dir(file)] = true
		for dir := path.Dir(file); ; dir = path.Dir(dir) {
			dirs[dir] = true
			if dir == "." {
				break
			}
		}
	}
	for _, dir := range sortedDiscoverySet(dirs) {
		entries, err := os.ReadDir(filepath.Join(moduleDir, filepath.FromSlash(dir)))
		if err != nil {
			return nil, fmt.Errorf("capture ordinary package directory %s: %w", dir, err)
		}
		captured := ordinarySelectionDirectory{Directory: dir, Entries: []ordinarySelectionEntry{}}
		for _, entry := range entries {
			kind := "file"
			if entry.IsDir() {
				kind = "directory"
			} else if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
				return nil, fmt.Errorf("ordinary source selection refuses non-regular entry %s", path.Join(dir, entry.Name()))
			}
			witness := ordinarySelectionEntry{Name: entry.Name(), Kind: kind}
			if kind == "file" {
				witness.SHA256, err = discoveryBinaryFingerprint(filepath.Join(moduleDir, filepath.FromSlash(dir), entry.Name()))
				if err != nil {
					return nil, err
				}
			}
			captured.Entries = append(captured.Entries, witness)
			if kind == "file" && (packageDirs[dir] &&
				(strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), ".s")) || entry.Name() == "go.mod") {
				files[path.Join(dir, entry.Name())] = true
			}
		}
		plan.Directories = append(plan.Directories, captured)
	}
	for _, file := range sortedDiscoverySet(files) {
		data, err := os.ReadFile(filepath.Join(moduleDir, filepath.FromSlash(file)))
		if err != nil {
			return nil, fmt.Errorf("capture ordinary source %s: %w", file, err)
		}
		input := ordinarySelectionSource{File: file, SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
		if strings.HasSuffix(file, ".go") {
			_, err := parser.ParseFile(token.NewFileSet(), file, data, parser.PackageClauseOnly)
			if err == nil {
				input.Header, err = discoveryGoSelectionHeader(file, data)
				if err != nil {
					return nil, err
				}
			} else {
				// Invalid package clauses fail before declarations. Retain a
				// bounded actual prefix and independently replay that rejection.
				if len(data) > 64<<10 {
					data = data[:64<<10]
				}
				input.Header = string(data)
				_, prefixErr := parser.ParseFile(token.NewFileSet(), file, data, parser.PackageClauseOnly)
				if prefixErr == nil {
					return nil, fmt.Errorf("invalid Go source requires more than the bounded package-clause witness: %s", file)
				}
				input.PackageDiagnostic = prefixErr.Error()
			}
		} else if strings.HasSuffix(file, ".s") {
			captured, err := nativeLayoutSourceInputFromBytes(file, data)
			if err != nil {
				return nil, err
			}
			input.Header = captured.Header
		} else if path.Base(file) == "go.mod" {
			if len(data) > 1<<20 {
				return nil, fmt.Errorf("oversized ordinary module-boundary witness: %s", file)
			}
			input.Header = string(data)
		}
		if strings.HasSuffix(file, ".go") || strings.HasSuffix(file, ".s") {
			input.Header = compactOrdinarySelectionHeader(input.Header)
		}
		input.HeaderSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(input.Header)))
		plan.Sources = append(plan.Sources, input)
	}
	scope, err := deriveOrdinaryAssemblyScope(plan, candidate.AsmFiles)
	if err != nil {
		return nil, err
	}
	plan.TestedAsmFiles = scope
	return plan, nil
}

// Keep line/blank/comment structure because legacy +build placement matters,
// while removing unrelated single-line license/documentation payload. Block
// comments remain intact so embedded apparent directives cannot be activated.
func compactOrdinarySelectionHeader(header string) string {
	lines := strings.Split(header, "\n")
	inBlock := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if inBlock {
			if strings.Contains(trimmed, "*/") {
				inBlock = false
			}
			continue
		}
		if strings.HasPrefix(trimmed, "/*") {
			inBlock = !strings.Contains(trimmed, "*/")
			continue
		}
		if strings.HasPrefix(trimmed, "//") && !constraint.IsGoBuild(trimmed) &&
			!constraint.IsPlusBuild(trimmed) && !strings.HasPrefix(trimmed, "//line ") {
			lines[i] = line[:strings.Index(line, "//")] + "//"
		}
	}
	return strings.Join(lines, "\n")
}

func ordinarySelectionLocalPath(file string) bool {
	return filepath.IsLocal(file) && filepath.ToSlash(file) == file && path.Clean(file) == file
}

func verifyOrdinarySelectionUnchanged(plan *discoveryOrdinarySelectionPlan, moduleDir string, candidate discoveryCandidate) error {
	current, err := captureOrdinarySelectionInputs(candidate, moduleDir, plan.Targets)
	if err != nil {
		return err
	}
	before, _ := json.Marshal(struct {
		Sources     []ordinarySelectionSource
		Directories []ordinarySelectionDirectory
	}{plan.Sources, plan.Directories})
	after, _ := json.Marshal(struct {
		Sources     []ordinarySelectionSource
		Directories []ordinarySelectionDirectory
	}{current.Sources, current.Directories})
	if !bytes.Equal(before, after) {
		return fmt.Errorf("ordinary package directory/source digest changed")
	}
	return nil
}

// Bind captured files and complete directory names to the exact downloaded
// module ZIP. Go's extractor may omit legal explicit directory entries. File
// paths establish mandatory directories; empty directory markers are optional.
func verifyOrdinarySelectionZIP(plan *discoveryOrdinarySelectionPlan, zipPath, modulePath, version, claimedSum string) error {
	sum, err := dirhash.HashZip(zipPath, dirhash.Hash1)
	if err != nil {
		return err
	}
	if claimedSum != "" && claimedSum != sum {
		return fmt.Errorf("ordinary selection module h1 differs from downloaded ZIP")
	}
	plan.ModuleSum = sum
	plan.ZipSHA256, err = discoveryBinaryFingerprint(zipPath)
	if err != nil {
		return err
	}
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	prefix := modulePath + "@" + version + "/"
	files := make(map[string]*zip.File)
	dirs := map[string]map[string]string{".": {}}
	optionalDirs := make(map[string]bool)
	for _, file := range reader.File {
		if !strings.HasPrefix(file.Name, prefix) {
			return fmt.Errorf("ordinary ZIP entry lies outside exact module identity")
		}
		relative := strings.TrimSuffix(strings.TrimPrefix(file.Name, prefix), "/")
		if relative == "" {
			continue
		}
		if !ordinarySelectionLocalPath(relative) {
			return fmt.Errorf("ordinary ZIP has an unsafe source path")
		}
		kind := "file"
		if file.FileInfo().IsDir() {
			optionalDirs[relative] = true
			continue
		} else {
			if files[relative] != nil || !file.Mode().IsRegular() {
				return fmt.Errorf("ordinary ZIP has duplicate or non-regular source")
			}
			files[relative] = file
		}
		for name := relative; name != "."; name = path.Dir(name) {
			dir := path.Dir(name)
			if dirs[dir] == nil {
				dirs[dir] = make(map[string]string)
			}
			if previous, exists := dirs[dir][path.Base(name)]; exists && previous != kind {
				return fmt.Errorf("ordinary ZIP directory/file conflict")
			}
			dirs[dir][path.Base(name)] = kind
			kind = "directory"
		}
	}
	for _, captured := range plan.Directories {
		entries := dirs[captured.Directory]
		seen := make(map[string]bool)
		for _, entry := range captured.Entries {
			seen[entry.Name] = true
			if entries[entry.Name] != entry.Kind && !(entry.Kind == "directory" && optionalDirs[path.Join(captured.Directory, entry.Name)]) {
				return fmt.Errorf("ordinary directory entry differs from exact ZIP")
			}
			if entry.Kind == "file" {
				file := files[path.Join(captured.Directory, entry.Name)]
				stream, err := file.Open()
				if err != nil {
					return err
				}
				hash := sha256.New()
				_, readErr := io.Copy(hash, stream)
				closeErr := stream.Close()
				if readErr != nil || closeErr != nil || fmt.Sprintf("%x", hash.Sum(nil)) != entry.SHA256 {
					return fmt.Errorf("ordinary package input differs from exact ZIP: %s", path.Join(captured.Directory, entry.Name))
				}
			}
		}
		for name := range entries {
			if !seen[name] {
				return fmt.Errorf("ordinary captured directory omits exact ZIP entry: %s", path.Join(captured.Directory, name))
			}
		}
	}
	for dir := range optionalDirs {
		if files[dir] != nil {
			return fmt.Errorf("ordinary ZIP entry is both a file and a directory marker")
		}
	}
	for _, input := range plan.Sources {
		file := files[input.File]
		if file == nil {
			return fmt.Errorf("ordinary captured source absent from exact ZIP: %s", input.File)
		}
		stream, err := file.Open()
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(stream)
		closeErr := stream.Close()
		if readErr != nil || closeErr != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != input.SHA256 {
			return fmt.Errorf("ordinary captured source differs from exact ZIP: %s", input.File)
		}
		var originalHeader string
		if strings.HasSuffix(input.File, ".s") || strings.HasSuffix(input.File, ".go") && input.PackageDiagnostic == "" {
			original, err := nativeLayoutSourceInputFromBytes(input.File, data)
			if err != nil {
				return err
			}
			originalHeader = original.Header
		} else if strings.HasSuffix(input.File, ".go") {
			if len(data) > 64<<10 {
				data = data[:64<<10]
			}
			originalHeader = string(data)
		} else if path.Base(input.File) == "go.mod" {
			originalHeader = string(data)
		}
		if strings.HasSuffix(input.File, ".go") || strings.HasSuffix(input.File, ".s") {
			originalHeader = compactOrdinarySelectionHeader(originalHeader)
		}
		if input.Header != originalHeader {
			return fmt.Errorf("ordinary selection header differs from exact ZIP bytes: %s", input.File)
		}
	}
	return nil
}

func ordinarySelectionIgnoredBoundary(dir string) string {
	if dir == "." {
		return ""
	}
	parts := strings.Split(dir, "/")
	for i, part := range parts {
		if part == "testdata" || part == "vendor" || strings.HasPrefix(part, ".") || strings.HasPrefix(part, "_") {
			return strings.Join(parts[:i+1], "/")
		}
	}
	return ""
}

func ordinarySelectionPackagePathError(modulePath, dir string) error {
	if dir != "." {
		modulePath += "/" + dir
	}
	return module.CheckImportPath(modulePath)
}

func ordinarySelectionBytes(plan *discoveryOrdinarySelectionPlan) (map[string][]byte, map[string]map[string]string, error) {
	sources := make(map[string][]byte)
	dirs := make(map[string]map[string]string)
	entryHashes := make(map[string]string)
	for _, dir := range plan.Directories {
		if !ordinarySelectionLocalPath(dir.Directory) || dirs[dir.Directory] != nil {
			return nil, nil, fmt.Errorf("invalid or duplicate ordinary package directory")
		}
		entries := make(map[string]string)
		previous := ""
		for _, entry := range dir.Entries {
			if path.Base(entry.Name) != entry.Name || entry.Name <= previous || entry.Name == "." || entry.Name == ".." ||
				(entry.Kind != "file" && entry.Kind != "directory") {
				return nil, nil, fmt.Errorf("invalid ordinary directory listing")
			}
			if entry.Kind == "file" && !discoverySHA256Pattern.MatchString(entry.SHA256) || entry.Kind == "directory" && entry.SHA256 != "" {
				return nil, nil, fmt.Errorf("ordinary directory entry lacks exact input hash")
			}
			entries[entry.Name], previous = entry.Kind, entry.Name
			if entry.Kind == "file" {
				entryHashes[path.Join(dir.Directory, entry.Name)] = entry.SHA256
			}
		}
		dirs[dir.Directory] = entries
	}
	for _, input := range plan.Sources {
		if !ordinarySelectionLocalPath(input.File) || !discoverySHA256Pattern.MatchString(input.SHA256) ||
			fmt.Sprintf("%x", sha256.Sum256([]byte(input.Header))) != input.HeaderSHA256 || sources[input.File] != nil ||
			dirs[path.Dir(input.File)][path.Base(input.File)] != "file" {
			return nil, nil, fmt.Errorf("invalid ordinary selection source %s", input.File)
		}
		if entryHashes[input.File] != input.SHA256 {
			return nil, nil, fmt.Errorf("ordinary selection source SHA disagrees with directory witness")
		}
		if strings.HasSuffix(input.File, ".go") {
			_, parseErr := parser.ParseFile(token.NewFileSet(), input.File, input.Header, parser.PackageClauseOnly)
			if (parseErr == nil) != (input.PackageDiagnostic == "") ||
				parseErr != nil && parseErr.Error() != input.PackageDiagnostic {
				return nil, nil, fmt.Errorf("ordinary Go package-clause diagnostic differs from captured input")
			}
		} else if input.PackageDiagnostic != "" {
			return nil, nil, fmt.Errorf("non-Go ordinary input carries a package-clause diagnostic")
		}
		sources[input.File] = []byte(input.Header)
	}
	return sources, dirs, nil
}

// Replay only source selection. No compiler, assembler or downloaded Go code
// is executed. Every root and ancestor directory is explicit: the virtual "."
// is a root package, never a dot-prefixed ignored directory.
func replayOrdinarySelection(plan *discoveryOrdinarySelectionPlan, asmFiles []string, actualProfiles ...*discoveryTargetFeatures) ([]ordinarySelectionDecision, map[nativeLayoutPlanKey]bool, error) {
	if plan == nil || (plan.Protocol != ordinarySelectionProtocol && plan.Protocol != ordinarySelectionScopeProtocol) || len(plan.Targets) == 0 ||
		len(plan.ReleaseTags) == 0 || len(asmFiles) == 0 ||
		!equalDiscoveryStrings(plan.Targets, uniqueSortedDiscoveryStrings(plan.Targets)) {
		return nil, nil, fmt.Errorf("missing or invalid ordinary source-selection protocol")
	}
	if len(actualProfiles) > 1 {
		return nil, nil, fmt.Errorf("single-profile ordinary replay requires one actual target environment")
	}
	if len(actualProfiles) == 1 {
		if err := validateDiscoveryTargetFeatures(actualProfiles[0]); err != nil {
			return nil, nil, err
		}
		if len(plan.Targets) != 1 || plan.Targets[0] != actualProfiles[0].Target || plan.GoVersion != actualProfiles[0].GoVersion {
			return nil, nil, fmt.Errorf("ordinary replay profile target/Go version differs from source plan")
		}
	}
	minor, err := discoveryGoMinor(plan.GoVersion)
	if err != nil {
		return nil, nil, err
	}
	var releaseTags []string
	for i := 1; i <= minor; i++ {
		releaseTags = append(releaseTags, fmt.Sprintf("go1.%d", i))
	}
	if !equalDiscoveryStrings(plan.ReleaseTags, releaseTags) {
		return nil, nil, fmt.Errorf("ordinary release tags differ from Go selection version")
	}
	if err := module.CheckImportPath(plan.Module); err != nil {
		return nil, nil, fmt.Errorf("ordinary selection requires a valid module import path: %w", err)
	}
	sources, dirs, err := ordinarySelectionBytes(plan)
	if err != nil {
		return nil, nil, err
	}
	var contexts []build.Context
	for _, target := range plan.Targets {
		if err := validateTarget(target); err != nil {
			return nil, nil, err
		}
		goos, goarch, _ := strings.Cut(target, "/")
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH, ctx.Compiler, ctx.CgoEnabled = goos, goarch, "gc", false
		ctx.BuildTags, ctx.ReleaseTags, ctx.ToolTags = nil, plan.ReleaseTags, plan.ToolTags
		if len(actualProfiles) == 1 {
			ctx, err = discoveryContextForFeatureProfile(actualProfiles[0])
			if err != nil {
				return nil, nil, err
			}
		}
		ctx.OpenFile = func(file string) (io.ReadCloser, error) {
			data, ok := sources[filepath.ToSlash(file)]
			if !ok {
				return nil, fmt.Errorf("uncaptured ordinary selection source %s", file)
			}
			return io.NopCloser(bytes.NewReader(data)), nil
		}
		contexts = append(contexts, ctx)
	}
	usedDirs, usedSources, seenAsm := make(map[string]bool), make(map[string]bool), make(map[string]bool)
	packageDirs := make(map[string]bool)
	for _, file := range asmFiles {
		packageDirs[path.Dir(file)] = true
	}
	eligible := make(map[nativeLayoutPlanKey]bool)
	var decisions []ordinarySelectionDecision
	for _, file := range asmFiles {
		if !ordinarySelectionLocalPath(file) || !strings.HasSuffix(file, ".s") || seenAsm[file] {
			return nil, nil, fmt.Errorf("invalid or duplicate ordinary assembly input")
		}
		seenAsm[file] = true
		if _, ok := sources[file]; !ok {
			return nil, nil, fmt.Errorf("missing ordinary assembly bytes for %s", file)
		}
		usedSources[file] = true
		dir := path.Dir(file)
		for ancestor := dir; ; ancestor = path.Dir(ancestor) {
			entries, ok := dirs[ancestor]
			if !ok {
				return nil, nil, fmt.Errorf("missing ordinary ancestor directory %s", ancestor)
			}
			usedDirs[ancestor] = true
			for name, kind := range entries {
				if kind == "file" && (packageDirs[ancestor] &&
					(strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".s")) || name == "go.mod") {
					input := path.Join(ancestor, name)
					if _, ok := sources[input]; !ok {
						return nil, nil, fmt.Errorf("directory listing omits source bytes for %s", input)
					}
					usedSources[input] = true
				}
			}
			if ancestor == "." {
				break
			}
			if dirs[path.Dir(ancestor)][path.Base(ancestor)] != "directory" {
				return nil, nil, fmt.Errorf("ordinary ancestor is absent from parent directory")
			}
		}
		boundary := ordinarySelectionIgnoredBoundary(dir)
		kind, diagnostic := nativeLayoutIgnoredDirectory, "recursive corpus walk excludes this Go-ignored directory; explicit package build was not attempted"
		if boundary == "" {
			for ancestor := dir; ancestor != "."; ancestor = path.Dir(ancestor) {
				if dirs[ancestor]["go.mod"] == "file" {
					boundary, kind = path.Join(ancestor, "go.mod"), nativeLayoutNestedModule
					diagnostic = "recursive corpus walk excludes this nested-module boundary; explicit package build was not attempted"
					break
				}
			}
		}
		if boundary != "" {
			decisions = append(decisions, ordinarySelectionDecision{AsmFiles: []string{file}, Targets: plan.Targets, Kind: kind, Boundary: boundary, Diagnostic: diagnostic})
			continue
		}
		// MatchFile checks filenames and constraints, not importability. Go's
		// module loader validates the whole import path before package lookup;
		// archives sometimes contain a nested pkg/mod cache with @version in
		// its directory names. Replay the same check from ZIP-bound inputs.
		// Do not weaken concrete diagnostics for real package build failures.
		if err := ordinarySelectionPackagePathError(plan.Module, dir); err != nil {
			decisions = append(decisions, ordinarySelectionDecision{
				AsmFiles: []string{file}, Targets: plan.Targets,
				Kind: ordinarySelectionInvalidPath, Boundary: dir,
				Diagnostic: "Go module loader rejects this package import path before compilation: " + err.Error(),
			})
			continue
		}
		var goFiles []string
		var rejected []string
		for name, entryKind := range dirs[dir] {
			if entryKind != "file" || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				continue
			}
			if _, err := parser.ParseFile(token.NewFileSet(), name, sources[path.Join(dir, name)], parser.PackageClauseOnly); err != nil {
				rejected = append(rejected, name+": "+err.Error())
				continue
			}
			goFiles = append(goFiles, name)
		}
		sort.Strings(goFiles)
		sort.Strings(rejected)
		alwaysDocumentation := len(actualProfiles) == 1 && plan.DocumentationSourceProtocol == discoveryDocumentationProtocol &&
			alwaysDocumentationDirectory(dir, sources, dirs[dir])
		if len(goFiles) == 0 {
			diagnostic := "directory has no non-test, non-hidden Go file with a valid package clause"
			if len(rejected) != 0 {
				diagnostic += "; parser diagnostics: " + strings.Join(rejected, "; ")
			}
			decisions = append(decisions, ordinarySelectionDecision{AsmFiles: []string{file}, Targets: plan.Targets, Kind: discoverySourceNotApplicableNoGoPackage, Diagnostic: diagnostic})
			continue
		}
		tagsByFile := make(map[string][]string)
		var allTags []string
		for _, name := range append(append([]string(nil), goFiles...), path.Base(file)) {
			input := path.Join(dir, name)
			expr, err := discoveryFileBuildExpression(input, contexts[0].OpenFile)
			if err != nil {
				return nil, nil, err
			}
			set := make(map[string]bool)
			if expr != nil {
				collectDiscoveryConstraintTags(expr, set)
			}
			tagsByFile[filepath.FromSlash(input)] = sortedDiscoverySet(set)
			allTags = append(allTags, tagsByFile[filepath.FromSlash(input)]...)
		}
		customTags := uniqueDiscoveryCustomTags(allTags, contexts)
		if len(actualProfiles) == 1 {
			customTags = discoveryCustomTagsWithoutFeatures(allTags, contexts)
		}
		for i, ctx := range contexts {
			tags, selected, err := findDiscoveryBuildTags(ctx, filepath.FromSlash(dir), path.Base(file), goFiles, customTags, tagsByFile)
			if err != nil {
				return nil, nil, err
			}
			kind, diagnostic := nativeLayoutBuildConstraints, "Go MatchFile/custom-tag search selects no assembly/non-test-Go pair with compiler=gc and CGO_ENABLED=0"
			if alwaysDocumentation {
				kind, diagnostic = discoveryDocumentationKind, discoveryDocumentationReason
			} else if selected {
				kind, diagnostic = nativeLayoutSelected, "Go MatchFile/custom-tag search selects this assembly/non-test-Go pair; compiler/assembler acceptance is checked separately"
				eligible[nativeLayoutKey(file, plan.Targets[i], tags)] = true
			} else {
				filenameContext := ctx
				filenameContext.OpenFile = func(string) (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader("")), nil
				}
				filenameMatches, err := filenameContext.MatchFile(filepath.FromSlash(dir), path.Base(file))
				if err != nil {
					return nil, nil, err
				}
				if !filenameMatches {
					kind = ordinarySelectionFilename
					diagnostic = "Go MatchFile rejects this assembly filename independently of build directives"
					if strings.HasPrefix(path.Base(file), "_") || strings.HasPrefix(path.Base(file), ".") {
						kind = ordinarySelectionIgnoredFilename
						diagnostic = "Go MatchFile ignores this dot/underscore-prefixed assembly filename"
					}
				} else {
					cgoContext := ctx
					cgoContext.CgoEnabled = true
					_, cgoSelects, err := findDiscoveryBuildTags(cgoContext, filepath.FromSlash(dir), path.Base(file), goFiles, customTags, tagsByFile)
					if err != nil {
						return nil, nil, err
					}
					if cgoSelects {
						kind = ordinarySelectionCgoDisabled
						diagnostic = "Go MatchFile selects an assembly/non-test-Go pair only after enabling cgo; corpus selection fixes CGO_ENABLED=0"
					}
				}
			}
			decisions = append(decisions, ordinarySelectionDecision{AsmFiles: []string{file}, Targets: []string{plan.Targets[i]}, BuildTags: tags, Kind: kind, Diagnostic: diagnostic})
		}
	}
	if len(usedDirs) != len(dirs) || len(usedSources) != len(sources) {
		return nil, nil, fmt.Errorf("ordinary selection proof has unrelated or unaccounted inputs")
	}
	return compactOrdinarySelectionDecisions(decisions), eligible, nil
}

func discoveryGoMinor(version string) (int, error) {
	if !strings.HasPrefix(version, "go1.") {
		return 0, fmt.Errorf("invalid ordinary Go selection version")
	}
	parts := strings.Split(strings.TrimPrefix(version, "go1."), ".")
	if len(parts) > 2 || len(parts) == 0 {
		return 0, fmt.Errorf("invalid ordinary Go selection version")
	}
	for _, part := range parts {
		if part == "" {
			return 0, fmt.Errorf("invalid ordinary Go selection version")
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return 0, fmt.Errorf("invalid ordinary Go selection version")
			}
		}
	}
	minor, err := strconv.Atoi(parts[0])
	if err != nil || minor < 1 || minor > 100 {
		return 0, fmt.Errorf("invalid ordinary Go selection version")
	}
	return minor, nil
}

func compactOrdinarySelectionDecisions(decisions []ordinarySelectionDecision) []ordinarySelectionDecision {
	var targetGroups []ordinarySelectionDecision
	for _, decision := range decisions {
		merged := false
		for i := range targetGroups {
			existing := &targetGroups[i]
			if existing.Kind == decision.Kind && existing.Boundary == decision.Boundary && existing.Diagnostic == decision.Diagnostic &&
				equalDiscoveryStrings(existing.BuildTags, decision.BuildTags) && equalDiscoveryStrings(existing.AsmFiles, decision.AsmFiles) {
				existing.Targets = uniqueSortedDiscoveryStrings(append(existing.Targets, decision.Targets...))
				merged = true
				break
			}
		}
		if !merged {
			targetGroups = append(targetGroups, decision)
		}
	}
	var compact []ordinarySelectionDecision
	for _, decision := range targetGroups {
		merged := false
		for i := range compact {
			existing := &compact[i]
			if existing.Kind == decision.Kind && existing.Boundary == decision.Boundary && existing.Diagnostic == decision.Diagnostic &&
				equalDiscoveryStrings(existing.BuildTags, decision.BuildTags) && equalDiscoveryStrings(existing.Targets, decision.Targets) {
				existing.AsmFiles = uniqueSortedDiscoveryStrings(append(existing.AsmFiles, decision.AsmFiles...))
				merged = true
				break
			}
		}
		if !merged {
			compact = append(compact, decision)
		}
	}
	return compact
}

func validateOrdinarySelectionResult(result discoveryCorpusResult, targets []string, goVersion string) error {
	plan := result.OrdinarySelectionPlan
	if plan == nil {
		if result.Status == discoveryStatusPassed || result.Status == discoveryStatusNotApplicable || len(result.SourceNotApplicableItems) != 0 {
			return fmt.Errorf("ordinary pass or source exclusion lacks exact source-selection proof")
		}
		return nil
	}
	if len(plan.FortranRejections) != 0 || len(plan.MixedPackageRejections) != 0 || len(plan.SDKNamespaceRejections) != 0 {
		return fmt.Errorf("typed loader source proof requires current profile-aware report replay")
	}
	if len(plan.DocumentationPackages) != 0 || plan.DocumentationRules != nil {
		return fmt.Errorf("documentation source proof requires current profile-aware report replay")
	}
	if err := validateDiscoverySourceNotApplicableEvidence(result); err != nil {
		return err
	}
	if plan.Module != result.Module || plan.Version != result.Version ||
		!equalDiscoveryStrings(plan.Targets, uniqueSortedDiscoveryStrings(targets)) ||
		(goVersion != "" && plan.GoVersion != goVersion) {
		return fmt.Errorf("ordinary source-selection module/target/Go provenance mismatch")
	}
	digest, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(plan.ModuleSum, "h1:"))
	if !strings.HasPrefix(plan.ModuleSum, "h1:") || err != nil || len(digest) != sha256.Size ||
		!discoverySHA256Pattern.MatchString(plan.ZipSHA256) {
		return fmt.Errorf("ordinary source-selection proof lacks exact module ZIP/sum identity")
	}
	scope, err := discoveryResultAssemblyScope(result)
	if err != nil {
		return err
	}
	decisions, eligible, err := replayOrdinarySelection(plan, scope)
	if err != nil {
		return err
	}
	if plan.CPPInputs != nil {
		if err := validateDiscoveryCPPInputs(plan.CPPInputs, plan, ordinarySelectionEligibleCPPFiles(eligible)); err != nil {
			return err
		}
		if result.Status == discoveryStatusPassed || result.Status == discoveryStatusNotApplicable || len(result.SourceNotApplicableItems) != 0 {
			required, err := discoveryCPPRequiresFeatureProfiles(plan.CPPInputs)
			if err != nil {
				return err
			}
			if required {
				return fmt.Errorf("CPP profiles require profile-aware production consumers; unconsumed profile cannot give pass/N/A credit")
			}
		}
	}
	if !equalOrdinarySelectionDecisions(decisions, plan.Decisions) {
		return fmt.Errorf("ordinary source-selection decisions disagree with exact source replay")
	}
	files, targetSet := make(map[string]bool), make(map[string]bool)
	for _, file := range scope {
		files[file] = true
	}
	for _, target := range targets {
		targetSet[target] = true
	}
	executed, err := nativeLayoutConfigurationKeys(result.BuildConfigurations, files, targetSet)
	if err != nil {
		return err
	}
	for key := range executed {
		if !eligible[key] {
			return fmt.Errorf("ordinary execution claims an unselected source scope %v", key)
		}
	}
	noPackage := make(map[nativeLayoutPlanKey]bool)
	for _, decision := range decisions {
		if decision.Kind == discoverySourceNotApplicableNoGoPackage {
			for _, file := range decision.AsmFiles {
				for _, target := range decision.Targets {
					noPackage[nativeLayoutKey(file, target, nil)] = true
				}
			}
		}
	}
	sourceNA := make(map[nativeLayoutPlanKey]bool)
	for _, item := range result.SourceNotApplicableItems {
		itemFiles := append(append([]string(nil), item.AsmFiles...), item.AsmFile)
		for _, file := range itemFiles {
			if file == "" {
				continue
			}
			for _, target := range item.Targets {
				key := nativeLayoutKey(file, target, item.BuildTags)
				valid := eligible[key] && item.Kind != discoverySourceNotApplicableNoGoPackage ||
					noPackage[key] && item.Kind == discoverySourceNotApplicableNoGoPackage
				if !valid || executed[key] || sourceNA[key] || strings.TrimSpace(item.Reason) == "" || isDiscoveryGoBuildInfrastructureFailure(item.Reason) {
					return fmt.Errorf("ordinary source N/A has unplanned, duplicate, executed or non-source evidence %v", key)
				}
				sourceNA[key] = true
			}
		}
	}
	for key := range eligible {
		if !executed[key] && !sourceNA[key] {
			return fmt.Errorf("ordinary selected source was neither executed nor rejected with evidence: %v", key)
		}
	}
	for key := range noPackage {
		if !sourceNA[key] {
			return fmt.Errorf("ordinary no-package decision lacks structured source evidence")
		}
	}
	if result.Translations+result.NotApplicableTranslations != len(executed) ||
		result.NotApplicableTranslations != len(result.NotApplicableItems) ||
		!equalDiscoveryStrings(result.ApplicableAsmFiles, discoveryConfigurationAsmFiles(result.BuildConfigurations)) {
		return fmt.Errorf("ordinary execution counts/file union disagree with source-selection proof")
	}
	targetNA, err := summarizeDiscoveryTargetSkips(discoveryCandidate{AsmFiles: scope}, result.NotApplicableItems)
	if err != nil {
		return err
	}
	seenTargetNA := make(map[nativeLayoutPlanKey]bool)
	for _, item := range targetNA {
		if item.Kind != targetNotApplicableGoTextArgSize || item.Symbol == "" || item.PkgPath == "" || item.DeclaredArgSize == item.ExpectedArgSize {
			return fmt.Errorf("ordinary target N/A has invalid ABI evidence")
		}
		found := false
		for key := range executed {
			if key.File == item.AsmFile && key.Target == item.Target {
				if seenTargetNA[key] {
					return fmt.Errorf("ordinary target N/A has duplicate ABI evidence")
				}
				seenTargetNA[key] = true
				found = true
			}
		}
		if !found {
			return fmt.Errorf("ordinary ABI evidence claims an unexecuted source")
		}
	}
	return nil
}

func equalOrdinarySelectionDecisions(left, right []ordinarySelectionDecision) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].Kind != right[i].Kind || left[i].Boundary != right[i].Boundary || left[i].Diagnostic != right[i].Diagnostic ||
			!equalDiscoveryStrings(left[i].AsmFiles, right[i].AsmFiles) || !equalDiscoveryStrings(left[i].Targets, right[i].Targets) ||
			!equalDiscoveryStrings(left[i].BuildTags, right[i].BuildTags) {
			return false
		}
	}
	return true
}

func ordinarySelectionReason(plan *discoveryOrdinarySelectionPlan, evidence []discoverySourceNotApplicableItem, targetABI []matrixTargetNotApplicableItem) string {
	counts := make(map[string]int)
	decisions := plan.Decisions
	scope := "file/target scopes"
	if len(plan.ProfileDecisions) != 0 {
		decisions = nil
		for _, decision := range plan.ProfileDecisions {
			decisions = append(decisions, decision.ordinarySelectionDecision)
		}
		scope = "ordinary non-test file/target/profile/custom-tag scopes"
	}
	for _, decision := range decisions {
		if decision.Kind != nativeLayoutSelected {
			counts[decision.Kind] += len(decision.AsmFiles) * len(decision.Targets)
		}
	}
	for _, item := range evidence {
		if item.Kind == discoverySourceNotApplicableNoGoPackage || item.Kind == discoveryDocumentationKind {
			continue // Already represented by the pre-build source decision.
		}
		files := append(append([]string(nil), item.AsmFiles...), item.AsmFile)
		deleteEmpty := make(map[string]bool)
		for _, file := range files {
			if file != "" {
				deleteEmpty[file] = true
			}
		}
		counts[item.Kind] += len(deleteEmpty) * len(item.Targets)
	}
	if len(targetABI) != 0 {
		counts[targetNotApplicableGoTextArgSize] += len(targetABI)
	}
	var summaries []string
	for _, kind := range sortedDiscoveryMapKeys(counts) {
		summaries = append(summaries, fmt.Sprintf("%s=%d %s", kind, counts[kind], scope))
	}
	if len(summaries) == 0 {
		return "all source-selected scopes have separately recorded target ABI rejection"
	}
	return "exact source selection/rejection proof: " + strings.Join(summaries, "; ")
}

func sortedDiscoveryMapKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
