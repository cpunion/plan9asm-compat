package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/mod/module"
)

// This producer bypasses only cmd/go's vet-result cache. Stock Go still
// selects and compiles the actual package/test graph using its compiler cache.
// Caller-provided configs are not accepted. Analysis is not an object proof.
func runDiscoveryAsmDeclDirect(ctx context.Context, dir string, env, buildTags, patterns []string, modfilePath string) (result error) {
	plan, err := captureDiscoveryAsmDeclDirect(ctx, dir, env, buildTags, patterns, modfilePath)
	if err != nil {
		return err
	}
	defer func() {
		if err := plan.close(); err != nil {
			result = errors.Join(result, err)
		}
	}()
	return plan.run(ctx)
}

const (
	directAsmDeclMaxPackages    = 4096
	directAsmDeclMaxFiles       = 65536
	directAsmDeclMaxBytes       = 1 << 30
	directAsmDeclFileLimit      = 128 << 20
	directAsmDeclSDKSourceLimit = 4 << 20
)

type directAsmDeclModule struct {
	Path, Version, Dir, GoMod, GoVersion string
	Replace                              *directAsmDeclModule
	Time                                 *time.Time
	Main, Indirect                       bool
	Error                                *struct{ Err string }
}

type directAsmDeclPackage struct {
	ImportPath, Name, Dir, ForTest, Export, BuildID string
	DepOnly, Standard, Incomplete                   bool
	Match, Imports, Deps                            []string
	GoFiles, CgoFiles, CompiledGoFiles              []string
	SFiles, CFiles, HFiles                          []string
	TestGoFiles, XTestGoFiles                       []string
	IgnoredGoFiles, IgnoredOtherFiles               []string
	ImportMap                                       map[string]string
	Module                                          *directAsmDeclModule
	Error                                           *struct{ Err string }
	DepsErrors                                      []struct{ Err string }
}

// Both safety booleans are emitted explicitly. Optional fields are emitted
// only for SDKs that consume them; Go 1.20 has no GoVersion field.
type directAsmDeclConfig struct {
	ID, Compiler, Dir, ImportPath     string
	GoFiles, NonGoFiles, IgnoredFiles []string
	ImportMap, PackageFile            map[string]string
	Standard                          map[string]bool
	PackageVetx                       map[string]string
	VetxOnly                          bool
	VetxOutput                        string
	SucceedOnTypecheckFailure         bool
	GoVersion                         string               `json:",omitempty"`
	ModulePath, ModuleVersion         string               `json:",omitempty"`
	Module                            *directAsmDeclModule `json:",omitempty"`
}

type directAsmDeclUnit struct {
	PackageID, Filename string
	Config              directAsmDeclConfig
}

type directAsmDeclSnapshot struct {
	Path string
	SHA  [sha256.Size]byte
	Size int64
}

type directAsmDeclPlan struct {
	GoBinary, Dir, WorkDir string
	Env, Args              []string
	SDK                    map[string]string
	ToolVersions           map[string]string
	Minor                  int
	Packages               []directAsmDeclPackage
	Units                  []directAsmDeclUnit
	Files                  []directAsmDeclSnapshot
	Directories            map[string][]string
	Seal                   [sha256.Size]byte
	closed                 bool
	workInfo               os.FileInfo
	fileIndex              map[string]directAsmDeclSnapshot
	directoryInfo          map[string]os.FileInfo
	directoryAliases       map[string]string
	totalBytes             int64
	resultAliasRawFailures []*discoveryCapturedCommandError
}

func captureDiscoveryAsmDeclDirect(ctx context.Context, dir string, env, buildTags, patterns []string, modfilePath string) (_ *directAsmDeclPlan, result error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("direct asmdecl requires actual package patterns")
	}
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		if pattern == "" || strings.HasPrefix(pattern, "-") || seen[pattern] {
			return nil, fmt.Errorf("invalid or duplicate direct asmdecl pattern %q", pattern)
		}
		seen[pattern] = true
	}
	dir, err := directAsmDeclPhysicalDirectory(dir)
	if err != nil {
		return nil, err
	}
	if env == nil {
		env = os.Environ()
	}
	goBinary, err := directAsmDeclGoBinary(env)
	if err != nil {
		return nil, err
	}
	plan := &directAsmDeclPlan{
		GoBinary: goBinary, Dir: dir, Env: append([]string(nil), env...),
		Directories:      make(map[string][]string),
		fileIndex:        make(map[string]directAsmDeclSnapshot),
		directoryInfo:    make(map[string]os.FileInfo),
		directoryAliases: make(map[string]string),
	}
	defer func() {
		if result != nil {
			if err := plan.close(); err != nil {
				result = errors.Join(result, err)
			}
		}
	}()
	plan.SDK, err = directAsmDeclObserveSDK(ctx, dir, env, goBinary)
	if err != nil {
		return nil, err
	}
	plan.Minor, err = directAsmDeclSDKMinor(plan.SDK["GOVERSION"])
	if err != nil {
		return nil, err
	}
	if err := plan.bindSDK(); err != nil {
		return nil, err
	}
	plan.ToolVersions, err = plan.observeToolVersions(ctx)
	if err != nil {
		return nil, err
	}
	plan.Args = []string{"list", "-deps", "-export", "-compiled", "-test", "-json", "-mod=mod"}
	if modfilePath != "" {
		if !filepath.IsAbs(modfilePath) {
			modfilePath = filepath.Join(dir, modfilePath)
		}
		plan.Args = append(plan.Args, "-modfile="+modfilePath)
		// Module.GoMod in a replacement/proxy record is not a substitute
		// for the effective invocation's alternate configuration.
		if err := plan.bindFile(modfilePath); err != nil {
			return nil, err
		}
	}
	if len(buildTags) != 0 {
		plan.Args = append(plan.Args, "-tags="+strings.Join(buildTags, ","))
	}
	plan.Args = append(plan.Args, patterns...)
	plan.Packages, err = plan.list(ctx)
	if err != nil {
		return nil, err
	}
	if modfilePath != "" {
		if err := plan.bindOptionalFile(strings.TrimSuffix(modfilePath, ".mod") + ".sum"); err != nil {
			return nil, err
		}
	}
	plan.WorkDir, err = os.MkdirTemp("", "plan9asm-direct-vet-")
	if err != nil {
		return nil, err
	}
	plan.workInfo, err = os.Lstat(plan.WorkDir)
	if err != nil || !plan.workInfo.IsDir() {
		return nil, fmt.Errorf("direct asmdecl owned config directory identity: %v", err)
	}
	physicalWorkDir, err := directAsmDeclPhysicalDirectory(plan.WorkDir)
	if err != nil {
		return nil, err
	}
	plan.WorkDir = physicalWorkDir
	if err := plan.buildUnits(); err != nil {
		return nil, err
	}
	if err := plan.bindPackages(); err != nil {
		return nil, err
	}
	for _, unit := range plan.Units {
		data, err := json.MarshalIndent(unit.Config, "", "\t")
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(unit.Filename, append(data, '\n'), 0600); err != nil {
			return nil, err
		}
		if err := plan.bindFile(unit.Filename); err != nil {
			return nil, err
		}
	}
	plan.Seal, err = plan.digest()
	if err != nil {
		return nil, err
	}
	if err := plan.verify(ctx); err != nil {
		return nil, err
	}
	return plan, nil
}

func (plan *directAsmDeclPlan) run(ctx context.Context) error {
	if err := plan.verify(ctx); err != nil {
		return err
	}
	var failures []error
	for _, unit := range plan.Units {
		if err := plan.verifyUnitBytes(unit); err != nil {
			return errors.Join(append(failures, err)...)
		}
		stage, cancel := context.WithTimeout(ctx, 5*time.Minute)
		output, err := runCapturedCommandOutput(stage, plan.Dir, plan.Env, plan.GoBinary, "tool", "vet", "-asmdecl", unit.Filename)
		cancel()
		if err != nil {
			err = plan.filterResultAliasWarnings(unit, err)
			if err != nil {
				failures = append(failures, err)
			}
		} else if len(bytes.TrimSpace(output)) != 0 {
			failures = append(failures, fmt.Errorf("direct asmdecl returned unexplained successful output: %s", output))
		}
		if err := plan.verifyUnitBytes(unit); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if ctx.Err() != nil {
			return errors.Join(append(failures, ctx.Err())...)
		}
	}
	if err := plan.verify(ctx); err != nil {
		return errors.Join(append(failures, err)...)
	}
	// Only this fully completed and independently reverified path may
	// aggregate the separately observed analysis failures. Incomplete,
	// source/tool/config/cleanup failures never receive this authority.
	return combineDiscoveryAsmDeclAnalysisFailures(failures, len(plan.Units), len(plan.Units))
}

func (plan *directAsmDeclPlan) close() error {
	if plan.closed {
		return nil
	}
	plan.closed = true
	if plan.WorkDir != "" {
		current, err := os.Lstat(plan.WorkDir)
		if err != nil || plan.workInfo == nil || !current.IsDir() || !os.SameFile(current, plan.workInfo) {
			return fmt.Errorf("direct asmdecl owned config directory changed; not removed: %v", err)
		}
		return os.RemoveAll(plan.WorkDir)
	}
	return nil
}

func (plan *directAsmDeclPlan) digest() ([sha256.Size]byte, error) {
	// This private seal is never accepted from report JSON. Marshal failure
	// must not become an empty universal digest.
	data, err := json.Marshal(struct {
		GoBinary, Dir, WorkDir string
		Env, Args              []string
		SDK                    map[string]string
		ToolVersions           map[string]string
		Minor                  int
		Packages               []directAsmDeclPackage
		Units                  []directAsmDeclUnit
		Files                  []directAsmDeclSnapshot
		Directories            map[string][]string
		FileIndex              map[string]directAsmDeclSnapshot
		DirectoryAliases       map[string]string
	}{plan.GoBinary, plan.Dir, plan.WorkDir, plan.Env, plan.Args, plan.SDK, plan.ToolVersions, plan.Minor, plan.Packages, plan.Units, plan.Files, plan.Directories, plan.fileIndex, plan.directoryAliases})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(data), nil
}

func (plan *directAsmDeclPlan) verifyBytes() error {
	if plan.closed {
		return fmt.Errorf("direct asmdecl plan is closed")
	}
	digest, err := plan.digest()
	if err != nil {
		return err
	}
	if digest != plan.Seal {
		return fmt.Errorf("direct asmdecl config/source identity changed")
	}
	if err := plan.verifyDirectoryIdentities(); err != nil {
		return err
	}
	for _, input := range plan.Files {
		if err := directAsmDeclVerifyFile(input); err != nil {
			return err
		}
	}
	for dir, names := range plan.Directories {
		current, err := directAsmDeclDirectoryNames(dir)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, names) {
			return fmt.Errorf("direct asmdecl package directory changed: %s", dir)
		}
	}
	return plan.verifyDirectoryIdentities()
}

func (plan *directAsmDeclPlan) verifyDirectoryIdentities() error {
	for logical, captured := range plan.directoryAliases {
		physical, err := directAsmDeclPhysicalDirectory(logical)
		if err != nil || physical != captured {
			return fmt.Errorf("direct asmdecl directory alias changed: %s (%v)", logical, err)
		}
	}
	for dir, identity := range plan.directoryInfo {
		current, err := os.Lstat(dir)
		if err != nil || !current.IsDir() || !os.SameFile(identity, current) {
			return fmt.Errorf("direct asmdecl source/config directory identity changed: %s (%v)", dir, err)
		}
	}
	return nil
}

// The SDK and full graph are guarded at the whole-call boundaries. Each
// analysis additionally checks its exact config/source/imported exports;
// it does not repeatedly hash every SDK binary for every requested unit.
func (plan *directAsmDeclPlan) verifyUnitBytes(unit directAsmDeclUnit) error {
	if plan.closed {
		return fmt.Errorf("direct asmdecl plan is closed")
	}
	digest, err := plan.digest()
	if err != nil || digest != plan.Seal {
		return fmt.Errorf("direct asmdecl config/source identity changed: %v", err)
	}
	if err := plan.verifyDirectoryIdentities(); err != nil {
		return err
	}
	paths := append([]string{unit.Filename}, unit.Config.GoFiles...)
	paths = append(paths, unit.Config.NonGoFiles...)
	paths = append(paths, unit.Config.IgnoredFiles...)
	for _, file := range unit.Config.PackageFile {
		paths = append(paths, file)
	}
	seen := make(map[string]bool)
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		input, found := plan.fileIndex[path]
		if !found {
			return fmt.Errorf("direct asmdecl unit input is unbound: %s", path)
		}
		if err := directAsmDeclVerifyFile(input); err != nil {
			return err
		}
	}
	names, err := directAsmDeclDirectoryNames(unit.Config.Dir)
	if err != nil || !reflect.DeepEqual(names, plan.Directories[unit.Config.Dir]) {
		return fmt.Errorf("direct asmdecl unit directory changed: %v", err)
	}
	return nil
}

func directAsmDeclVerifyFile(input directAsmDeclSnapshot) error {
	if input.Size == -1 {
		if _, err := os.Lstat(input.Path); os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("direct asmdecl absent metadata changed: %s", input.Path)
	}
	sha, size, err := directAsmDeclFileSHA(input.Path)
	if err != nil {
		return err
	}
	if sha != input.SHA || size != input.Size {
		return fmt.Errorf("direct asmdecl input changed: %s", input.Path)
	}
	return nil
}

func (plan *directAsmDeclPlan) verify(ctx context.Context) error {
	if err := plan.verifyBytes(); err != nil {
		return err
	}
	sdk, err := directAsmDeclObserveSDK(ctx, plan.Dir, plan.Env, plan.GoBinary)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(sdk, plan.SDK) {
		return fmt.Errorf("direct asmdecl actual SDK/context changed")
	}
	versions, err := plan.observeToolVersions(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(versions, plan.ToolVersions) {
		return fmt.Errorf("direct asmdecl actual tool versions changed")
	}
	packages, err := plan.list(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(packages, plan.Packages) {
		return fmt.Errorf("direct asmdecl actual package/export selection changed")
	}
	return plan.verifyBytes()
}

func (plan *directAsmDeclPlan) list(ctx context.Context) ([]directAsmDeclPackage, error) {
	output, err := directAsmDeclCommandJSON(ctx, plan.Dir, plan.Env, plan.GoBinary, plan.Args...)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	var packages []directAsmDeclPackage
	seen := make(map[string]bool)
	for {
		var pkg directAsmDeclPackage
		if err := decoder.Decode(&pkg); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode actual direct asmdecl package graph: %w", err)
		}
		if pkg.ImportPath == "" || seen[pkg.ImportPath] || pkg.Incomplete || pkg.Error != nil || len(pkg.DepsErrors) != 0 {
			return nil, fmt.Errorf("incomplete/duplicate actual direct asmdecl package %q", pkg.ImportPath)
		}
		if len(pkg.CgoFiles) != 0 {
			return nil, fmt.Errorf("direct asmdecl generated cgo inputs have no registered source mapping: %s", pkg.ImportPath)
		}
		if len(packages) >= directAsmDeclMaxPackages {
			return nil, fmt.Errorf("direct asmdecl package graph exceeds %d packages", directAsmDeclMaxPackages)
		}
		seen[pkg.ImportPath] = true
		packages = append(packages, pkg)
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("actual direct asmdecl package graph is empty")
	}
	return packages, nil
}

func directAsmDeclCanonical(pkg directAsmDeclPackage) (string, error) {
	if pkg.ForTest == "" {
		if strings.ContainsAny(pkg.ImportPath, " []") {
			return "", fmt.Errorf("unregistered actual package variant %q", pkg.ImportPath)
		}
		return pkg.ImportPath, nil
	}
	suffix := " [" + pkg.ForTest + ".test]"
	if !strings.HasSuffix(pkg.ImportPath, suffix) {
		return "", fmt.Errorf("actual ForTest identity does not bind variant %q", pkg.ImportPath)
	}
	canonical := strings.TrimSuffix(pkg.ImportPath, suffix)
	if canonical == "" || strings.ContainsAny(canonical, " []") {
		return "", fmt.Errorf("invalid actual canonical package %q", canonical)
	}
	return canonical, nil
}

func (plan *directAsmDeclPlan) buildUnits() error {
	byID := make(map[string]directAsmDeclPackage)
	for _, pkg := range plan.Packages {
		byID[pkg.ImportPath] = pkg
	}
	var selected []directAsmDeclPackage
	for _, original := range plan.Packages {
		if original.DepOnly || original.ForTest != "" || len(original.Match) == 0 {
			continue
		}
		ptest := original
		if len(original.TestGoFiles) != 0 || (original.Name == "main" && len(original.XTestGoFiles) != 0) {
			id := original.ImportPath + " [" + original.ImportPath + ".test]"
			var found bool
			ptest, found = byID[id]
			if !found || ptest.Dir != original.Dir || !reflect.DeepEqual(ptest.Module, original.Module) {
				return fmt.Errorf("actual in-package test variant is absent or foreign: %s", original.ImportPath)
			}
		}
		selected = append(selected, ptest)
		if len(original.XTestGoFiles) != 0 {
			id := original.ImportPath + "_test [" + original.ImportPath + ".test]"
			pxtest, found := byID[id]
			if !found || pxtest.Dir != original.Dir || !reflect.DeepEqual(pxtest.Module, original.Module) {
				return fmt.Errorf("actual external test variant is absent or foreign: %s", original.ImportPath)
			}
			selected = append(selected, pxtest)
		}
	}
	if len(selected) == 0 {
		return fmt.Errorf("actual direct asmdecl graph has no requested compilation units")
	}
	seen := make(map[string]bool)
	for _, pkg := range selected {
		if seen[pkg.ImportPath] {
			return fmt.Errorf("duplicate direct asmdecl unit %s", pkg.ImportPath)
		}
		seen[pkg.ImportPath] = true
		config, err := plan.makeConfig(pkg, byID)
		if err != nil {
			return err
		}
		index := len(plan.Units)
		config.VetxOutput = filepath.Join(plan.WorkDir, fmt.Sprintf("unit-%d.vetx", index))
		plan.Units = append(plan.Units, directAsmDeclUnit{pkg.ImportPath, filepath.Join(plan.WorkDir, fmt.Sprintf("unit-%d.cfg", index)), config})
	}
	return nil
}

func (plan *directAsmDeclPlan) makeConfig(pkg directAsmDeclPackage, byID map[string]directAsmDeclPackage) (directAsmDeclConfig, error) {
	canonical, err := directAsmDeclCanonical(pkg)
	if err != nil {
		return directAsmDeclConfig{}, err
	}
	config := directAsmDeclConfig{
		ID: pkg.ImportPath, Compiler: "gc", Dir: pkg.Dir, ImportPath: canonical,
		ImportMap: make(map[string]string), PackageFile: make(map[string]string),
		Standard: make(map[string]bool), PackageVetx: make(map[string]string),
	}
	if len(pkg.CompiledGoFiles) == 0 || len(pkg.CgoFiles) != 0 {
		return config, fmt.Errorf("actual direct asmdecl unit has no closed compiled Go inputs: %s", pkg.ImportPath)
	}
	config.GoFiles, err = directAsmDeclAbsFiles(pkg.Dir, pkg.CompiledGoFiles)
	if err != nil {
		return config, err
	}
	config.NonGoFiles, err = directAsmDeclAbsFiles(pkg.Dir, append(append([]string(nil), pkg.SFiles...), pkg.CFiles...))
	if err != nil {
		return config, err
	}
	config.IgnoredFiles, err = directAsmDeclAbsFiles(pkg.Dir, append(append([]string(nil), pkg.IgnoredGoFiles...), pkg.IgnoredOtherFiles...))
	if err != nil {
		return config, err
	}
	for _, id := range pkg.Imports {
		dependency, found := byID[id]
		if !found {
			return config, fmt.Errorf("actual direct import is absent: %s -> %s", pkg.ImportPath, id)
		}
		path, err := directAsmDeclCanonical(dependency)
		if err != nil {
			return config, err
		}
		if _, mapped := pkg.ImportMap[path]; !mapped {
			config.ImportMap[path] = path
		}
	}
	for source, id := range pkg.ImportMap {
		dependency, found := byID[id]
		if !found {
			return config, fmt.Errorf("actual ImportMap target is absent: %s -> %s", source, id)
		}
		path, err := directAsmDeclCanonical(dependency)
		if err != nil {
			return config, err
		}
		config.ImportMap[source] = path
	}
	// Each unit owns its reachable exports. Other test units may legitimately
	// have a different archive for the same canonical package elsewhere.
	queue := append([]string(nil), pkg.Imports...)
	visited := make(map[string]bool)
	for len(queue) != 0 {
		id := queue[0]
		queue = queue[1:]
		if visited[id] {
			continue
		}
		visited[id] = true
		dependency, found := byID[id]
		if !found {
			return config, fmt.Errorf("actual dependency closure is absent: %s", id)
		}
		path, err := directAsmDeclCanonical(dependency)
		if err != nil {
			return config, err
		}
		if path != "unsafe" {
			if dependency.Export == "" || !filepath.IsAbs(dependency.Export) {
				return config, fmt.Errorf("actual dependency has no absolute compiled export: %s", id)
			}
			if old, found := config.PackageFile[path]; found && old != dependency.Export {
				return config, fmt.Errorf("conflicting actual exports in one unit for %s", path)
			}
			config.PackageFile[path] = dependency.Export
		}
		if dependency.Standard {
			config.Standard[path] = true
		}
		queue = append(queue, dependency.Imports...)
	}
	if plan.Minor >= 21 {
		if plan.Minor >= 23 {
			config.GoVersion = plan.SDK["GOVERSION"]
		}
		if pkg.Module != nil {
			version := pkg.Module.GoVersion
			if version == "" {
				version = "1.16"
			}
			config.GoVersion = "go" + version
		}
	}
	if plan.Minor >= 24 && plan.Minor <= 26 && pkg.Module != nil {
		config.ModulePath, config.ModuleVersion = pkg.Module.Path, pkg.Module.Version
	}
	if plan.Minor == 27 {
		config.Module = pkg.Module
	}
	return config, nil
}

func (plan *directAsmDeclPlan) bindPackages() error {
	if gomod := plan.SDK["GOMOD"]; gomod != "" && gomod != os.DevNull {
		if err := plan.bindFile(gomod); err != nil {
			return err
		}
		if err := plan.bindOptionalFile(strings.TrimSuffix(gomod, ".mod") + ".sum"); err != nil {
			return err
		}
	}
	for _, pkg := range plan.Packages {
		if !filepath.IsAbs(pkg.Dir) {
			return fmt.Errorf("actual package directory is not absolute: %s", pkg.ImportPath)
		}
		if err := plan.bindDirectoryIdentity(pkg.Dir); err != nil {
			return err
		}
		names, err := directAsmDeclDirectoryNames(pkg.Dir)
		if err != nil {
			return err
		}
		plan.Directories[pkg.Dir] = names
		groups := [][]string{pkg.GoFiles, pkg.CompiledGoFiles, pkg.SFiles, pkg.CFiles, pkg.HFiles, pkg.TestGoFiles, pkg.XTestGoFiles, pkg.IgnoredGoFiles, pkg.IgnoredOtherFiles}
		for _, group := range groups {
			files, err := directAsmDeclAbsFiles(pkg.Dir, group)
			if err != nil {
				return err
			}
			for _, file := range files {
				if err := plan.bindFile(file); err != nil {
					return err
				}
			}
		}
		if pkg.Export != "" {
			if err := plan.bindFile(pkg.Export); err != nil {
				return err
			}
		}
		for module := pkg.Module; module != nil; module = module.Replace {
			if module.Error != nil || module.GoMod == "" {
				return fmt.Errorf("actual module metadata is incomplete: %s", module.Path)
			}
			if err := plan.bindFile(module.GoMod); err != nil {
				return err
			}
			if err := plan.bindOptionalFile(strings.TrimSuffix(module.GoMod, ".mod") + ".sum"); err != nil {
				return err
			}
		}
	}
	if plan.SDK["GOWORK"] != "" && plan.SDK["GOWORK"] != "off" {
		if err := plan.bindFile(plan.SDK["GOWORK"]); err != nil {
			return err
		}
		return plan.bindOptionalFile(plan.SDK["GOWORK"] + ".sum")
	}
	return nil
}

func (plan *directAsmDeclPlan) bindOptionalFile(path string) error {
	if err := plan.bindDirectoryIdentity(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			if _, found := plan.fileIndex[path]; !found {
				if len(plan.Files) >= directAsmDeclMaxFiles {
					return fmt.Errorf("direct asmdecl input count exceeds %d", directAsmDeclMaxFiles)
				}
				input := directAsmDeclSnapshot{Path: path, Size: -1}
				plan.Files = append(plan.Files, input)
				plan.fileIndex[path] = input
			}
			return nil
		}
		return err
	}
	return plan.bindFile(path)
}

func (plan *directAsmDeclPlan) bindFile(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("direct asmdecl input path is not absolute: %s", path)
	}
	if err := plan.bindDirectoryIdentity(filepath.Dir(path)); err != nil {
		return err
	}
	if _, found := plan.fileIndex[path]; found {
		return nil
	}
	if len(plan.Files) >= directAsmDeclMaxFiles {
		return fmt.Errorf("direct asmdecl input count exceeds %d", directAsmDeclMaxFiles)
	}
	sha, size, err := directAsmDeclFileSHA(path)
	if err != nil {
		return err
	}
	if size > directAsmDeclMaxBytes-plan.totalBytes {
		return fmt.Errorf("direct asmdecl input bytes exceed %d", directAsmDeclMaxBytes)
	}
	input := directAsmDeclSnapshot{path, sha, size}
	plan.Files = append(plan.Files, input)
	plan.fileIndex[path] = input
	plan.totalBytes += size
	return nil
}

func (plan *directAsmDeclPlan) bindDirectoryIdentity(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("direct asmdecl directory spelling is not absolute and clean: %s", dir)
	}
	physical, err := directAsmDeclPhysicalDirectory(dir)
	if err != nil {
		return err
	}
	if previous, found := plan.directoryAliases[dir]; found && previous != physical {
		return fmt.Errorf("direct asmdecl directory alias changed while binding: %s", dir)
	}
	// Keep the actual Go spelling in Config/Files/SDK. Its private alias is
	// sealed separately; only the physical directory and ancestor identities
	// supply the filesystem guard. A leaf file may never be a symlink.
	plan.directoryAliases[dir] = physical
	dir = physical
	for {
		if _, found := plan.directoryInfo[dir]; !found {
			info, err := os.Lstat(dir)
			if err != nil || !info.IsDir() {
				return fmt.Errorf("direct asmdecl directory identity unavailable: %s (%v)", dir, err)
			}
			plan.directoryInfo[dir] = info
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}

func directAsmDeclFileSHA(path string) ([sha256.Size]byte, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > directAsmDeclFileLimit {
		return [sha256.Size]byte{}, 0, fmt.Errorf("direct asmdecl input is nonregular or oversized: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	hash := sha256.New()
	n, readErr := io.Copy(hash, io.LimitReader(file, directAsmDeclFileLimit+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	if n != info.Size() || n > directAsmDeclFileLimit {
		return [sha256.Size]byte{}, 0, fmt.Errorf("direct asmdecl input changed size while reading: %s", path)
	}
	var sha [sha256.Size]byte
	copy(sha[:], hash.Sum(nil))
	return sha, n, nil
}

func directAsmDeclAbsFiles(dir string, names []string) ([]string, error) {
	var files []string
	seen := make(map[string]bool)
	for _, name := range names {
		if name == "" {
			return nil, fmt.Errorf("empty actual direct asmdecl filename")
		}
		if !filepath.IsAbs(name) {
			if filepath.Clean(name) != name || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
				return nil, fmt.Errorf("escaping actual direct asmdecl filename %q", name)
			}
			name = filepath.Join(dir, name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate actual direct asmdecl filename %q", name)
		}
		seen[name] = true
		files = append(files, name)
	}
	return files, nil
}

func directAsmDeclDirectoryNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name()+":"+entry.Type().String())
	}
	return names, nil
}

func directAsmDeclPhysicalDirectory(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(dir)
}

func directAsmDeclGoBinary(env []string) (string, error) {
	path := ""
	seen := make(map[string]bool)
	for _, item := range env {
		key, _, found := strings.Cut(item, "=")
		if !found || key == "" || seen[key] {
			return "", fmt.Errorf("incomplete or duplicate direct asmdecl environment field %q", key)
		}
		seen[key] = true
		if strings.HasPrefix(item, "PATH=") {
			if path != "" {
				return "", fmt.Errorf("duplicate actual direct asmdecl PATH")
			}
			path = strings.TrimPrefix(item, "PATH=")
		}
	}
	name := "go"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	for _, dir := range filepath.SplitList(path) {
		if !filepath.IsAbs(dir) {
			return "", fmt.Errorf("direct asmdecl PATH requires absolute directories")
		}
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("invalid actual Go tool: %s", candidate)
		}
		return filepath.EvalSymlinks(candidate)
	}
	return "", fmt.Errorf("actual Go tool is absent from direct asmdecl PATH")
}

func directAsmDeclObserveSDK(ctx context.Context, dir string, env []string, goBinary string) (map[string]string, error) {
	args := []string{"env", "-json", "GOROOT", "GOTOOLDIR", "GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED", "GOMOD", "GOWORK", "GOFLAGS", "GOEXPERIMENT", "GOCACHE", "GOTOOLCHAIN", "GOENV", "GOAMD64", "GO386", "GOPATH", "GOMODCACHE"}
	output, err := directAsmDeclCommandJSON(ctx, dir, env, goBinary, args...)
	if err != nil {
		return nil, err
	}
	var sdk map[string]string
	if err := json.Unmarshal(output, &sdk); err != nil {
		return nil, err
	}
	minor, err := directAsmDeclSDKMinor(sdk["GOVERSION"])
	if err != nil {
		return nil, err
	}
	// Go 1.20 predates automatic toolchain selection and reports an empty
	// value for this otherwise unknown env key. Later SDKs must be local.
	localToolchain := sdk["GOTOOLCHAIN"] == "local" || (minor == 20 && sdk["GOTOOLCHAIN"] == "")
	if len(sdk) != len(args)-2 || sdk["GOROOT"] == "" || sdk["GOTOOLDIR"] == "" || sdk["GOOS"] == "" || sdk["GOARCH"] == "" || !localToolchain {
		return nil, fmt.Errorf("actual direct asmdecl SDK/context is incomplete or not local")
	}
	goenvOff := false
	for _, entry := range env {
		if entry == "GOENV=off" {
			goenvOff = true
		}
	}
	// cmd/go reports an empty GOENV pathname when explicitly disabled.
	if !goenvOff || sdk["GOENV"] != "" || sdk["CGO_ENABLED"] != "0" {
		return nil, fmt.Errorf("direct asmdecl requires explicit GOENV=off and registered CGO=0 source mapping")
	}
	if strings.Contains(sdk["GOFLAGS"], "overlay") || strings.Contains(sdk["GOFLAGS"], "toolexec") || strings.Contains(sdk["GOFLAGS"], "compiler") || strings.Contains(sdk["GOFLAGS"], "modfile") {
		return nil, fmt.Errorf("direct asmdecl compiler/overlay routing is unregistered")
	}
	return sdk, nil
}

var directAsmDeclVersion = regexp.MustCompile(`^go1\.([0-9]+)(?:\.[0-9]+)?$`)

func directAsmDeclSDKMinor(version string) (int, error) {
	match := directAsmDeclVersion.FindStringSubmatch(version)
	if match == nil {
		return 0, fmt.Errorf("unregistered direct asmdecl SDK version %q", version)
	}
	minor, err := strconv.Atoi(match[1])
	if err != nil || minor < 20 || minor > 27 {
		return 0, fmt.Errorf("unregistered direct asmdecl SDK version %q", version)
	}
	return minor, nil
}

func (plan *directAsmDeclPlan) bindSDK() error {
	root, err := directAsmDeclPhysicalDirectory(plan.SDK["GOROOT"])
	if err != nil {
		return err
	}
	expectedGo, err := filepath.EvalSymlinks(filepath.Join(root, "bin", filepath.Base(plan.GoBinary)))
	if err != nil {
		return err
	}
	if expectedGo != plan.GoBinary {
		return fmt.Errorf("actual Go executable does not belong to observed GOROOT")
	}
	if _, _, err := gotoolprofile.BuiltinCandidates(root, plan.SDK["GOVERSION"]); err != nil {
		return fmt.Errorf("direct asmdecl actual SDK experiment registration: %w", err)
	}
	toolDir, err := directAsmDeclPhysicalDirectory(plan.SDK["GOTOOLDIR"])
	if err != nil {
		return err
	}
	if !strings.HasPrefix(toolDir, root+string(filepath.Separator)) {
		return fmt.Errorf("actual direct asmdecl tool directory escapes GOROOT")
	}
	unitSource := filepath.Join(root, "src", "cmd", "vendor", "golang.org", "x", "tools", "go", "analysis", "unitchecker", "unitchecker.go")
	if err := directAsmDeclValidateConfigRegistration(unitSource, plan.Minor); err != nil {
		return err
	}
	asmSource := filepath.Join(root, "src", "cmd", "vendor", "golang.org", "x", "tools", "go", "analysis", "passes", "asmdecl", "asmdecl.go")
	file, err := directAsmDeclParseSDKSource(asmSource)
	if err != nil {
		return err
	}
	registration := false
	ast.Inspect(file, func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || value.Names[0].Name != "Analyzer" || len(value.Values) != 1 {
			return true
		}
		unary, ok := value.Values[0].(*ast.UnaryExpr)
		if !ok {
			return false
		}
		literal, ok := unary.X.(*ast.CompositeLit)
		if !ok {
			return false
		}
		registration = true
		nameBound, runBound := false, false
		for _, field := range literal.Elts {
			pair, ok := field.(*ast.KeyValueExpr)
			if !ok {
				registration = false
				break
			}
			key, ok := pair.Key.(*ast.Ident)
			if !ok || key.Name == "Requires" || key.Name == "FactTypes" {
				registration = false
				break
			}
			switch key.Name {
			case "Name":
				literal, ok := pair.Value.(*ast.BasicLit)
				nameBound = ok && literal.Kind == token.STRING && literal.Value == `"asmdecl"`
			case "Run":
				function, ok := pair.Value.(*ast.Ident)
				runBound = ok && function.Name == "run"
			case "Doc", "URL":
			default:
				registration = false
			}
		}
		registration = registration && nameBound && runBound
		return false
	})
	if !registration {
		return fmt.Errorf("actual asmdecl factless analyzer registration is unclosed")
	}
	files := []string{plan.GoBinary, filepath.Join(root, "VERSION"), unitSource, asmSource}
	for _, relative := range []string{"internal/buildcfg/cfg.go", "internal/buildcfg/exp.go", "internal/goexperiment/flags.go", "cmd/internal/objabi/flag.go"} {
		files = append(files, filepath.Join(root, "src", filepath.FromSlash(relative)))
	}
	for _, name := range []string{"vet", "compile", "asm"} {
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		files = append(files, filepath.Join(toolDir, name))
	}
	for _, name := range []string{"textflag.h", "funcdata.h", "asm_amd64.h"} {
		files = append(files, filepath.Join(root, "pkg", "include", name))
	}
	for _, relative := range []string{"cmd/go/internal/work/exec.go", "cmd/go/internal/work/action.go", "cmd/go/internal/list/list.go", "cmd/go/internal/load/test.go", "cmd/go/internal/load/pkg.go", "cmd/go/internal/modfetch/fetch.go", "cmd/vet/main.go", "go/internal/gcimporter/gcimporter.go"} {
		files = append(files, filepath.Join(root, "src", filepath.FromSlash(relative)))
	}
	for _, file := range files {
		if err := plan.bindFile(file); err != nil {
			return err
		}
	}
	return nil
}

func (plan *directAsmDeclPlan) observeToolVersions(ctx context.Context) (map[string]string, error) {
	versions := make(map[string]string)
	names, err := directAsmDeclExperimentOrder(filepath.Join(plan.SDK["GOROOT"], "src", "internal", "goexperiment", "flags.go"))
	if err != nil {
		return nil, err
	}
	var actualExperiments string
	for _, tool := range []string{"vet", "compile", "asm"} {
		output, err := directAsmDeclCommandJSON(ctx, plan.Dir, plan.Env, plan.GoBinary, "tool", tool, "-V=full")
		if err != nil {
			return nil, err
		}
		version := strings.TrimSpace(string(output))
		experiments, err := directAsmDeclToolVersionExperiments(version, tool, plan.SDK["GOVERSION"], names)
		if err != nil {
			return nil, err
		}
		if tool == "vet" {
			actualExperiments = experiments
		} else if experiments != actualExperiments {
			return nil, fmt.Errorf("direct asmdecl actual SDK tools have different experiment identities")
		}
		versions[tool] = version
	}
	return versions, nil
}

func directAsmDeclValidateConfigRegistration(path string, minor int) error {
	file, err := directAsmDeclParseSDKSource(path)
	if err != nil {
		return err
	}
	actual := make(map[string]string)
	duplicate := false
	ast.Inspect(file, func(node ast.Node) bool {
		typeSpec, ok := node.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != "Config" {
			return true
		}
		structure, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, field := range structure.Fields.List {
			var expression bytes.Buffer
			if err := format.Node(&expression, token.NewFileSet(), field.Type); err != nil {
				return false
			}
			for _, name := range field.Names {
				if _, found := actual[name.Name]; found {
					duplicate = true
				}
				actual[name.Name] = expression.String()
			}
		}
		return false
	})
	expected := map[string]string{
		"ID":                        "string",
		"Compiler":                  "string",
		"Dir":                       "string",
		"ImportPath":                "string",
		"GoFiles":                   "[]string",
		"NonGoFiles":                "[]string",
		"IgnoredFiles":              "[]string",
		"ImportMap":                 "map[string]string",
		"PackageFile":               "map[string]string",
		"Standard":                  "map[string]bool",
		"PackageVetx":               "map[string]string",
		"VetxOnly":                  "bool",
		"VetxOutput":                "string",
		"SucceedOnTypecheckFailure": "bool",
	}
	if minor >= 21 {
		expected["GoVersion"] = "string"
	}
	if minor >= 24 {
		expected["ModulePath"], expected["ModuleVersion"] = "string", "string"
	}
	if minor >= 26 {
		expected["Stdout"], expected["FixArchive"] = "string", "string"
	}
	if minor >= 27 {
		expected["Module"] = "*analysis.Module"
	}
	if duplicate || !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("unregistered actual Go vet Config fields: %v", actual)
	}
	return nil
}

func directAsmDeclParseSDKSource(path string) (*ast.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, directAsmDeclSDKSourceLimit+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if len(data) > directAsmDeclSDKSourceLimit {
		return nil, fmt.Errorf("direct asmdecl registered SDK source exceeds %d bytes", directAsmDeclSDKSourceLimit)
	}
	return parser.ParseFile(token.NewFileSet(), path, data, 0)
}

// This uses the same owned command lifecycle, deadline and output limit as
// the existing capture helper, but download stderr cannot enter JSON stdout.
func directAsmDeclCommandJSON(ctx context.Context, dir string, env []string, binary string, args ...string) ([]byte, error) {
	stage, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(stage, binary, args...)
	cmd.Dir, cmd.Env, cmd.WaitDelay = dir, env, 2*time.Second
	var stdout, stderr boundedDiscoveryCommandOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := runDiscoveryCommand(cmd)
	if stage.Err() != nil {
		return nil, fmt.Errorf("direct asmdecl JSON command: %w", stage.Err())
	}
	if stdout.truncated || stderr.truncated || len(stdout.Bytes())+len(stderr.Bytes()) > discoveryCommandOutputLimit {
		return nil, fmt.Errorf("direct asmdecl JSON command: %w", errDiscoveryCommandOutputExceeded)
	}
	if err != nil {
		physical, pathErr := directAsmDeclPhysicalDirectory(dir)
		if pathErr != nil {
			return nil, errors.Join(err, pathErr)
		}
		message := string(stderr.Bytes()) + string(stdout.Bytes())
		return nil, &discoveryCapturedCommandError{command: strings.Join(append([]string{binary}, args...), " "), cause: err, output: message, display: message, directory: physical}
	}
	// Successful cmd/go JSON may have ordinary module resolver/download
	// notices on stderr. They are not analysis output or analysis authority.
	// They are not JSON and must not be discarded as arbitrary warnings.
	// Only the registered modfetch formatting is allowed; local toolchain
	// routing cannot legitimately produce a toolchain-download notice.
	if err := directAsmDeclValidateSuccessfulStderr(args, stderr.String()); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

func directAsmDeclValidateSuccessfulStderr(args []string, stderr string) error {
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(args) == 0 || args[0] != "list" || len(fields) == 0 || fields[0] != "go:" || line != strings.Join(fields, " ") {
			return fmt.Errorf("direct asmdecl command returned unregistered successful stderr: %s", stderr)
		}
		switch {
		case len(fields) == 4 && fields[1] == "downloading":
			if fields[2] == "golang.org/toolchain" || module.Check(fields[2], fields[3]) != nil {
				return fmt.Errorf("direct asmdecl download notice has invalid identity: %s", line)
			}
		case len(fields) == 6 && strings.Join(fields[1:5], " ") == "finding module for package":
			if fields[5] == "golang.org/toolchain" || module.CheckImportPath(fields[5]) != nil {
				return fmt.Errorf("direct asmdecl resolver notice has invalid package identity: %s", line)
			}
		case len(fields) == 6 && fields[1] == "found" && fields[3] == "in":
			packagePath, modulePath, version := fields[2], fields[4], fields[5]
			if modulePath == "golang.org/toolchain" || module.CheckImportPath(packagePath) != nil ||
				module.Check(modulePath, version) != nil ||
				packagePath != modulePath && !strings.HasPrefix(packagePath, modulePath+"/") {
				return fmt.Errorf("direct asmdecl resolved package/module/version identity is invalid: %s", line)
			}
		default:
			return fmt.Errorf("direct asmdecl command returned unregistered successful stderr: %s", stderr)
		}
	}
	return nil
}
