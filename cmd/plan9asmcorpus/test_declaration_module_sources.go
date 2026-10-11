package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/mod/module"
)

type discoverySelectedTestModule struct {
	Path, Version, Dir, GoMod string
	Main                      bool
	Replace                   *discoverySelectedTestModule
}

type discoverySelectedTestPackage struct {
	ImportPath, Name, ForTest, Dir, Export    string
	Standard                                  bool
	GoFiles, CompiledGoFiles, SFiles, Imports []string
	EmbedFiles, EmbedPatterns                 []string
	ImportMap                                 map[string]string
	Module                                    *discoverySelectedTestModule
	Error                                     *struct{ Err string }
	DepsErrors                                []struct{ Err string }
}

// This decision uses actual Go module ownership, not package-name prefixes.
// A local/unknown replacement cannot acquire the original ZIP source role.
func discoveryTestPackageSourceRole(actual discoverySelectedTestPackage, input *gotoolprofile.ConsumerInput,
	original gotoolprofile.PackageProof, mainRoot, goRoot string,
) (gotoolprofile.PackageProof, string, error) {
	packagePath, _, _ := strings.Cut(actual.ImportPath, " [")
	pkg := gotoolprofile.PackageProof{PackagePath: packagePath, SourceSHA256: make(map[string]string)}
	if actual.Module == nil {
		if !actual.Standard || strings.Contains(strings.Split(packagePath, "/")[0], ".") {
			return pkg, "", fmt.Errorf("test dependency lacks actual stdlib/Module source ownership")
		}
		pkg.SourceRole = "stdlib"
		return pkg, filepath.Join(goRoot, "src"), nil
	}
	metadata := actual.Module
	if module.Check(metadata.Path, metadata.Version) != nil ||
		packagePath != metadata.Path && !strings.HasPrefix(packagePath, metadata.Path+"/") {
		return pkg, "", fmt.Errorf("test dependency package has a different actual versioned module owner")
	}
	root, err := filepath.EvalSymlinks(metadata.Dir)
	if err != nil || !filepath.IsAbs(root) {
		return pkg, "", fmt.Errorf("test dependency has an inaccessible actual module directory: %v", err)
	}
	pkg.ModulePath, pkg.ModuleVersion = metadata.Path, metadata.Version
	pkg.SourceModule, pkg.SourceVersion, pkg.SourceRole = metadata.Path, metadata.Version, "module"
	if metadata.Replace != nil {
		if module.Check(metadata.Replace.Path, metadata.Replace.Version) != nil {
			return pkg, "", fmt.Errorf("test dependency has an unsupported local/unknown replacement")
		}
		replacedRoot, err := filepath.EvalSymlinks(metadata.Replace.Dir)
		if err != nil || replacedRoot != root {
			return pkg, "", fmt.Errorf("test dependency replacement differs from actual module source root")
		}
		pkg.SourceModule, pkg.SourceVersion, pkg.SourceRole = metadata.Replace.Path, metadata.Replace.Version, "version_replace"
	}
	if metadata.Main {
		return pkg, "", fmt.Errorf("test dependency lacks exact versioned module ownership")
	}
	if root == mainRoot {
		if pkg.ModulePath != input.Module || pkg.ModuleVersion != input.Version ||
			pkg.SourceModule != original.SourceModule || pkg.SourceVersion != original.SourceVersion || pkg.SourceRole != original.SourceRole {
			return pkg, "", fmt.Errorf("test dependency changed the actual original Module/Replace source role")
		}
		pkg.GoModOrigin, pkg.GoModSHA256, pkg.GoModSum = original.GoModOrigin, original.GoModSHA256, original.GoModSum
	} else if pkg.ModulePath == input.Module {
		return pkg, "", fmt.Errorf("test dependency reused candidate identity at a different actual source root")
	}
	return pkg, root, nil
}

type discoveryTestModuleCapture struct {
	Root      string
	Download  moduleDownloadInfo
	Plan      *discoveryOrdinarySelectionPlan
	GoVersion string
	Exports   map[string]string
	Metadata  map[string]string
}

func captureDiscoveryForeignTestDirectory(ctx context.Context, captures map[string]*discoveryTestModuleCapture,
	actual discoverySelectedTestPackage, pkg gotoolprofile.PackageProof, root, goVersion, dir string, env []string,
) (string, string, error) {
	id := pkg.SourceModule + "@" + pkg.SourceVersion
	if pkg.SourceRole == "stdlib" {
		id = "stdlib@" + goVersion
	}
	capture := captures[id]
	if capture == nil {
		capture = &discoveryTestModuleCapture{
			Root: root, GoVersion: goVersion,
			Plan:     &discoveryOrdinarySelectionPlan{Module: pkg.SourceModule, Version: pkg.SourceVersion},
			Exports:  make(map[string]string),
			Metadata: make(map[string]string),
		}
		if pkg.SourceRole != "stdlib" {
			data, _, err := runDiscoveryMachineCommand(ctx, dir, env, "go", "mod", "download", "-json", id)
			if err != nil {
				return "", "", err
			}
			if err := json.Unmarshal(data, &capture.Download); err != nil || capture.Download.Error != "" ||
				capture.Download.Path != pkg.SourceModule || capture.Download.Version != pkg.SourceVersion ||
				capture.Download.Sum == "" || capture.Download.GoModSum == "" {
				return "", "", fmt.Errorf("test dependency lacks actual exact authenticated Go download: %v", err)
			}
			downloadRoot, err := filepath.EvalSymlinks(capture.Download.Dir)
			if err != nil || downloadRoot != root {
				return "", "", fmt.Errorf("test dependency source root differs from actual exact Go download")
			}
			metadata := actual.Module.GoMod
			if actual.Module.Replace != nil {
				metadata = actual.Module.Replace.GoMod
			}
			actualMod, err := discoveryFeatureFileSHA256(metadata)
			proxyMod, proxyErr := discoveryFeatureFileSHA256(capture.Download.GoMod)
			if err != nil || proxyErr != nil || actualMod != proxyMod {
				return "", "", fmt.Errorf("test dependency actual Go metadata differs from exact proxy go.mod")
			}
			capture.Metadata[metadata], capture.Metadata[capture.Download.GoMod] = actualMod, proxyMod
		}
		captures[id] = capture
	} else if capture.Root != root {
		return "", "", fmt.Errorf("test dependency repeated source identity at different roots")
	}
	if err := captureDiscoveryTestSourceDirectory(capture.Plan, root, actual.Dir); err != nil {
		return "", "", err
	}
	if err := captureDiscoveryTestModuleGoMod(ctx, capture, dir, env); err != nil {
		return "", "", err
	}
	if pkg.SourceRole != "stdlib" {
		metadata := actual.Module.GoMod
		if actual.Module.Replace != nil {
			metadata = actual.Module.Replace.GoMod
		}
		digest, err := discoveryFeatureFileSHA256(metadata)
		if err != nil || digest != capture.Metadata[capture.Download.GoMod] {
			return "", "", fmt.Errorf("test dependency actual metadata changed or disappeared during capture")
		}
		capture.Metadata[metadata] = digest
	}
	if actual.ImportPath == "unsafe" {
		if actual.Name != "unsafe" || actual.Module != nil || actual.Export != "" || len(actual.CompiledGoFiles) != 0 ||
			len(actual.SFiles) != 0 || len(actual.Imports) != 0 || len(actual.GoFiles) != 1 || actual.GoFiles[0] != "unsafe.go" ||
			filepath.Clean(actual.Dir) != filepath.Join(root, "unsafe") {
			return "", "", fmt.Errorf("test dependency changed actual Go unsafe builtin/documentation selection")
		}
		return id, "", nil
	}
	export, err := discoveryFeatureFileSHA256(actual.Export)
	if err != nil {
		return "", "", fmt.Errorf("test dependency lacks its actual same-profile export: %w", err)
	}
	if prior, exists := capture.Exports[actual.Export]; exists && prior != export {
		return "", "", fmt.Errorf("test dependency actual export bytes changed during capture")
	}
	capture.Exports[actual.Export] = export
	return id, export, nil
}

func discoveryTestModuleSnapshot(capture *discoveryTestModuleCapture) (gotoolprofile.TestModuleSource, error) {
	return discoveryTestModuleSnapshotWithZIPHash(capture, discoveryFeatureFileSHA256)
}

func discoveryTestModuleSnapshotWithZIPHash(capture *discoveryTestModuleCapture,
	zipHash func(string) (string, error),
) (gotoolprofile.TestModuleSource, error) {
	result := gotoolprofile.TestModuleSource{
		Protocol:     gotoolprofile.TestDependencyModuleProtocol,
		SourceModule: capture.Plan.Module, SourceVersion: capture.Plan.Version,
		Sources: make(map[string]string), Headers: make(map[string]string),
		Directories: make(map[string][]gotoolprofile.TestSourceEntry),
	}
	for _, dir := range capture.Plan.TestDeclarationDirectories {
		result.Directories[dir.Directory] = []gotoolprofile.TestSourceEntry{}
		for _, entry := range dir.Entries {
			result.Directories[dir.Directory] = append(result.Directories[dir.Directory], gotoolprofile.TestSourceEntry{
				Name: entry.Name, Kind: entry.Kind, SHA256: entry.SHA256,
			})
			if entry.Kind == "file" {
				result.Sources[path.Join(dir.Directory, entry.Name)] = entry.SHA256
			}
		}
	}
	for _, source := range capture.Plan.TestDeclarationSources {
		result.Headers[source.File] = source.Header
	}
	if capture.Plan.Module == "" {
		result.GoVersion = capture.GoVersion
	} else {
		result.ModuleSum, result.GoModSum = capture.Download.Sum, capture.Download.GoModSum
		result.GoModSHA256 = result.Sources["go.mod"]
		result.GoModOrigin = gotoolprofile.TestModuleOriginalGoModOrigin
		if proxy := capture.Plan.ProxyGoMod; proxy != nil {
			result.GoModOrigin, result.GoModSHA256 = proxy.Protocol, proxy.SHA256
			result.ProxyGoMod = proxy
		}
		var err error
		result.ZipSHA256, err = zipHash(capture.Download.Zip)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func verifyDiscoveryForeignTestSnapshots(ctx context.Context, dependency *gotoolprofile.TestDependencyProof,
	captures map[string]*discoveryTestModuleCapture,
) error {
	return verifyDiscoveryForeignTestSnapshotsWithGuard(ctx, dependency, captures, newDiscoveryTestSnapshotGuard())
}

func verifyDiscoveryForeignTestSnapshotsWithGuard(ctx context.Context, dependency *gotoolprofile.TestDependencyProof,
	captures map[string]*discoveryTestModuleCapture, guard *discoveryTestSnapshotGuard,
) error {
	for _, source := range dependency.SourceModules {
		capture := captures[source.ID()]
		if capture == nil {
			return fmt.Errorf("test dependency source-root inventory was not actually captured")
		}
		if err := guard.verify(ctx, source, capture); err != nil {
			return err
		}
		proxyPlan := discoveryTestModuleProxyPlan(capture)
		if err := verifyDiscoveryProxyGoMod(&proxyPlan); err != nil {
			return fmt.Errorf("final test dependency metadata %s: %w", source.ID(), err)
		}
		if source.SourceModule != "" {
			for filename := range capture.Metadata {
				if err := gotoolprofile.VerifyTestModuleGoModMetadata(source, capture.Root, filename, capture.Download.GoMod); err != nil {
					return fmt.Errorf("final test dependency metadata %s: %w", source.ID(), err)
				}
			}
		}
		for filename, wanted := range capture.Exports {
			actual, err := discoveryFeatureFileSHA256(filename)
			if err != nil || actual != wanted {
				return fmt.Errorf("test dependency actual export bytes changed before final objects")
			}
		}
		for filename, wanted := range capture.Metadata {
			actual, err := discoveryFeatureFileSHA256(filename)
			if err != nil || actual != wanted {
				return fmt.Errorf("test dependency actual/proxy GoMod bytes changed before final objects")
			}
		}
	}
	return nil
}
