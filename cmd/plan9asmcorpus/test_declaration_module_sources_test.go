package main

import (
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestTestDeclarationActualModuleOwnershipNotImportPrefix(t *testing.T) {
	canonical := func() string {
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return dir
	}
	mainRoot, externalRoot, goRoot := canonical(), canonical(), canonical()
	input := &gotoolprofile.ConsumerInput{Module: "example.invalid/parent", Version: "v1.0.0"}
	original := gotoolprofile.PackageProof{
		SourceModule: input.Module, SourceVersion: input.Version, SourceRole: "module",
	}
	for name, metadata := range map[string]*discoverySelectedTestModule{
		"original module":                {Path: input.Module, Version: input.Version, Dir: mainRoot},
		"same-prefix independent module": {Path: input.Module + "/loader", Version: "v0.5.2", Dir: externalRoot},
		"unrelated module":               {Path: "example.invalid/foreign", Version: "v1.0.0", Dir: externalRoot},
		"actual version replacement": {
			Path: "example.invalid/foreign", Version: "v1.0.0", Dir: externalRoot,
			Replace: &discoverySelectedTestModule{Path: "example.invalid/fork", Version: "v1.0.1", Dir: externalRoot},
		},
	} {
		t.Run(name, func(t *testing.T) {
			actual := discoverySelectedTestPackage{ImportPath: metadata.Path + "/child", Module: metadata}
			proof, root, err := discoveryTestPackageSourceRole(actual, input, original, mainRoot, goRoot)
			if err != nil || root != metadata.Dir || proof.ModulePath != metadata.Path || proof.ModuleVersion != metadata.Version {
				t.Fatalf("actual Module/Dir selection was replaced with a path heuristic: %#v, %s, %v", proof, root, err)
			}
			if metadata.Replace != nil && (proof.SourceRole != "version_replace" || proof.SourceModule != metadata.Replace.Path || proof.SourceVersion != metadata.Replace.Version) {
				t.Fatal("actual replacement source was omitted")
			}
		})
	}
	for name, actual := range map[string]discoverySelectedTestPackage{
		"same module different source root": {
			ImportPath: input.Module + "/child",
			Module:     &discoverySelectedTestModule{Path: input.Module, Version: input.Version, Dir: externalRoot},
		},
		"different module uses main root": {
			ImportPath: "example.invalid/foreign",
			Module:     &discoverySelectedTestModule{Path: "example.invalid/foreign", Version: "v1.0.0", Dir: mainRoot},
		},
		"different version": {
			ImportPath: input.Module,
			Module:     &discoverySelectedTestModule{Path: input.Module, Version: "v1.0.1", Dir: mainRoot},
		},
		"module ownership contradicts import": {
			ImportPath: input.Module + "/loader",
			Module:     &discoverySelectedTestModule{Path: "other.invalid/foreign", Version: "v1.0.0", Dir: externalRoot},
		},
		"local replacement": {
			ImportPath: "example.invalid/foreign",
			Module: &discoverySelectedTestModule{
				Path: "example.invalid/foreign", Version: "v1.0.0", Dir: externalRoot,
				Replace: &discoverySelectedTestModule{Path: "../local", Dir: externalRoot},
			},
		},
		"replacement directory mismatch": {
			ImportPath: "example.invalid/foreign",
			Module: &discoverySelectedTestModule{
				Path: "example.invalid/foreign", Version: "v1.0.0", Dir: externalRoot,
				Replace: &discoverySelectedTestModule{Path: "example.invalid/fork", Version: "v1.0.1", Dir: mainRoot},
			},
		},
		"unknown module owner": {ImportPath: "example.invalid/foreign"},
		"stdlib impersonation": {ImportPath: "example.invalid/foreign", Standard: true},
		"unversioned main owner": {
			ImportPath: "example.invalid/foreign",
			Module:     &discoverySelectedTestModule{Path: "example.invalid/foreign", Dir: externalRoot, Main: true},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := discoveryTestPackageSourceRole(actual, input, original, mainRoot, goRoot); err == nil {
				t.Fatal("unknown/replaced/mismatched source acquired actual module authority")
			}
		})
	}
	actual := discoverySelectedTestPackage{ImportPath: "math", Standard: true}
	proof, root, err := discoveryTestPackageSourceRole(actual, input, original, mainRoot, goRoot)
	if err != nil || root != filepath.Join(goRoot, "src") || proof.SourceRole != "stdlib" || proof.ModulePath != "" {
		t.Fatalf("actual stdlib must derive its source root from the actual driver: %#v, %s, %v", proof, root, err)
	}
}

func TestTestDependencyModuleHeaderMatchesExistingCanonicalSource(t *testing.T) {
	for name, text := range map[string]string{
		"simple.go": "package simple\nfunc Body() {}\n",
		"tagged.go": "// license\n//go:build linux && !race\n// +build linux,!race\n\npackage tagged\nimport alias \"example.invalid/dep\"\nvar Body = alias.Value\n",
		"block.go":  "/* original block license\n*/\n\npackage block\nimport (\n \"unsafe\"\n)\nvar _ unsafe.Pointer\n",
		"simple.s":  "// license\n//go:build arm64\n\nTEXT ·probe(SB),$0\nRET\n",
		"block.s":   "/* license\n*/\n\n// +build amd64\n\n#include \"textflag.h\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			legacy, err := nativeLayoutSourceInputFromBytes(name, []byte(text))
			if err != nil {
				t.Fatal(err)
			}
			actual, err := gotoolprofile.TestSelectionHeader(name, []byte(text))
			if err != nil || actual != compactOrdinarySelectionHeader(legacy.Header) {
				t.Fatalf("source-boundary refactor changed original MatchFile/import bytes: %q, %v", actual, err)
			}
		})
	}
}
