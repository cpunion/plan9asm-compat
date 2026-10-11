package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// External production uses current Go only. Its actual compiler fixtures must
// be listed in that lane, not reported as skipped in a historical SDK lane.
// Shared fixtures and portable readers remain untagged and independently run.
func TestCurrentProducerFixturesHaveExplicitBuildRole(t *testing.T) {
	var names = []string{
		"TestOrdinaryProducerActuallyConsumesCPUProfiles",
		"TestOrdinaryProducerZeroByteAssemblySiblingFiveArchitectures",
		"TestOrdinaryProducerNonemptyAssemblySiblingsFiveArchitectures",
		"TestOrdinaryProducerPartialAsmDeclKeepsCompletePackageSelection",
		"TestOrdinaryGeneratedHeaderProducerActualProfilesAndOfflineReplay",
		"TestTestDeclarationDependencyProducerOriginalPureGoClosure",
		"TestTestDeclarationDependencyProducerPureGoAncestors",
		"TestTestDeclarationDependencyProducerNestedModuleBoundary",
		"TestTestDeclarationDependencyProducerZeroAssemblySibling",
		"TestDataOnlySiblingPreservesActualSupplementalDeclarationQuery",
	}
	wanted := make(map[string]int, len(names))
	for _, name := range names {
		wanted[name] = 0
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), data, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if _, selected := wanted[function.Name.Name]; !selected {
				continue
			}
			wanted[function.Name.Name]++
			if !strings.HasPrefix(string(data), "//go:build go1.27\n\n") {
				t.Errorf("%s must have the explicit current-Go compiler build role", function.Name.Name)
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if selector.Sel.Name == "Skip" || selector.Sel.Name == "Skipf" || selector.Sel.Name == "SkipNow" {
					t.Errorf("%s must execute its current-Go assertions, not Skip", function.Name.Name)
				}
				return true
			})
		}
	}
	for name, count := range wanted {
		if count != 1 {
			t.Errorf("current compiler fixture %s has %d definitions; want exactly one", name, count)
		}
	}
}
