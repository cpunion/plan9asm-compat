package main

import (
	"go/ast"
	"go/token"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

type discoveryAssemblerMacros = gotoolprofile.AssemblerMacros

func captureDiscoveryAssemblerMacros(root string, observed *discoveryTargetFeatures, packagePath string) (*discoveryAssemblerMacros, error) {
	return gotoolprofile.CaptureAssemblerMacros(root, observed, packagePath)
}

func discoveryAssemblerASTSHA(fset *token.FileSet, node ast.Node) (string, error) {
	return gotoolprofile.ASTSHA(fset, node)
}
