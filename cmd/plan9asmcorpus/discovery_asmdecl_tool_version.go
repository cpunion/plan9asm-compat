package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
)

// buildcfg.expList emits differing Flags in their declaration order, adding
// "no" for disabled flags. This is the exact source-bound namespace, not a
// permissive suffix regexp or the translator's own build-time experiments.
func directAsmDeclExperimentOrder(filename string) ([]string, error) {
	file, err := directAsmDeclParseSDKSource(filename)
	if err != nil {
		return nil, err
	}
	var names []string
	flagTypes := 0
	seen := make(map[string]bool)
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.TYPE {
			continue
		}
		for _, spec := range group.Specs {
			typ, ok := spec.(*ast.TypeSpec)
			if !ok || typ.Name.Name != "Flags" {
				continue
			}
			flagTypes++
			fields, ok := typ.Type.(*ast.StructType)
			if !ok || typ.Assign.IsValid() || flagTypes != 1 {
				return nil, fmt.Errorf("direct asmdecl SDK experiment Flags role is unclosed")
			}
			for _, field := range fields.Fields.List {
				kind, ok := field.Type.(*ast.Ident)
				if !ok || kind.Name != "bool" || len(field.Names) != 1 || field.Tag != nil {
					return nil, fmt.Errorf("direct asmdecl SDK experiment field is unclosed")
				}
				name := strings.ToLower(field.Names[0].Name)
				if seen[name] {
					return nil, fmt.Errorf("direct asmdecl SDK experiment field is duplicated")
				}
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("direct asmdecl SDK experiment Flags namespace is missing")
	}
	return names, nil
}

func directAsmDeclToolVersionExperiments(version, tool, sdk string, names []string) (string, error) {
	prefix := tool + " version " + sdk
	fail := func() (string, error) {
		return "", fmt.Errorf("direct asmdecl actual %s version is not the selected SDK/experiment grammar: %q", tool, version)
	}
	if version == prefix {
		return "", nil
	}
	if !strings.HasPrefix(version, prefix+" X:") {
		return fail()
	}
	experiments := strings.TrimPrefix(version, prefix+" X:")
	last := -1
	for _, flag := range strings.Split(experiments, ",") {
		position := -1
		for index, name := range names {
			if flag == name || flag == "no"+name {
				position = index
				break
			}
		}
		if position <= last {
			return fail() // unknown, duplicate, contradictory or noncanonical order
		}
		last = position
	}
	return experiments, nil
}
