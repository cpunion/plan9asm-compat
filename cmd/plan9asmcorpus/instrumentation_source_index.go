package main

import (
	"fmt"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// This index lives for exactly one denominator replay. It contains only
// copied source predicates, never actual selection/export/consumer evidence.
// Constraints and package clauses stay lazy: an ignored or filename-impossible
// source must not acquire an error that the original planner never requested.
type discoveryInstrumentationSourceIndex struct {
	contents    map[string]string
	directories map[string]*discoveryInstrumentationDirectoryIndex
	nested      map[string]bool
	expressions map[string]discoveryInstrumentationExpression
	clauses     map[string]bool
}

type discoveryInstrumentationDirectoryIndex struct {
	files      []string
	partners   []string
	parsed     bool
	eligible   bool
	classified bool
}

type discoveryInstrumentationExpression struct {
	expression constraint.Expr
	err        error
}

func newDiscoveryInstrumentationSourceIndex(plan *discoveryOrdinarySelectionPlan, files []string) (*discoveryInstrumentationSourceIndex, error) {
	index := &discoveryInstrumentationSourceIndex{
		contents:    make(map[string]string, len(plan.Sources)),
		directories: make(map[string]*discoveryInstrumentationDirectoryIndex),
		nested:      make(map[string]bool), expressions: make(map[string]discoveryInstrumentationExpression),
		clauses: make(map[string]bool),
	}
	for _, file := range files {
		dir := path.Dir(file)
		if index.directories[dir] == nil {
			index.directories[dir] = &discoveryInstrumentationDirectoryIndex{}
		}
	}
	for _, source := range plan.Sources {
		if _, duplicate := index.contents[source.File]; duplicate {
			return nil, fmt.Errorf("duplicate mode selection source")
		}
		index.contents[source.File] = source.Header
		if directory := index.directories[path.Dir(source.File)]; directory != nil {
			directory.files = append(directory.files, source.File)
		}
	}
	for _, directory := range plan.Directories {
		for _, entry := range directory.Entries {
			if entry.Name == "go.mod" && entry.Kind == "file" {
				index.nested[directory.Directory] = true
			}
		}
	}
	return index, nil
}

func (index *discoveryInstrumentationSourceIndex) open(file string) (io.ReadCloser, error) {
	source, found := index.contents[filepath.ToSlash(file)]
	if !found {
		return nil, fmt.Errorf("uncaptured original mode source: %s", file)
	}
	return io.NopCloser(strings.NewReader(source)), nil
}

func (index *discoveryInstrumentationSourceIndex) expression(file string) (constraint.Expr, error) {
	key := filepath.ToSlash(file)
	if result, found := index.expressions[key]; found {
		return result.expression, result.err
	}
	expression, err := discoveryFileBuildExpression(file, index.open)
	index.expressions[key] = discoveryInstrumentationExpression{expression: expression, err: err}
	return expression, err
}

func (index *discoveryInstrumentationSourceIndex) directoryEligible(module, dir string) bool {
	directory := index.directories[dir]
	if !directory.classified {
		directory.classified = true
		directory.eligible = !discoveryDirIsIgnored(dir) && ordinarySelectionPackagePathError(module, dir) == nil
		for ancestor := dir; directory.eligible && ancestor != "."; ancestor = path.Dir(ancestor) {
			if index.nested[ancestor] {
				directory.eligible = false
			}
		}
	}
	return directory.eligible
}

func (index *discoveryInstrumentationSourceIndex) goPartners(dir string) []string {
	directory := index.directories[dir]
	if !directory.parsed {
		directory.parsed = true
		for _, name := range directory.files {
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasPrefix(path.Base(name), ".") || strings.HasPrefix(path.Base(name), "_") {
				continue
			}
			valid, known := index.clauses[name]
			if !known {
				_, err := parser.ParseFile(token.NewFileSet(), name, index.contents[name], parser.PackageClauseOnly)
				valid = err == nil
				index.clauses[name] = valid
			}
			if valid {
				directory.partners = append(directory.partners, name)
			}
		}
		sort.Strings(directory.partners)
	}
	return directory.partners
}

func (index *discoveryInstrumentationSourceIndex) pairTags(files ...string) (map[string]bool, bool, error) {
	all := make(map[string]bool)
	for _, file := range files {
		expression, err := index.expression(filepath.FromSlash(file))
		if err != nil {
			return nil, false, err
		}
		if expression != nil {
			collectDiscoveryConstraintTags(expression, all)
		}
	}
	return all, all["cgo"], nil
}
