package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Keep directory/hash lookup linear in the captured inventory. A scan of
// every directory for each source is quadratic before any Go/profile replay.
func TestOrdinarySelectionSourceHashesDoNotRescanDirectories(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "ordinary_selection.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "ordinarySelectionBytes" {
			continue
		}
		found = true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			outer, ok := node.(*ast.RangeStmt)
			if !ok || !ordinarySelectionRangeField(outer, "Sources") {
				return true
			}
			ast.Inspect(outer.Body, func(node ast.Node) bool {
				inner, ok := node.(*ast.RangeStmt)
				if ok && ordinarySelectionRangeField(inner, "Directories") {
					t.Error("source hash validation rescans the complete directory inventory per source")
				}
				return true
			})
			return false
		})
	}
	if !found {
		t.Fatal("missing ordinarySelectionBytes validation consumer")
	}
}

func ordinarySelectionRangeField(loop *ast.RangeStmt, field string) bool {
	selector, ok := loop.X.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == field
}

func ordinarySelectionIndexedFixture(directories, files int) *discoveryOrdinarySelectionPlan {
	plan := &discoveryOrdinarySelectionPlan{}
	for directory := 0; directory < directories; directory++ {
		dir := ordinarySelectionDirectory{Directory: fmt.Sprintf("pkg%04d", directory)}
		for index := 0; index < files; index++ {
			name := fmt.Sprintf("decl%04d.go", index)
			header := fmt.Sprintf("// package input %d/%d\npackage fixture\n", directory, index)
			hash := fmt.Sprintf("%x", sha256.Sum256([]byte(header)))
			dir.Entries = append(dir.Entries, ordinarySelectionEntry{Name: name, Kind: "file", SHA256: hash})
			plan.Sources = append(plan.Sources, ordinarySelectionSource{
				File: dir.Directory + "/" + name, Header: header, SHA256: hash, HeaderSHA256: hash,
			})
		}
		plan.Directories = append(plan.Directories, dir)
	}
	return plan
}

func TestOrdinarySelectionIndexedHashesRetainExactBindings(t *testing.T) {
	plan := ordinarySelectionIndexedFixture(16, 8)
	sources, directories, err := ordinarySelectionBytes(plan)
	if err != nil || len(sources) != 128 || len(directories) != 16 {
		t.Fatalf("complete source/directory denominator: %d/%d/%v", len(sources), len(directories), err)
	}
	for _, source := range plan.Sources {
		if !bytes.Equal(sources[source.File], []byte(source.Header)) {
			t.Fatalf("source header changed: %s", source.File)
		}
	}
	for _, mutation := range []string{"source SHA", "directory SHA", "header SHA", "entry kind", "duplicate directory", "package diagnostic"} {
		t.Run(mutation, func(t *testing.T) {
			input := ordinarySelectionIndexedFixture(16, 8)
			switch mutation {
			case "source SHA":
				input.Sources[0].SHA256 = strings.Repeat("1", 64)
			case "directory SHA":
				input.Directories[0].Entries[0].SHA256 = strings.Repeat("1", 64)
			case "header SHA":
				input.Sources[0].HeaderSHA256 = strings.Repeat("1", 64)
			case "entry kind":
				input.Directories[0].Entries[0].Kind = "directory"
				input.Directories[0].Entries[0].SHA256 = ""
			case "duplicate directory":
				input.Directories = append(input.Directories, input.Directories[0])
			case "package diagnostic":
				input.Sources[0].PackageDiagnostic = "invented original Go diagnostic"
			}
			if sources, directories, err := ordinarySelectionBytes(input); err == nil || sources != nil || directories != nil {
				t.Fatalf("changed binding returned a partial usable inventory: %v", err)
			}
		})
	}
}

func BenchmarkOrdinarySelectionBytesIndexedInputs(b *testing.B) {
	for _, directories := range []int{128, 512, 2048} {
		b.Run(fmt.Sprintf("directories%d", directories), func(b *testing.B) {
			plan := ordinarySelectionIndexedFixture(directories, 8)
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if _, _, err := ordinarySelectionBytes(plan); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
