package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func transferCursorRecords() []shardedRecord {
	var modules []string
	for i := 0; len(modules) < 3; i++ {
		module := fmt.Sprintf("example.com/cursor/%08d", i)
		if sha256.Sum256([]byte(module))[0] == 0x80 {
			modules = append(modules, module)
		}
	}
	return []shardedRecord{
		{Kind: "failure", Module: modules[0], Version: "v1.0.0", Error: strings.Repeat("源😀", 20000)},
		{Kind: "failure", Module: modules[0], Version: "v1.0.1", Error: "second version"},
		{Kind: "matched", Module: modules[1], Version: "v1.0.0", AsmFiles: []string{strings.Repeat("文件", 20000) + ".s"}, Architectures: []string{"amd64"}},
		{Kind: "scanned", Module: modules[2], Version: "v1.0.0"},
	}
}

func TestDiscoveryTransferCursorExactByteOffsets(t *testing.T) {
	for _, name := range []string{"lf", "crlf", "unterminated", "final-cr"} {
		t.Run(name, func(t *testing.T) {
			records := transferCursorRecords()
			newline := []byte("\n")
			if name == "crlf" {
				newline = []byte("\r\n")
			}
			var data []byte
			starts := make([]int64, len(records))
			for i, record := range records {
				starts[i] = int64(len(data))
				encoded, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, encoded...)
				if i != len(records)-1 || name != "unterminated" && name != "final-cr" {
					data = append(data, newline...)
				} else if name == "final-cr" {
					data = append(data, '\r')
				}
			}
			path := filepath.Join(t.TempDir(), "80.jsonl")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			var full []shardedRecord
			if _, err := scanRecordShard(path, &ledgerSummary{}, func(record shardedRecord) error {
				full = append(full, record)
				return nil
			}); err != nil || !reflect.DeepEqual(full, records) {
				t.Fatalf("full scanner boundary control: %v", err)
			}
			cursor, err := newTransferModuleCursor(path)
			if err != nil || cursor.offset != 0 || cursor.line != 0 || cursor.module != records[0].Module {
				t.Fatalf("cursor initial boundary: %+v %v", cursor, err)
			}
			for _, boundary := range []struct{ first, end int }{{0, 2}, {2, 3}, {3, 4}} {
				group, err := cursor.readGroup(false)
				if err != nil || group.module != records[boundary.first].Module ||
					!reflect.DeepEqual(publicationRecords(group.report), records[boundary.first:boundary.end]) {
					t.Fatalf("cursor changed complete group %d..%d: %v", boundary.first, boundary.end, err)
				}
				nextModule, offset := "", int64(len(data))
				if boundary.end < len(records) {
					nextModule, offset = records[boundary.end].Module, starts[boundary.end]
				}
				if cursor.module != nextModule || cursor.offset != offset || cursor.line != boundary.end {
					t.Fatalf("byte/line offset mismatch: module=%q offset=%d/%d line=%d/%d",
						cursor.module, cursor.offset, offset, cursor.line, boundary.end)
				}
				if cursor.previous.Error != "" || cursor.previous.AsmFiles != nil || cursor.previous.Architectures != nil {
					t.Fatal("cursor retained previous record payload")
				}
			}
		})
	}
}

func TestDiscoveryTransferCursorSharesCompleteLineRejections(t *testing.T) {
	for _, name := range []string{"blank-middle", "blank-tail", "duplicate", "reversed", "invalid-version", "unknown-kind", "wrong-bucket", "oversized", "malformed-tail"} {
		t.Run(name, func(t *testing.T) {
			records := transferCursorRecords()
			if name == "duplicate" {
				records[1] = records[0]
			} else if name == "reversed" {
				records[0], records[1] = records[1], records[0]
			} else if name == "invalid-version" {
				records[2].Version = "not-semver"
			} else if name == "unknown-kind" {
				records[2].Kind = "unknown"
			} else if name == "wrong-bucket" {
				records[2].Module += "-wrong-bucket"
			} else if name == "oversized" {
				records[2].AsmFiles = []string{strings.Repeat("x", 17<<20)}
			}
			var data bytes.Buffer
			for i, record := range records {
				if err := json.NewEncoder(&data).Encode(record); err != nil {
					t.Fatal(err)
				}
				if name == "blank-middle" && i == 0 {
					data.WriteByte('\n')
				}
			}
			if name == "blank-tail" {
				data.WriteByte('\n')
			} else if name == "malformed-tail" {
				data.WriteString("not JSON\n")
			}
			path := filepath.Join(t.TempDir(), "80.jsonl")
			if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			_, fullErr := scanRecordShard(path, &ledgerSummary{}, nil)
			if fullErr == nil {
				t.Fatal("invalid whole-scanner fixture unexpectedly accepted")
			}
			cursor, cursorErr := newTransferModuleCursor(path)
			for cursorErr == nil && cursor.module != "" {
				_, cursorErr = cursor.readGroup(false)
			}
			if cursorErr == nil || cursorErr.Error() != fullErr.Error() {
				t.Fatalf("cursor weakened full line rule: cursor=%v full=%v", cursorErr, fullErr)
			}
		})
	}
}

func TestDiscoveryTransferCursorDoesNotRetainOpenReaders(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "streaming_transfer_cursor.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	readers, closes := 0, 0
	ast.Inspect(file, func(node ast.Node) bool {
		if declaration, ok := node.(*ast.FuncDecl); ok && declaration.Name.Name == "readGroup" {
			readers++
			ast.Inspect(declaration.Body, func(node ast.Node) bool {
				if statement, ok := node.(*ast.DeferStmt); ok {
					ast.Inspect(statement.Call, func(node ast.Node) bool {
						if call, ok := node.(*ast.CallExpr); ok {
							if method, ok := call.Fun.(*ast.SelectorExpr); ok && method.Sel.Name == "Close" {
								if name, ok := method.X.(*ast.Ident); ok && name.Name == "file" {
									closes++
								}
							}
						}
						return true
					})
				}
				if _, ok := node.(*ast.GoStmt); ok {
					t.Error("cursor launched unjoined asynchronous reader")
				}
				return true
			})
		}
		return true
	})
	if readers != 1 || closes != 1 {
		t.Fatalf("cursor must close one local reader on every return: readers=%d closes=%d", readers, closes)
	}
}
