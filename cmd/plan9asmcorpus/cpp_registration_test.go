package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCPPRegistrationBindsActualGoDirectiveAndIdentifierNamespaces(t *testing.T) {
	proof, err := captureDiscoveryCPPRegistration(runtime.GOROOT(), runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDiscoveryCPPRegistration(proof, runtime.Version()); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ file, from, to string }{
		{"VERSION", runtime.Version(), "go1.99.1"},
		{"src/cmd/asm/internal/lex/input.go", "case \"ifdef\":", "case \"different\":"},
		{"src/cmd/asm/internal/lex/tokenizer.go", "unicode.IsLetter(ch)", "unicode.IsDigit(ch)"},
	} {
		t.Run(mutation.file, func(t *testing.T) {
			root := t.TempDir()
			for file := range proof.ToolSourceSHA256 {
				data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), filepath.FromSlash(file)))
				if err != nil {
					t.Fatal(err)
				}
				if file == mutation.file {
					changed := strings.Replace(string(data), mutation.from, mutation.to, 1)
					if changed == string(data) {
						t.Fatal("source mutation was not exercised")
					}
					data = []byte(changed)
				}
				name := filepath.Join(root, filepath.FromSlash(file))
				if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, name, string(data))
			}
			if _, err := captureDiscoveryCPPRegistration(root, runtime.Version()); err == nil {
				t.Fatal("changed CPP source registration was accepted")
			}
		})
	}
}
