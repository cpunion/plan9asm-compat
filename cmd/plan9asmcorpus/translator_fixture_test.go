package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// First-party producer fixtures build the real translator from its separate
// checkout. This is not a download of an external library under test.
func fixtureTranslatorRoot() (string, error) {
	root := os.Getenv("PLAN9ASM_TRANSLATOR_ROOT")
	if root == "" {
		root = filepath.Join("..", "..", "_out", "translator")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(root, "cmd", "plan9asmll", "go.mod")); err != nil {
		return "", fmt.Errorf("prepare the pinned translator checkout before producer tests: %w", err)
	}
	return root, nil
}
