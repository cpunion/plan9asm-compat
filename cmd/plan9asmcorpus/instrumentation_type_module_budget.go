package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Account before the shared directory capture allocates source text. A new
// module does not receive a fresh per-module entry or original-byte allowance.
type discoveryInstrumentationTypeBudget struct {
	directories map[string]bool
	entries     int
	bytes       int64
}

func (budget *discoveryInstrumentationTypeBudget) check(root, directory string) error {
	directory, err := filepath.EvalSymlinks(directory)
	rel, relErr := filepath.Rel(root, directory)
	if err != nil || relErr != nil || !filepath.IsLocal(rel) {
		return fmt.Errorf("foreign type inventory directory escapes its exact source root")
	}
	if directory != root {
		if err := budget.check(root, filepath.Dir(directory)); err != nil {
			return err
		}
	}
	if budget.directories == nil {
		budget.directories = make(map[string]bool)
	}
	if budget.directories[directory] {
		return nil
	}
	if len(budget.directories) >= 4096 {
		return fmt.Errorf("foreign type inventory exceeds its shared directory bound")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) > 65536-budget.entries {
		return fmt.Errorf("foreign type inventory exceeds its shared entry bound")
	}
	budget.entries += len(entries)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil || !entry.Type().IsRegular() || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 16<<20-budget.bytes {
			return fmt.Errorf("foreign type inventory exceeds its shared regular source-byte bound")
		}
		budget.bytes += info.Size()
	}
	budget.directories[directory] = true
	return nil
}
