package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/mod/module"
)

// An embedded-module alias resolves an old self-import to source already
// present inside the same checksum-verified module ZIP. It does not fetch a
// different upstream module or change the downloaded source tree.
type discoveryEmbeddedModuleAlias struct {
	Module       string `json:"module"`
	Version      string `json:"version"`
	ModuleSum    string `json:"module_sum"`
	SourceDir    string `json:"source_dir"`
	ImportModule string `json:"import_module"`
	EvidenceURL  string `json:"evidence_url"`
}

type discoveryEmbeddedModuleManifest struct {
	SchemaVersion int                            `json:"schema_version"`
	Aliases       []discoveryEmbeddedModuleAlias `json:"aliases"`
}

func loadDiscoveryEmbeddedModuleAliases(repoRoot string, candidates []discoveryCandidate) (map[string]discoveryEmbeddedModuleAlias, error) {
	name := filepath.Join(repoRoot, "testdata", "corpus", "embedded-modules.json")
	data, err := os.ReadFile(name)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var manifest discoveryEmbeddedModuleManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode embedded-module aliases: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	if manifest.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported embedded-module alias schema %d", manifest.SchemaVersion)
	}
	known := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		known[candidate.exactKey()] = true
	}
	aliases := make(map[string]discoveryEmbeddedModuleAlias, len(manifest.Aliases))
	for _, alias := range manifest.Aliases {
		key := alias.Module + "@" + alias.Version
		if !known[key] {
			return nil, fmt.Errorf("embedded-module alias %s is absent from scan ledger", key)
		}
		if _, duplicate := aliases[key]; duplicate {
			return nil, fmt.Errorf("duplicate embedded-module alias %s", key)
		}
		if err := module.Check(alias.Module, alias.Version); err != nil {
			return nil, fmt.Errorf("%s: invalid module version: %w", key, err)
		}
		if err := module.CheckPath(alias.ImportModule); err != nil || alias.ImportModule == alias.Module {
			return nil, fmt.Errorf("%s: invalid embedded-module import path %q", key, alias.ImportModule)
		}
		if !strings.HasPrefix(alias.ModuleSum, "h1:") {
			return nil, fmt.Errorf("%s: invalid pinned module checksum", key)
		}
		digest, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(alias.ModuleSum, "h1:"))
		if err != nil || len(digest) != 32 {
			return nil, fmt.Errorf("%s: invalid pinned module checksum", key)
		}
		if !filepath.IsLocal(alias.SourceDir) || path.Clean(alias.SourceDir) != alias.SourceDir ||
			filepath.ToSlash(alias.SourceDir) != alias.SourceDir {
			return nil, fmt.Errorf("%s: invalid embedded-module source directory %q", key, alias.SourceDir)
		}
		evidence, err := url.Parse(alias.EvidenceURL)
		if err != nil || evidence.Scheme != "https" || evidence.Host == "" {
			return nil, fmt.Errorf("%s: invalid embedded-module evidence URL", key)
		}
		aliases[key] = alias
	}
	return aliases, nil
}

func prepareDiscoveryEmbeddedAlias(workDir string, download moduleDownloadInfo, alias discoveryEmbeddedModuleAlias) error {
	if download.Path != alias.Module || download.Version != alias.Version || download.Sum != alias.ModuleSum {
		return fmt.Errorf("embedded-module alias source does not match pinned module, version and checksum")
	}
	if !filepath.IsLocal(alias.SourceDir) || path.Clean(alias.SourceDir) != alias.SourceDir ||
		filepath.ToSlash(alias.SourceDir) != alias.SourceDir {
		return fmt.Errorf("invalid embedded-module source directory %q", alias.SourceDir)
	}
	sourceDir := filepath.Join(download.Dir, filepath.FromSlash(alias.SourceDir))
	info, err := os.Lstat(sourceDir)
	if err != nil {
		return fmt.Errorf("inspect embedded-module source: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("embedded-module source %q is not a directory", alias.SourceDir)
	}
	if _, err := os.Stat(filepath.Join(sourceDir, "go.mod")); err == nil {
		return fmt.Errorf("embedded-module source %q already contains go.mod", alias.SourceDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect embedded-module go.mod: %w", err)
	}

	aliasDir := filepath.Join(workDir, "embedded-module-alias")
	if err := copyDiscoveryModuleTree(sourceDir, aliasDir); err != nil {
		return fmt.Errorf("copy embedded-module source: %w", err)
	}
	goMod := fmt.Sprintf("module %s\n\ngo 1.27\n", alias.ImportModule)
	if err := os.WriteFile(filepath.Join(aliasDir, "go.mod"), []byte(goMod), 0644); err != nil {
		return fmt.Errorf("write embedded-module go.mod: %w", err)
	}
	return nil
}

func addDiscoveryEmbeddedAliasToPlan(plan discoveryExecutionPlan, alias discoveryEmbeddedModuleAlias) (discoveryExecutionPlan, error) {
	if alias.ImportModule == plan.ModulePath {
		return discoveryExecutionPlan{}, fmt.Errorf("embedded-module import path cannot equal the candidate module path")
	}
	plan.GoMod += fmt.Sprintf("\nrequire %s v0.0.0\nreplace %s => ./embedded-module-alias\n",
		alias.ImportModule, alias.ImportModule)
	return plan, nil
}
