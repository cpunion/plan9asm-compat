package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/llgo-compat/plan9asm/internal/gotoolchain"
	"golang.org/x/mod/module"
)

// A native-layout skip identifies source that depends on the exact bytes or
// offsets of a Go object. It is not a successful LLVM translation.
type discoveryNativeLayoutSkip struct {
	Module       string   `json:"module"`
	Version      string   `json:"version"`
	AsmFile      string   `json:"asm_file"`
	Targets      []string `json:"targets"`
	SourceSHA256 string   `json:"source_sha256"`
	Symbol       string   `json:"symbol"`
	ObjectHex    string   `json:"object_hex"`
	Reason       string   `json:"reason"`
	EvidenceURLs []string `json:"evidence_urls"`
}

type discoveryNativeLayoutManifest struct {
	SchemaVersion int                         `json:"schema_version"`
	Skips         []discoveryNativeLayoutSkip `json:"skips"`
}

var nativeLayoutSymbolPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9]*$`)

func loadNativeLayoutSkips(repoRoot, ledgerPath string) (map[string]discoveryNativeLayoutSkip, error) {
	name := filepath.Join(repoRoot, "testdata", "corpus", "native-layout.json")
	data, err := os.ReadFile(name)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var manifest discoveryNativeLayoutManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode native-layout manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	if manifest.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported native-layout manifest schema %d", manifest.SchemaVersion)
	}
	interests := make(map[discoveryAssemblyFileKey]bool, len(manifest.Skips))
	for _, skip := range manifest.Skips {
		interests[discoveryAssemblyFileKey{Module: skip.Module, Version: skip.Version, AsmFile: skip.AsmFile}] = true
	}
	known, err := discoveryAssemblyFileMembershipFor(ledgerPath, interests)
	if err != nil {
		return nil, err
	}
	skips := make(map[string]discoveryNativeLayoutSkip, len(manifest.Skips))
	for _, skip := range manifest.Skips {
		key := skip.Module + "@" + skip.Version
		if _, duplicate := skips[key]; duplicate {
			return nil, fmt.Errorf("duplicate native-layout skip %s", key)
		}
		if !known[discoveryAssemblyFileKey{Module: skip.Module, Version: skip.Version, AsmFile: skip.AsmFile}] {
			return nil, fmt.Errorf("%s: native-layout file %q is absent from scan ledger", key, skip.AsmFile)
		}
		if err := module.Check(skip.Module, skip.Version); err != nil {
			return nil, fmt.Errorf("%s: invalid module version: %w", key, err)
		}
		if !filepath.IsLocal(skip.AsmFile) || path.Clean(skip.AsmFile) != skip.AsmFile ||
			filepath.ToSlash(skip.AsmFile) != skip.AsmFile || !strings.HasSuffix(skip.AsmFile, ".s") {
			return nil, fmt.Errorf("%s: invalid native-layout assembly path %q", key, skip.AsmFile)
		}
		if len(skip.Targets) == 0 {
			return nil, fmt.Errorf("%s: native-layout skip has no targets", key)
		}
		seenTargets := make(map[string]bool, len(skip.Targets))
		for _, target := range skip.Targets {
			if err := validateTarget(target); err != nil {
				return nil, fmt.Errorf("%s: invalid native-layout target: %w", key, err)
			}
			if seenTargets[target] {
				return nil, fmt.Errorf("%s: duplicate native-layout target %s", key, target)
			}
			seenTargets[target] = true
		}
		if !discoverySHA256Pattern.MatchString(skip.SourceSHA256) {
			return nil, fmt.Errorf("%s: invalid native-layout source SHA-256", key)
		}
		if !nativeLayoutSymbolPattern.MatchString(skip.Symbol) {
			return nil, fmt.Errorf("%s: invalid native-layout symbol %q", key, skip.Symbol)
		}
		if len(skip.ObjectHex) < 2 || len(skip.ObjectHex)%2 != 0 ||
			strings.ToLower(skip.ObjectHex) != skip.ObjectHex {
			return nil, fmt.Errorf("%s: invalid native-layout object bytes %q", key, skip.ObjectHex)
		}
		if _, err := hex.DecodeString(skip.ObjectHex); err != nil {
			return nil, fmt.Errorf("%s: invalid native-layout object bytes: %w", key, err)
		}
		if strings.TrimSpace(skip.Reason) == "" || len(skip.EvidenceURLs) == 0 {
			return nil, fmt.Errorf("%s: native-layout skip lacks reason or evidence", key)
		}
		for _, rawURL := range skip.EvidenceURLs {
			parsed, err := url.Parse(rawURL)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
				return nil, fmt.Errorf("%s: invalid native-layout evidence URL %q", key, rawURL)
			}
		}
		skips[key] = skip
	}
	return skips, nil
}

func verifyNativeLayoutSource(moduleDir string, skip discoveryNativeLayoutSkip) error {
	if !filepath.IsLocal(skip.AsmFile) {
		return fmt.Errorf("native-layout assembly path is not local: %q", skip.AsmFile)
	}
	name := filepath.Join(moduleDir, filepath.FromSlash(skip.AsmFile))
	data, err := os.ReadFile(name)
	if err != nil {
		return fmt.Errorf("read native-layout assembly %s: %w", skip.AsmFile, err)
	}
	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != skip.SourceSHA256 {
		return fmt.Errorf("native-layout source SHA-256 mismatch for %s: got %s", skip.AsmFile, got)
	}
	return nil
}

func verifyNativeLayoutGoObject(
	ctx context.Context,
	workDir, moduleDir string,
	env []string,
	skip discoveryNativeLayoutSkip,
) error {
	for _, target := range skip.Targets {
		if err := verifyNativeLayoutGoObjectTarget(ctx, workDir, moduleDir, env, skip, target); err != nil {
			return err
		}
	}
	return nil
}

func verifyNativeLayoutGoObjectTarget(
	ctx context.Context,
	workDir, moduleDir string,
	env []string,
	skip discoveryNativeLayoutSkip,
	target string,
) error {
	goos, goarch, ok := strings.Cut(target, "/")
	if !ok {
		return fmt.Errorf("invalid native-layout target %q", target)
	}
	source := filepath.Join(moduleDir, filepath.FromSlash(skip.AsmFile))
	object := filepath.Join(workDir, "native-layout-source.o")
	includeDir := filepath.Dir(source)
	goRoot, err := gotoolchain.Root()
	if err != nil {
		return err
	}
	targetEnv := replaceEnv(env, map[string]string{
		"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0",
	})
	if err := runCapturedCommand(ctx, workDir, targetEnv, "go",
		"tool", "asm", "-I", includeDir, "-I", filepath.Join(goRoot, "pkg", "include"),
		"-o", object, source); err != nil {
		return fmt.Errorf("current Go assembler rejects native-layout source %s on %s: %w",
			skip.AsmFile, target, err)
	}
	defer os.Remove(object)
	output, err := runCapturedCommandOutput(ctx, workDir, targetEnv, "go", "tool", "objdump", "-s", skip.Symbol, object)
	if err != nil {
		return fmt.Errorf("disassemble native-layout source %s on %s: %w", skip.AsmFile, target, err)
	}
	objectBytes, err := nativeLayoutSymbolBytes(output, skip.Symbol)
	if err != nil {
		return fmt.Errorf("native-layout source %s on %s: %w", skip.AsmFile, target, err)
	}
	witness, _ := hex.DecodeString(skip.ObjectHex)
	if !bytes.Contains(objectBytes, witness) {
		return fmt.Errorf("native-layout object bytes %s absent from symbol %s", skip.ObjectHex, skip.Symbol)
	}
	return nil
}

func nativeLayoutSymbolBytes(output []byte, symbol string) ([]byte, error) {
	var objectBytes []byte
	within := false
	found := false
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "TEXT ") {
			if within {
				break
			}
			fields := strings.Fields(line)
			within = len(fields) >= 2 && strings.HasSuffix(fields[1], "."+symbol+"(SB)")
			found = found || within
			continue
		}
		if !within {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.HasPrefix(fields[1], "0x") {
			continue
		}
		instruction, err := hex.DecodeString(fields[2])
		if err != nil {
			return nil, fmt.Errorf("invalid Go objdump bytes %q: %w", fields[2], err)
		}
		objectBytes = append(objectBytes, instruction...)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !found || len(objectBytes) == 0 {
		return nil, fmt.Errorf("Go objdump has no bytes for symbol %s", symbol)
	}
	return objectBytes, nil
}

func filterNativeLayoutConfigurations(
	configs []discoveryBuildConfiguration,
	skip discoveryNativeLayoutSkip,
) ([]discoveryBuildConfiguration, bool, error) {
	selectedTargets := make(map[string]bool)
	for _, config := range configs {
		if !containsDiscoveryString(config.AsmFiles, skip.AsmFile) {
			continue
		}
		for _, target := range config.Targets {
			selectedTargets[target] = true
		}
	}
	pinnedTargets := make(map[string]bool, len(skip.Targets))
	for _, target := range skip.Targets {
		pinnedTargets[target] = true
	}
	allPinned := len(selectedTargets) == len(pinnedTargets)
	for target := range selectedTargets {
		if !pinnedTargets[target] {
			allPinned = false
		}
	}
	if !allPinned {
		return nil, false, fmt.Errorf(
			"native-layout source %s selects targets %v, pinned targets %v",
			skip.AsmFile, sortedDiscoverySet(selectedTargets), sortedDiscoverySet(pinnedTargets),
		)
	}
	for _, target := range skip.Targets {
		filtered, active, err := filterExactAssemblyConfiguration(configs, skip.AsmFile, target, "native-layout")
		if err != nil || !active {
			return nil, active, err
		}
		configs = filtered
	}
	return configs, true, nil
}

func nativeLayoutSkipMatchesResult(skip discoveryNativeLayoutSkip, result discoveryCorpusResult) bool {
	if skip.Module == "" || result.NativeLayout == nil {
		return false
	}
	actual, err := json.Marshal(result.NativeLayout)
	if err != nil {
		return false
	}
	want, err := json.Marshal(skip)
	return err == nil && bytes.Equal(actual, want)
}

func validateNativeLayoutResult(result discoveryCorpusResult) error {
	skip := result.NativeLayout
	if skip == nil || skip.Module != result.Module || skip.Version != result.Version ||
		result.Error != "" || !containsDiscoveryString(result.DiscoveredAsmFiles, skip.AsmFile) ||
		strings.TrimSpace(skip.Reason) == "" || skip.SourceSHA256 == "" ||
		skip.Symbol == "" || skip.ObjectHex == "" {
		return fmt.Errorf("invalid native-layout skip evidence")
	}
	return validateNativeLayoutPlan(result)
}
