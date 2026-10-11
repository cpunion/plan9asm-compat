package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/xgo-dev/plan9asm"
)

// A direct assembly probe is bound to the same driver/environment and package
// path used by the real package compilation. Package path must come from that
// compilation's source-selection observation, not from a special-path guess.
type discoveryAsmCommandProfile struct {
	Context     context.Context
	Observed    *discoveryTargetFeatures
	GoBinary    string
	GoRoot      string
	PackagePath string
	Environment []string
}

func discoveryAssemblyProfileCommand(profile *discoveryAsmCommandProfile, goos, goarch, goRoot string) (string, []string, []string, map[string]string, error) {
	if profile == nil || profile.GoRoot != goRoot || !filepath.IsAbs(profile.GoRoot) || !filepath.IsAbs(profile.GoBinary) {
		return "", nil, nil, nil, fmt.Errorf("missing or inconsistent actual assembly driver/root")
	}
	if profile.Context != nil && profile.Context.Err() != nil {
		return "", nil, nil, nil, fmt.Errorf("actual assembly profile context: %w", profile.Context.Err())
	}
	if err := validateDiscoveryTargetFeatures(profile.Observed); err != nil {
		return "", nil, nil, nil, err
	}
	if profile.Observed.Target != goos+"/"+goarch {
		return "", nil, nil, nil, fmt.Errorf("direct assembler target differs from actual feature profile")
	}
	if err := verifyDiscoveryAssemblyProfileTools(profile); err != nil {
		return "", nil, nil, nil, err
	}
	// Audit the complete cmd/go/cmd/asm/package-special registration. cmd/asm
	// itself adds special-package experiment macros; do not duplicate those
	// with -D or accidentally add them to an ordinary external package.
	macroProof, err := captureDiscoveryAssemblerMacros(profile.GoRoot, profile.Observed, profile.PackagePath)
	if err != nil {
		return "", nil, nil, nil, err
	}
	defines, err := plan9asm.GoAssemblerDefinesForEnvironment(goos, goarch, profile.Observed.Environment)
	if err != nil {
		return "", nil, nil, nil, err
	}
	args := []string{"tool", "asm", "-p", profile.PackagePath}
	for _, define := range defines {
		args = append(args, "-D", define)
	}
	env := replaceEnv(profile.Environment, profile.Observed.Environment)
	env = replaceEnv(env, map[string]string{"GOROOT": profile.GoRoot, "GOTOOLCHAIN": "local", "GOWORK": "off", "CGO_ENABLED": "0"})
	return profile.GoBinary, args, env, macroProof.ToolSourceSHA256, nil
}

func verifyDiscoveryAssemblyProfileTools(profile *discoveryAsmCommandProfile, macroSources ...map[string]string) error {
	actual, err := discoveryFeatureFileSHA256(profile.GoBinary)
	if err != nil || actual != profile.Observed.DriverSHA256 {
		return fmt.Errorf("direct assembler driver bytes differ from actual profile")
	}
	env := replaceEnv(profile.Environment, profile.Observed.Environment)
	env = replaceEnv(env, map[string]string{"GOROOT": profile.GoRoot})
	state, err := inspectDiscoveryFeatureDriver(profile.Context, profile.GoBinary, env, profile.Observed.Target, nil)
	if err != nil {
		return fmt.Errorf("direct assembler actual subtool inspection: %w", err)
	}
	wantedTools := &discoveryFeatureToolState{
		directory: profile.Observed.ToolDirectory, digests: profile.Observed.ToolBinarySHA256,
		origins: profile.Observed.ToolBinaryOrigins, routing: profile.Observed.ToolRoutingSHA256,
		dispatcher: profile.Observed.ToolDispatcherSHA256,
	}
	if !equalDiscoveryFeatureToolStates(state.tools, wantedTools) {
		return fmt.Errorf("direct assembler subtool bytes/routing/cache differ from actual profile")
	}
	for key, wanted := range profile.Observed.Environment {
		if state.environment[key] != wanted {
			return fmt.Errorf("direct assembler actual environment differs: %s", key)
		}
	}
	for file, wanted := range profile.Observed.ToolSourceSHA256 {
		actual, err := discoveryFeatureFileSHA256(filepath.Join(profile.GoRoot, filepath.FromSlash(file)))
		if err != nil || actual != wanted {
			return fmt.Errorf("direct assembler feature-registration source changed: %s", file)
		}
	}
	for _, sources := range macroSources {
		for file, wanted := range sources {
			actual, err := discoveryFeatureFileSHA256(filepath.Join(profile.GoRoot, filepath.FromSlash(file)))
			if err != nil || actual != wanted {
				return fmt.Errorf("direct assembler macro/package-role registration changed: %s", file)
			}
		}
	}
	return nil
}
