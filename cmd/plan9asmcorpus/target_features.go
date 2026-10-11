package main

import (
	"context"
	"go/build"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

type discoveryTargetFeatures = gotoolprofile.Observation

const discoveryFeatureMarkerModule = "example.invalid/plan9asm-feature-markers"

var discoveryFeatureEnvKeys = gotoolprofile.EnvironmentKeys()

func captureDiscoveryTargetFeatures(ctx context.Context, binary, ownedDir string, env []string, target string, overrides map[string]string) (*discoveryTargetFeatures, error) {
	return gotoolprofile.Capture(ctx, binary, ownedDir, env, target, overrides, runDiscoveryMachineCommand)
}
func validateDiscoveryCPUEnvironment(arch, value string, minor int) error {
	return gotoolprofile.CPUEnvironment(arch, value, minor)
}
func discoveryCPUFeatureCandidates() []string { return gotoolprofile.CPUCandidates() }
func discoveryBuiltinFeatureCandidates(root string, versions ...string) ([]string, map[string]string, error) {
	return gotoolprofile.BuiltinCandidates(root, versions...)
}
func validateDiscoveryFeatureRegistration(data []byte, minors ...int) error {
	return gotoolprofile.ValidateRegistration(data, minors...)
}
func discoveryExperimentFeatureCandidates(data []byte) ([]string, error) {
	return gotoolprofile.ExperimentCandidates(data)
}
func discoveryFeatureMarkerFiles(tags []string) map[string][]byte {
	return gotoolprofile.MarkerFiles(tags)
}
func decodeDiscoveryFeatureMarkers(data []byte, dir string, tags []string) (map[string]bool, error) {
	return gotoolprofile.DecodeMarkers(data, dir, tags)
}
func discoveryFeatureTagNamespace(tag string) bool           { return gotoolprofile.TagNamespace(tag) }
func discoveryFeatureFileSHA256(name string) (string, error) { return gotoolprofile.FileSHA256(name) }
func discoveryFeatureMarkerSHA256(files map[string][]byte) string {
	return gotoolprofile.MarkerSHA256(files)
}

func discoveryCustomTagsWithoutFeatures(tags []string, contexts []build.Context) []string {
	var custom []string
	for _, tag := range uniqueDiscoveryCustomTags(tags, contexts) {
		if !discoveryFeatureTagNamespace(tag) {
			custom = append(custom, tag)
		}
	}
	return custom
}
