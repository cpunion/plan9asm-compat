package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestFeatureObservationBindsActualGoSubtools(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	observed, err := captureDiscoveryTargetFeatures(ctx, binary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Directory string            `json:"tool_directory"`
		Tools     map[string]string `json:"tool_binary_sha256"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(record.Directory, "pkg/tool/") || len(record.Tools) != 5 {
		t.Fatalf("actual driver observation omitted subtool identity: %+v", record)
	}
	for _, name := range []string{"asm", "compile", "link", "nm", "vet"} {
		output, _, err := runDiscoveryMachineCommand(ctx, "", replaceEnv(targetFeatureTestEnv(), observed.Environment), binary, "tool", "-n", name)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := discoveryFeatureFileSHA256(strings.TrimSpace(string(output)))
		if err != nil || actual != record.Tools[name] {
			t.Fatalf("actual %s bytes are not bound to the observation: %v", name, err)
		}
	}
	// Keep the rest of a valid observation unchanged: old observer evidence
	// must not be upgraded merely by relabeling the surrounding report.
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "tool_directory")
	delete(legacy, "tool_binary_sha256")
	data, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var missing discoveryTargetFeatures
	if err := json.Unmarshal(data, &missing); err != nil {
		t.Fatal(err)
	}
	if err := validateDiscoveryTargetFeatures(&missing); err == nil {
		t.Fatal("unchanged driver/source evidence accepted missing Go subtool identity")
	}
}

func TestAssemblyProfileRejectsSubtoolMutationWithUnchangedDriver(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	observed, err := captureDiscoveryTargetFeatures(ctx, binary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for file := range observed.ToolSourceSHA256 {
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), filepath.FromSlash(file)))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, path, string(data))
	}
	// No original tools are modified or deleted. The guard must reject this
	// owned replacement root even though its driver and registration match.
	toolDir := filepath.Join(root, "pkg", "tool", runtime.GOOS+"_"+runtime.GOARCH)
	if err := os.MkdirAll(toolDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(toolDir, "asm"), "different assembler bytes")
	profile := &discoveryAsmCommandProfile{Context: ctx, Observed: observed, GoBinary: binary, GoRoot: root}
	if err := verifyDiscoveryAssemblyProfileTools(profile); err == nil {
		t.Fatal("changed/missing subtools were accepted with unchanged driver and registration")
	}
}
