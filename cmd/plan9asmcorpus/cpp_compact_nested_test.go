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

	"github.com/xgo-dev/plan9asm"
)

func TestCompactCPPInventoryGeneratedFunctionNamesRequireContext(t *testing.T) {
	source := strings.Join([]string{
		"#define MAKE " + strings.Repeat("\\", 1),
		"#define USE(NAME) " + strings.Repeat("\\", 3),
		"#define NAME GLOBL ·generatedMarker(SB),$8 " + strings.Repeat("\\", 1),
		"",
		"MAKE",
		"USE(NEW)",
		"NEW",
		"TEXT ·Probe(SB),$0-0",
		"RET",
		"",
	}, "\n")
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), target, nil)
			if err != nil {
				t.Fatal(err)
			}
			profile := &discoveryAsmCommandProfile{
				Context: ctx, Observed: observed, GoBinary: goBinary, GoRoot: runtime.GOROOT(),
				PackagePath: "example.invalid/compact-nested", Environment: targetFeatureTestEnv(),
			}
			parts := strings.Split(target, "/")
			binary, args, env, _, err := discoveryAssemblyProfileCommand(profile, parts[0], parts[1], runtime.GOROOT())
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			file, object := filepath.Join(root, "original.s"), filepath.Join(root, "original.o")
			writeTestFile(t, file, source)
			args = append(args, "-o", object, file)
			_, _, err = runDiscoveryMachineCommand(ctx, root, env, binary, args...)
			if err != nil {
				t.Fatalf("original nested generator is not Go accepted: %v", err)
			}
			nm, _, err := runDiscoveryMachineCommand(ctx, root, env, binary, "tool", "nm", object)
			if err != nil || !strings.Contains(string(nm), "generatedMarker") {
				t.Fatalf("actual Go did not invoke the generated macro: %s %v", nm, err)
			}
			data, err := os.ReadFile(object)
			if err != nil || len(data) == 0 {
				t.Fatalf("missing actual original object: %v", err)
			}
			receipt, err := json.Marshal(struct {
				Version   string
				Target    string
				Source    string
				SourceSHA string
				Object    []byte
				ObjectSHA string
				Symbols   string
				Arguments []string
			}{observed.GoVersion, target, source, discoveryFeatureBytesSHA256([]byte(source)), data,
				discoveryFeatureBytesSHA256(data), string(nm), args})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("COMPACT_NESTED_ACTUAL_GO_RECEIPT %s", receipt)
			if inventory, err := captureDiscoveryCompactCPPInventory(map[string][]byte{"module/original.s": []byte(source)}, nil); err == nil {
				t.Fatalf("generated function formal silently omitted later NEW invocation: %+v", inventory)
			}
		})
	}
}

func TestCompactCPPInventoryGeneratedFunctionScopesRemainUnclosed(t *testing.T) {
	for _, definition := range []string{
		"#define INNER(NAME) NAME",
		"#define INNER (NAME) NAME",
		"#define INNER() RET",
		"#define INNER () RET",
		"#define INNER/* gap */(NAME) NAME",
	} {
		t.Run(definition, func(t *testing.T) {
			source := "#define OUTER \\\n" + definition + "\nOUTER\nINNER(NEW)\nNEW\n"
			physical, err := plan9asm.InspectAssemblyCPPSource(source, "original.s", nil)
			if err != nil || len(physical.Records) == 0 || physical.Records[0].Text != "#define OUTER \\\n"+definition+"\n" {
				t.Fatalf("raw generated definition was not retained: %+v %v", physical, err)
			}
			inventory, err := captureDiscoveryCompactCPPInventory(map[string][]byte{"module/original.s": []byte(source)}, nil)
			if inventory != nil || err == nil || !strings.Contains(err.Error(), "generated CPP function macro needs an exact invocation proof") {
				t.Fatalf("unclosed generated function scope was accepted: %+v %v", inventory, err)
			}
		})
	}

	source := "#define USE(NAME) NAME\nUSE(RET)\n"
	inventory, err := captureDiscoveryCompactCPPInventory(map[string][]byte{"module/original.s": []byte(source)}, nil)
	if err != nil || inventory == nil || len(inventory.InvocationNames) != 1 || inventory.InvocationNames[0] != "USE" {
		t.Fatalf("ordinary physical function macro was changed: %+v %v", inventory, err)
	}
}
