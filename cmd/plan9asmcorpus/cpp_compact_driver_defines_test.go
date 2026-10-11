package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
)

func TestCompactCPPInventoryDriverDefinesReachOriginalInvocations(t *testing.T) {
	cases := []struct {
		name    string
		source  string
		defines []string
		names   []string
	}{
		{
			name:    "driver only",
			source:  "TEXT ·Probe(SB),$0-0\nEMIT\nRET\n",
			defines: []string{"EMIT=GLOBL ·driverMarker(SB),$8"},
			names:   []string{"EMIT"},
		},
		{
			name:   "ordered overwrite and defaults",
			source: "TEXT ·Probe(SB),$0-0\n#ifdef ENABLED\nEMIT\n#endif\nRET\n",
			defines: []string{
				"ENABLED", "EMPTY=", "EMIT=GLOBL ·oldMarker(SB),$8",
				"EMIT=GLOBL ·driverMarker(SB),$8",
			},
			names: []string{"EMIT", "EMPTY", "ENABLED"},
		},
		{
			name:    "literal generated definition",
			source:  "MAKE\nNEW\nTEXT ·Probe(SB),$0-0\nRET\n",
			defines: []string{"MAKE=#define NEW GLOBL ·driverMarker(SB),$8\n"},
			names:   []string{"MAKE", "NEW"},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
				t.Run(target, func(t *testing.T) {
					defines := compactCPPDriverOriginalObject(t, target, test.source, test.defines)
					inventory, err := captureDiscoveryCompactCPPInventory(map[string][]byte{
						"module/original.s": []byte(test.source),
					}, defines)
					if err != nil {
						t.Fatal(err)
					}
					for _, name := range test.names {
						if !compactCPPDriverHasName(inventory.InvocationNames, name) {
							t.Fatalf("actual driver seed %q disappeared from raw name closure: names=%v defines=%q", name, inventory.InvocationNames, defines)
						}
					}
					if len(inventory.Sources["module/original.s"].Records) == 0 {
						t.Fatal("actual driver-only invocation disappeared from original source inventory")
					}
					for _, invocation := range []string{"EMIT\n", "MAKE\n", "NEW\n"} {
						if !strings.Contains(test.source, invocation) {
							continue
						}
						found := false
						for _, record := range inventory.Sources["module/original.s"].Records {
							found = found || record.Kind == "candidate" && record.Text == invocation
						}
						if !found {
							t.Fatalf("actual invocation %q lost its exact original candidate span", invocation)
						}
					}
					if err := verifyDiscoveryCompactCPPInventory(inventory, map[string][]byte{
						"module/original.s": []byte(test.source),
					}, defines); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestCompactCPPInventoryDriverDefinesRequireIndependentOrderedSeeds(t *testing.T) {
	sources := map[string][]byte{
		"module/source.s": []byte("EMIT\nMAKE\nNEW\nHEADER\n"),
		"module/defs.h":   []byte("#define HEADER 1\n"),
	}
	required := []string{"EMIT=first", "EMIT=last", "MAKE=#define NEW 1\n"}
	input := append([]string(nil), required...)
	got, err := captureDiscoveryCompactCPPInventory(sources, input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.InvocationNames, []string{"EMIT", "HEADER", "MAKE", "NEW"}) ||
		len(got.DriverDefinitions) != 3 || len(got.Sources["module/source.s"].Records) != 4 {
		t.Fatalf("driver/physical/generated name closure changed: %+v", got)
	}
	input[0] = "MUTATED"
	if got.DriverDefinitions[0].Text != required[0] {
		t.Fatal("caller-owned definition slice mutated the query")
	}
	if err := verifyDiscoveryCompactCPPInventory(got, sources, required); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*discoveryCompactCPPInventory){
		"missing": func(value *discoveryCompactCPPInventory) {
			value.DriverDefinitions = nil
		},
		"empty": func(value *discoveryCompactCPPInventory) {
			value.DriverDefinitions = value.DriverDefinitions[:0]
		},
		"deleted overwritten seed": func(value *discoveryCompactCPPInventory) {
			value.DriverDefinitions = value.DriverDefinitions[1:]
		},
		"extra duplicate": func(value *discoveryCompactCPPInventory) {
			value.DriverDefinitions = append(value.DriverDefinitions, value.DriverDefinitions[0])
		},
		"reorder": func(value *discoveryCompactCPPInventory) {
			value.DriverDefinitions[0], value.DriverDefinitions[1] = value.DriverDefinitions[1], value.DriverDefinitions[0]
		},
		"text": func(value *discoveryCompactCPPInventory) {
			value.DriverDefinitions[0].Text = "EMIT=changed"
		},
		"name": func(value *discoveryCompactCPPInventory) {
			value.DriverDefinitions[0].Definition.Name = "changed"
		},
		"replacement": func(value *discoveryCompactCPPInventory) {
			value.DriverDefinitions[0].Definition.Replacement[0].RecordedValue = "changed"
		},
		"raw token": func(value *discoveryCompactCPPInventory) {
			value.DriverDefinitions[0].Definition.Replacement[0].Text = "changed"
		},
		"token position": func(value *discoveryCompactCPPInventory) {
			value.DriverDefinitions[0].Definition.Replacement[0].Start++
		},
		"function identity": func(value *discoveryCompactCPPInventory) {
			value.DriverDefinitions[0].Definition.Function = true
			value.DriverDefinitions[0].Definition.Parameters = []string{}
		},
		"paired closure deletion": func(value *discoveryCompactCPPInventory) {
			value.DriverDefinitions = []plan9asm.AssemblyCPPDriverDefinition{}
			value.InvocationNames = []string{"HEADER"}
			file := value.Sources["module/source.s"]
			file.Records = file.Records[3:]
			value.Sources["module/source.s"] = file
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var copy discoveryCompactCPPInventory
			if err := json.Unmarshal(encoded, &copy); err != nil {
				t.Fatal(err)
			}
			mutate(&copy)
			if err := verifyDiscoveryCompactCPPInventory(&copy, sources, required); err == nil {
				t.Fatal("changed query borrowed independent source/driver identity")
			}
		})
	}
	for _, different := range [][]string{
		nil, required[:2], {required[1], required[0], required[2]},
		{required[0], required[1], required[2], required[2]},
		{"EMIT=changed", required[1], required[2]},
	} {
		if err := verifyDiscoveryCompactCPPInventory(got, sources, different); err == nil {
			t.Fatal("changed independent driver inputs accepted the old query")
		}
	}
	empty, err := captureDiscoveryCompactCPPInventory(sources, nil)
	if err != nil || empty.DriverDefinitions == nil || len(empty.DriverDefinitions) != 0 {
		t.Fatal("complete empty seed set was omitted")
	}
	empty.DriverDefinitions = nil
	if err := verifyDiscoveryCompactCPPInventory(empty, sources, nil); err == nil {
		t.Fatal("missing seed field was treated as complete empty input")
	}
}

func TestCompactCPPInventoryDriverDefinesKeepUnclosedGenerationStrict(t *testing.T) {
	sources := map[string][]byte{"module/source.s": []byte("MAKE\nUSE(NEW)\nNEW\n")}
	for _, definition := range []string{
		"MAKE=#define USE(NAME) NAME\n", "MAKE=#define USE (NAME) NAME\n",
		"MAKE=#define USE() RET\n", "MAKE=#define USE /* gap */ (NAME) NAME\n",
	} {
		t.Run(definition, func(t *testing.T) {
			inventory, err := captureDiscoveryCompactCPPInventory(sources, []string{definition})
			if inventory != nil || err == nil || !strings.Contains(err.Error(), "generated CPP function macro needs an exact invocation proof") {
				t.Fatalf("driver-generated formal scope was silently truncated: %+v %v", inventory, err)
			}
		})
	}
}

func compactCPPDriverHasName(names []string, wanted string) bool {
	for _, name := range names {
		if name == wanted {
			return true
		}
	}
	return false
}

// This compiles first-party original assembly only. Exact ordered -D inputs,
// source bytes and actual object bytes are retained independently of the query.
func compactCPPDriverOriginalObject(t *testing.T, target, source string, explicit []string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, root, targetFeatureTestEnv(), target, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := &discoveryAsmCommandProfile{
		Context: ctx, Observed: observed, GoBinary: goBinary, GoRoot: runtime.GOROOT(),
		PackagePath: "example.invalid/compact-driver", Environment: targetFeatureTestEnv(),
	}
	parts := strings.Split(target, "/")
	binary, args, env, _, err := discoveryAssemblyProfileCommand(profile, parts[0], parts[1], runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, definition := range explicit {
		args = append(args, "-D", definition)
	}
	defines := []string{}
	for index := 0; index < len(args); index++ {
		if args[index] == "-D" {
			if index+1 == len(args) {
				t.Fatal("actual assembler profile has an incomplete -D argument")
			}
			index++
			defines = append(defines, args[index])
		}
	}
	file, object := filepath.Join(root, "original.s"), filepath.Join(root, "original.o")
	writeTestFile(t, file, source)
	args = append(args, "-o", object, file)
	_, _, err = runDiscoveryMachineCommand(ctx, root, env, binary, args...)
	if err != nil {
		t.Fatalf("original explicit -D source is not Go accepted: %v", err)
	}
	nm, _, err := runDiscoveryMachineCommand(ctx, root, env, binary, "tool", "nm", object)
	if err != nil || !strings.Contains(string(nm), "compact-driver.driverMarker") || strings.Contains(string(nm), "oldMarker") {
		t.Fatalf("original driver macro invocation/overwrite was not observed: %s %v", nm, err)
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
		Defines   []string
		Object    []byte
		ObjectSHA string
		Symbols   string
		Arguments []string
	}{observed.GoVersion, target, source, discoveryFeatureBytesSHA256([]byte(source)), defines,
		data, discoveryFeatureBytesSHA256(data), string(nm), args})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("COMPACT_DRIVER_ACTUAL_GO_RECEIPT %s", receipt)
	return defines
}
