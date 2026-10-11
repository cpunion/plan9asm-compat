package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestCPPToolIncludeEOFOriginalGraphFiveArchitectures(t *testing.T) {
	const include = "../../src/runtime/go_tls.h"
	const header = "#include \"" + include + "\""
	const marker = "TEXT ·Probe(SB),$0-0\nRET\nDATA ·value(SB)/4,$42\nGLOBL ·value(SB),8,$4\n"
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			parts := strings.Split(target, "/")
			file := "pkg/native_" + parts[1] + ".s"
			plan, root, archive := fixtureCPPInputsForTarget(t, target, map[string]string{
				file:          "#include \"eof.h\"\n\n" + marker,
				"pkg/eof.h":   header,
				"pkg/decl.go": "package fixture\nfunc Probe()\n",
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			env := append(os.Environ(), "GOOS="+parts[0], "GOARCH="+parts[1])
			args := []string{"tool", "asm", "-S", "-D", "GOOS_" + parts[0], "-D", "GOARCH_" + parts[1],
				"-I", filepath.Join(runtime.GOROOT(), "pkg/include"), "-o", filepath.Join(t.TempDir(), "go.o"), filepath.Join(root, filepath.FromSlash(file))}
			stdout, stderr, err := gotoolprofile.RunBounded(ctx, filepath.Join(root, "pkg"), env, "go", args...)
			if err != nil || !strings.Contains(string(stdout), "2a 00 00 00") {
				t.Fatalf("actual original included-EOF Go object: %v\n%s\n%s", err, stdout, stderr)
			}

			for _, deferred := range []bool{false, true} {
				inputs, err := captureDiscoveryCPPInputsMode(plan, root, runtime.GOROOT(), []string{file}, deferred)
				if err != nil {
					t.Errorf("original included EOF capture (deferred=%t): %v", deferred, err)
					continue
				}
				if err := verifyDiscoveryCPPModuleZIP(inputs, plan, archive); err != nil {
					t.Fatal(err)
				}
				if err := verifyDiscoveryCPPInputsUnchanged(inputs, root, runtime.GOROOT()); err != nil {
					t.Fatal(err)
				}
				canonical, err := json.Marshal(inputs)
				if err != nil {
					t.Fatal(err)
				}
				for name, mutate := range map[string]func(*discoveryCPPInputs){
					"drop absence": func(p *discoveryCPPInputs) { p.Units[0].PackageSearchMisses = nil },
					"wrong parent": func(p *discoveryCPPInputs) {
						for key, miss := range p.Units[0].PackageSearchMisses {
							miss.Source = "module/" + file
							p.Units[0].PackageSearchMisses[key] = miss
						}
					},
				} {
					t.Run(name, func(t *testing.T) {
						var changed discoveryCPPInputs
						if err := json.Unmarshal(canonical, &changed); err != nil {
							t.Fatal(err)
						}
						mutate(&changed)
						if err := validateDiscoveryCPPInputs(&changed, plan, []string{file}); err == nil {
							t.Fatal("included EOF lost its original search source contract")
						}
					})
				}
			}

			// This is a separate original translation unit, not a header whose
			// input stack can resume a parent's newline.
			if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(file)), []byte(marker+header), 0600); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, err = gotoolprofile.RunBounded(ctx, filepath.Join(root, "pkg"), env, "go", args...)
			if err == nil || !strings.Contains(string(stderr), "expected newline after #include") {
				t.Fatalf("actual translation-unit EOF must remain Go-rejected: %v\n%s\n%s", err, stdout, stderr)
			}
		})
	}
}
