package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
)

func TestAssemblerMacroRegistrationActualRoleAndDefaults(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", map[string]string{"GOEXPERIMENT": "fieldtrack"})
	if err != nil {
		t.Fatal(err)
	}
	minor, _ := discoveryGoMinor(observed.GoVersion)
	for _, pkg := range []string{"example.invalid/ordinary", "runtime", "reflect"} {
		proof, err := captureDiscoveryAssemblerMacros(runtime.GOROOT(), observed, pkg)
		if err != nil {
			t.Fatal(err)
		}
		wantExperiments := minor >= 22 && pkg != "example.invalid/ordinary"
		if containsTargetFeature(proof.Defines, "GOEXPERIMENT_fieldtrack") != wantExperiments {
			t.Errorf("%s experiment macro enabled=%t, want=%t; proof=%+v", pkg, containsTargetFeature(proof.Defines, "GOEXPERIMENT_fieldtrack"), wantExperiments, proof)
		}
		if len(proof.ToolSourceSHA256) < 3 || proof.RegistrationSHA256["asmArgs"] == "" {
			t.Error("assembler macro role lacks actual source registration evidence")
		}
	}
}

func TestAssemblerMacrosActualDirectPackageRoleFiveArchitectures(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ target, experiment string }{
		{"linux/386", "fieldtrack"}, {"linux/amd64", "fieldtrack"}, {"linux/arm", "fieldtrack"},
		{"linux/arm64", "fieldtrack"}, {"js/wasm", "fieldtrack"}, {"linux/amd64", ""},
	} {
		t.Run(test.target+"/"+test.experiment, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			target, experiment := test.target, test.experiment
			// Empty raw GOEXPERIMENT still enables real registered defaults.
			env := replaceEnv(targetFeatureTestEnv(), map[string]string{"GOEXPERIMENT": experiment})
			observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), env, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, pkg := range []string{"example.invalid/ordinary", "runtime"} {
				proof, err := captureDiscoveryAssemblerMacros(runtime.GOROOT(), observed, pkg)
				if err != nil {
					t.Fatal(err)
				}
				cpuDefines, err := plan9asm.GoAssemblerDefinesForEnvironment(observed.Environment["GOOS"], observed.Environment["GOARCH"], observed.Environment)
				if err != nil {
					t.Fatal(err)
				}
				var names []string
				for name := range observed.MarkerSelection {
					if strings.HasPrefix(name, "goexperiment.") {
						names = append(names, "GOEXPERIMENT_"+strings.TrimPrefix(name, "goexperiment."))
					}
				}
				names = uniqueSortedDiscoveryStrings(names)
				source := "#include \"textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-0\nRET\n"
				for index, macro := range names {
					source += fmt.Sprintf("#ifdef %s\nGLOBL ·experiment%03d(SB),NOPTR,$8\nDATA ·experiment%03d(SB)/8,$1\n#endif\n", macro, index, index)
				}
				dir := t.TempDir()
				file, object := filepath.Join(dir, "probe.s"), filepath.Join(dir, "probe.o")
				if err := os.WriteFile(file, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				args := []string{"tool", "asm", "-p", pkg, "-I", filepath.Join(runtime.GOROOT(), "pkg/include"), "-o", object}
				// Do not pass experiment -D flags: their real presence/absence
				// must come from cmd/asm's observed package role.
				for _, define := range cpuDefines {
					args = append(args, "-D", define)
				}
				args = append(args, file)
				actualEnv := replaceEnv(env, observed.Environment)
				if _, _, err := runDiscoveryMachineCommand(ctx, dir, actualEnv, goBinary, args...); err != nil {
					t.Fatal(err)
				}
				nm, _, err := runDiscoveryMachineCommand(ctx, dir, actualEnv, goBinary, "tool", "nm", object)
				if err != nil {
					t.Fatal(err)
				}
				arch := map[string]plan9asm.Arch{"386": plan9asm.ArchAMD64, "amd64": plan9asm.ArchAMD64, "arm": plan9asm.ArchARM, "arm64": plan9asm.ArchARM64, "wasm": plan9asm.ArchWASM}[observed.Environment["GOARCH"]]
				parsed, err := plan9asm.ParseWithDefines(arch, source, proof.Defines)
				if err != nil {
					t.Fatal(err)
				}
				for index, macro := range names {
					name := fmt.Sprintf("experiment%03d", index)
					selected := false
					for _, global := range parsed.Globl {
						selected = selected || strings.Contains(global.Sym, name)
					}
					want := containsTargetFeature(proof.Defines, macro)
					if strings.Contains(string(nm), name) != want || selected != want {
						t.Errorf("%s %s %s direct=%t translator=%t want=%t", target, pkg, macro, strings.Contains(string(nm), name), selected, want)
					}
				}
				t.Logf("actual %s %s GOEXPERIMENT=%q role=%s pkg=%s macro_source=%v nm_sha=%s defines=%v", observed.GoVersion, target, experiment, proof.PackageRole, pkg, proof.ToolSourceSHA256, discoveryFeatureBytesSHA256(nm), proof.Defines)
			}
		})
	}
}

func TestAssemblerMacroRegistrationRejectsSourceChanges(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	observed, err := captureDiscoveryTargetFeatures(ctx, goBinary, t.TempDir(), targetFeatureTestEnv(), "linux/amd64", nil)
	if err != nil {
		t.Fatal(err)
	}
	minor, _ := discoveryGoMinor(observed.GoVersion)
	for _, mutation := range []struct{ name, file, from, to string }{
		{"version", "VERSION", observed.GoVersion, "go1.99.1"},
		{"cpu-registration", "src/cmd/go/internal/work/gc.go", "\"GOARCH_\"", "\"FAKEARCH_\""},
		{"experiment-registration", "src/cmd/asm/main.go", "GOEXPERIMENT_", "FAKEEXPERIMENT_"},
		{"role-registration", "src/cmd/internal/objabi/pkgspecial.go", "\"runtime\",", "\"example.invalid/ordinary\","},
	} {
		if minor < 22 && (mutation.name == "experiment-registration" || mutation.name == "role-registration") {
			continue // Those registrations genuinely did not exist yet.
		}
		t.Run(mutation.name, func(t *testing.T) {
			root := t.TempDir()
			files := []string{"VERSION", "src/cmd/go/internal/work/gc.go", "src/cmd/asm/main.go"}
			if minor >= 22 {
				files = append(files, "src/cmd/internal/objabi/pkgspecial.go")
			}
			for _, file := range files {
				data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), filepath.FromSlash(file)))
				if err != nil {
					t.Fatal(err)
				}
				if file == mutation.file {
					changed := strings.Replace(string(data), mutation.from, mutation.to, 1)
					if changed == string(data) {
						t.Fatal("source mutation was not exercised")
					}
					data = []byte(changed)
				}
				name := filepath.Join(root, filepath.FromSlash(file))
				if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := captureDiscoveryAssemblerMacros(root, observed, "runtime"); err == nil {
				t.Fatal("accepted changed actual tool registration source")
			}
		})
	}
}
