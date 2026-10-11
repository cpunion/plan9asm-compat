package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestCPPHeaderPlanningSourcePreflightRetainsOriginalBindings(t *testing.T) {
	// Actual captured profile fixtures are used only to replay source predicates.
	// This test supplies neither an actual query nor external authentication.
	data, err := os.ReadFile("testdata/go127_feature_protocol_fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture featureProtocolFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	profile := discoveryFeatureProfile{Observed: fixture.Observed["linux/amd64"],
		Request: discoveryFeatureProfileRequest{Target: "linux/amd64", Baseline: true}}
	profile.ID = discoveryFeatureProfileID(profile.Observed)
	for _, axis := range []string{"closed", "builtin unsafe", "irrelevant imports", "imports", "generic", "directive", "linkage directive", "source", "archive", "selection", "language", "profile"} {
		t.Run(axis, func(t *testing.T) {
			source := "package header\nconst Value = 7\nfunc probe() uint64\n"
			switch axis {
			case "builtin unsafe":
				source = "package header\nimport \"unsafe\"\nconst Value = unsafe.Sizeof(uintptr(0))\nfunc probe() uint64\n"
			case "irrelevant imports":
				source = "package header\nimport \"fmt\"\nvar _ = fmt.Sprintf\nfunc probe() uint64\n"
			case "imports":
				source = "package header\nimport \"fmt\"\ntype Property fmt.Stringer\nfunc probe() uint64\n"
			case "generic":
				source += "type Record[T any] struct { Value T }\n"
			case "directive":
				source += "//go:noinline\nfunc unused() {}\n"
			case "linkage directive":
				source += "//go:linkname unused other.unused\nfunc unused() {}\n"
			}
			candidate := discoveryCandidate{Module: "example.invalid/header", Version: "v1.0.0", AsmFiles: []string{"probe.s"}}
			download := fixtureProfileModuleDownload(t, candidate, map[string]string{
				"go.mod": "module example.invalid/header\ngo 1.20\n", "header.go": source,
				"probe.s": "TEXT ·probe(SB),4,$0-8\nMOVQ $7,ret+0(FP)\nRET\n",
			})
			plan, err := captureOrdinarySelectionInputs(candidate, download.Dir, []string{"linux/amd64"})
			if err != nil {
				t.Fatal(err)
			}
			plan.ZipSHA256, err = discoveryFeatureFileSHA256(download.Zip)
			if err != nil {
				t.Fatal(err)
			}
			selected := profile
			switch axis {
			case "source":
				writeTestFile(t, filepath.Join(download.Dir, "header.go"), source+"// changed\n")
			case "archive":
				file, err := os.OpenFile(download.Zip, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, writeErr := file.WriteString("changed")
				closeErr := file.Close()
				if writeErr != nil || closeErr != nil {
					t.Fatalf("owned archive mutation: %v %v", writeErr, closeErr)
				}
			case "selection", "language":
				for index := range plan.Sources {
					if axis == "selection" && plan.Sources[index].File == "header.go" {
						plan.Sources[index].Header = "//go:build windows\n\npackage header\n"
					}
					if axis == "language" && plan.Sources[index].File == "go.mod" {
						plan.Sources[index].Header = "module example.invalid/header\ngo 1.27\n"
					}
				}
			case "profile":
				selected.Observed = nil
			}
			err = preflightDiscoveryHeaderQuery(plan, selected, download, "probe.s", nil)
			unsupported := gotoolprofile.NativeHeaderSourceDomainUnsupported(err)
			if axis == "closed" || axis == "builtin unsafe" || axis == "irrelevant imports" || axis == "generic" || axis == "directive" {
				if err != nil || plan.HeaderPlanning != nil || plan.headerPlanningQueryStarts != 0 {
					t.Fatalf("unmodified preflight must not create query authority: %v", err)
				}
			} else if axis == "imports" || axis == "linkage directive" {
				if !unsupported || plan.HeaderPlanning != nil || plan.headerPlanningQueryStarts != 0 {
					t.Fatalf("exact unclosed domain must retain all candidates without query authority: %v", err)
				}
			} else if err == nil || unsupported {
				t.Fatalf("changed source/ZIP/selection/language/profile was swallowed by domain fallback: %v", err)
			}
		})
	}
}

func TestCPPHeaderPlanningUnsupportedStillRequiresActualCompiler(t *testing.T) {
	testCPPHeaderPlanningStillRequiresActualCompiler(t, false, false)
}

func TestCPPHeaderPlanningIndependentImportsStillRequireActualCompiler(t *testing.T) {
	testCPPHeaderPlanningStillRequiresActualCompiler(t, true, false)
}

func TestCPPHeaderPlanningUninstantiatedGenericStillRequiresActualCompiler(t *testing.T) {
	testCPPHeaderPlanningStillRequiresActualCompiler(t, true, true)
}

func testCPPHeaderPlanningStillRequiresActualCompiler(t *testing.T, independent, generic bool) {
	t.Helper()
	candidate := discoveryCandidate{Module: "example.invalid/header", Version: "v1.0.0", AsmFiles: []string{"probe.s"}}
	property := "type Property fmt.Stringer"
	if independent {
		property = "var _ = fmt.Sprintf"
	}
	invalid := "func Invalid() { _ = MissingOriginalValue }"
	diagnostic := "undefined: MissingOriginalValue"
	if generic {
		invalid = "type Broken[T any] struct { Value MissingGenericType }"
		diagnostic = "undefined: MissingGenericType"
	}
	sources := map[string]string{
		"go.mod": "module example.invalid/header\ngo 1.20\n",
		"header.go": "package header\nimport \"fmt\"\n" + property + "\n" +
			"func probe() uint64\n" + invalid + "\n",
		"probe.s": "TEXT ·probe(SB),4,$0-8\nMOVQ $7,ret+0(FP)\nRET\n",
	}
	download := fixtureProfileModuleDownload(t, candidate, sources)
	plan, err := captureOrdinarySelectionInputs(candidate, download.Dir, []string{"linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	plan.ZipSHA256, err = discoveryFeatureFileSHA256(download.Zip)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/go127_feature_protocol_fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture featureProtocolFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	profile := discoveryFeatureProfile{Observed: fixture.Observed["linux/amd64"],
		Request: discoveryFeatureProfileRequest{Target: "linux/amd64", Baseline: true}}
	err = preflightDiscoveryHeaderQuery(plan, profile, download, "probe.s", nil)
	if independent && err != nil || !independent && !gotoolprofile.NativeHeaderSourceDomainUnsupported(err) ||
		plan.HeaderPlanning != nil || plan.headerPlanningQueryStarts != 0 {
		t.Fatalf("imported source acquired planning authority: %v", err)
	}

	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err = filepath.Abs(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	driverSHA, err := discoveryFeatureFileSHA256(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	env := replaceEnv(os.Environ(), map[string]string{
		"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOFLAGS": "",
		"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOEXPERIMENT": "",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, download.Dir, env, goBinary,
		"list", "-p=2", "-mod=readonly", "-export", "-compiled", "-json", ".")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
		!strings.Contains(string(stderr), "header.go:5:") || !strings.Contains(string(stderr), diagnostic) {
		t.Fatalf("unsupported planning domain hid an actual final compiler failure: %v\n%s\n%s", err, stdout, stderr)
	}
	if after, err := discoveryFeatureFileSHA256(goBinary); err != nil || after != driverSHA {
		t.Fatalf("actual compiler driver changed: %v", err)
	}
	hashes := map[string]string{"header.go": discoveryFeatureBytesSHA256([]byte(sources["header.go"]))}
	if err := verifyDiscoveryOriginalSourceMap(plan, download.Dir, download.Zip, hashes); err != nil {
		t.Fatal(err)
	}
	t.Logf("NATIVE_HEADER_UNSUPPORTED_FINAL_COMPILER driver_sha=%s source_sha=%s exit=%d stderr=%q",
		driverSHA, hashes["header.go"], exit.ExitCode(), stderr)
}
