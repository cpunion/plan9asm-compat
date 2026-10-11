package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

type headerPreflightReuseFixture struct {
	plan        *discoveryOrdinarySelectionPlan
	candidate   discoveryCandidate
	download    moduleDownloadInfo
	sources     map[string]string
	cache       *discoveryFeatureObservationCache
	inspections int
	cancel      context.CancelFunc
	directory   string
}

func newHeaderPreflightReuseFixture(t *testing.T, goRoot string) *headerPreflightReuseFixture {
	t.Helper()
	candidate := discoveryCandidate{Module: "example.invalid/header", Version: "v1.0.0", AsmFiles: []string{"probe.s", "sibling.s"}}
	sources := map[string]string{
		"go.mod":    "module example.invalid/header\ngo 1.20\n",
		"header.go": "package header\nimport \"fmt\"\ntype Property fmt.Stringer\nfunc probe() uint64\n",
		"probe.s":   "TEXT ·probe(SB),4,$0-8\nMOVQ $7,ret+0(FP)\nRET\n",
		"sibling.s": "TEXT ·sibling(SB),4,$0-0\nRET\n",
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
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err = filepath.Abs(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	fixture := &headerPreflightReuseFixture{plan: plan, candidate: candidate, download: download, sources: sources,
		cancel: cancel, directory: t.TempDir()}
	fixture.cache = &discoveryFeatureObservationCache{inspect: func(ctx context.Context, binary string, env []string, target string, overrides map[string]string) (*discoveryFeatureDriverState, error) {
		fixture.inspections++
		return inspectDiscoveryFeatureDriver(ctx, binary, env, target, overrides)
	}}
	// No producer runs: a header property depends on an unclosed imported type.
	err = installDiscoveryHeaderPlanning(ctx, plan, candidate, download, fixture.directory, goRoot, goBinary,
		t.TempDir(), filepath.Join(t.TempDir(), "unused-translator"), targetFeatureTestEnv(), fixture.cache)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *headerPreflightReuseFixture) query(t *testing.T) error {
	t.Helper()
	header, err := fixture.plan.headerPlanningCapture(discoveryFeatureProfileRequest{Target: "linux/amd64", Baseline: true}, "probe.s", nil)
	if header != nil || fixture.plan.HeaderPlanning != nil || fixture.plan.headerPlanningQueryStarts != 0 ||
		len(fixture.plan.headerPlanningInventory.Observations) != 0 {
		t.Fatal("cost-only negative preflight published header/query/profile credit")
	}
	return err
}

func TestCPPHeaderPlanningRepeatedUnsupportedPreflight(t *testing.T) {
	fixture := newHeaderPreflightReuseFixture(t, runtime.GOROOT())
	request := discoveryFeatureProfileRequest{Target: "linux/amd64", Baseline: true}
	for index := 0; index < 20; index++ {
		err := fixture.query(t)
		var unsupported *discoveryHeaderPlanningUnsupported
		if !errors.As(err, &unsupported) {
			t.Fatalf("query %d must retain conservative source fallback: %v", index, err)
		}
	}
	if fixture.inspections != 2 {
		t.Fatalf("20 repeated negative preflights inspected the actual driver %d times, want 2 around one observation", fixture.inspections)
	}
	for _, tags := range [][]string{{"custom"}, {"different"}} {
		var unsupported *discoveryHeaderPlanningUnsupported
		if _, err := fixture.plan.headerPlanningCapture(request, "probe.s", tags); !errors.As(err, &unsupported) {
			t.Fatalf("distinct custom tags failed: %v", err)
		}
	}
	var unsupported *discoveryHeaderPlanningUnsupported
	if _, err := fixture.plan.headerPlanningCapture(request, "sibling.s", nil); !errors.As(err, &unsupported) {
		t.Fatalf("distinct assembly failed: %v", err)
	}
	request.Baseline, request.Overrides = false, map[string]string{"GOAMD64": "v2"}
	if _, err := fixture.plan.headerPlanningCapture(request, "probe.s", nil); !errors.As(err, &unsupported) {
		t.Fatalf("distinct CPU failed: %v", err)
	}
	if fixture.inspections != 10 {
		t.Fatalf("different exact source/tag/CPU scopes did not obtain actual observations: %d", fixture.inspections)
	}
}

func TestCPPHeaderPlanningNegativeReuseRechecksBindings(t *testing.T) {
	for _, axis := range []string{"source", "archive", "selection", "language", "workspace bytes", "workspace identity", "cancel", "sdk"} {
		t.Run(axis, func(t *testing.T) {
			goRoot := runtime.GOROOT()
			if axis == "sdk" {
				rules, err := gotoolprofile.CaptureNativeHeaderSourceRules(goRoot, runtime.Version())
				if err != nil {
					t.Fatal(err)
				}
				goRoot = t.TempDir()
				version, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "VERSION"))
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, filepath.Join(goRoot, "VERSION"), string(version))
				for name := range rules.SourceSHA256 {
					data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), filepath.FromSlash(name)))
					if err != nil {
						t.Fatal(err)
					}
					file := filepath.Join(goRoot, filepath.FromSlash(name))
					if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
						t.Fatal(err)
					}
					writeTestFile(t, file, string(data))
				}
			}
			fixture := newHeaderPreflightReuseFixture(t, goRoot)
			var unsupported *discoveryHeaderPlanningUnsupported
			if err := fixture.query(t); !errors.As(err, &unsupported) {
				t.Fatal(err)
			}
			switch axis {
			case "source":
				writeTestFile(t, filepath.Join(fixture.download.Dir, "header.go"), fixture.sources["header.go"]+"// changed\n")
			case "archive":
				writeTestFile(t, fixture.download.Zip, "not the original ZIP")
			case "selection", "language":
				for index := range fixture.plan.Sources {
					source := &fixture.plan.Sources[index]
					if axis == "selection" && source.File == "header.go" {
						source.Header = "//go:build windows\n\npackage header\n"
					}
					if axis == "language" && source.File == "go.mod" {
						source.Header = "module example.invalid/header\ngo 1.27\n"
					}
				}
			case "workspace bytes", "workspace identity":
				matches, err := filepath.Glob(filepath.Join(fixture.directory, "native-header-planning-*", "go.mod"))
				if err != nil || len(matches) != 1 {
					t.Fatalf("owned planning workspace: %v %v", matches, err)
				}
				if axis == "workspace identity" {
					if err := os.Rename(matches[0], matches[0]+".old"); err != nil {
						t.Fatal(err)
					}
				}
				writeTestFile(t, matches[0], "module changed.invalid/header\n")
			case "cancel":
				fixture.cancel()
			case "sdk":
				writeTestFile(t, filepath.Join(goRoot, "VERSION"), "go0.0.0\n")
			}
			if err := fixture.query(t); err == nil || errors.As(err, &unsupported) {
				t.Fatalf("negative reuse swallowed changed %s: %v", axis, err)
			}
			if fixture.inspections != 2 {
				t.Fatalf("changed binding was not rejected by source/workspace/SDK guards: %d", fixture.inspections)
			}
		})
	}
}

func TestCPPHeaderPlanningDeferredFailureCannotBecomeUnsupported(t *testing.T) {
	for _, axis := range []string{"cancel", "workspace"} {
		t.Run(axis, func(t *testing.T) {
			fixture := newHeaderPreflightReuseFixture(t, runtime.GOROOT())
			inspect := fixture.cache.inspect
			fixture.cache.inspect = func(ctx context.Context, binary string, env []string, target string, overrides map[string]string) (*discoveryFeatureDriverState, error) {
				state, err := inspect(ctx, binary, env, target, overrides)
				if err != nil || fixture.inspections != 2 {
					return state, err
				}
				if axis == "cancel" {
					fixture.cancel()
				} else {
					matches, err := filepath.Glob(filepath.Join(fixture.directory, "native-header-planning-*", "go.mod"))
					if err != nil || len(matches) != 1 {
						t.Fatalf("owned planning workspace: %v %v", matches, err)
					}
					writeTestFile(t, matches[0], "module changed.invalid/header\n")
				}
				return state, nil
			}
			err := fixture.query(t)
			var unsupported *discoveryHeaderPlanningUnsupported
			if err == nil || errors.As(err, &unsupported) || axis == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("deferred %s error retained the catchable unsupported classification: %v", axis, err)
			}
		})
	}
}

func TestCPPHeaderPlanningNegativeReuseNeverCachesOrdinaryErrors(t *testing.T) {
	fixture := newHeaderPreflightReuseFixture(t, runtime.GOROOT())
	file := filepath.Join(fixture.download.Dir, "header.go")
	writeTestFile(t, file, fixture.sources["header.go"]+"// changed\n")
	var unsupported *discoveryHeaderPlanningUnsupported
	if err := fixture.query(t); err == nil || errors.As(err, &unsupported) {
		t.Fatalf("initial source error became a conservative fallback: %v", err)
	}
	writeTestFile(t, file, fixture.sources["header.go"])
	if err := fixture.query(t); !errors.As(err, &unsupported) {
		t.Fatal(err)
	}
	if fixture.inspections != 4 {
		t.Fatalf("ordinary error retained an observation: inspections=%d", fixture.inspections)
	}
	writeTestFile(t, file, fixture.sources["header.go"]+"// changed again\n")
	if err := fixture.query(t); err == nil || errors.As(err, &unsupported) {
		t.Fatalf("retained preflight swallowed an ordinary source error: %v", err)
	}
	writeTestFile(t, file, fixture.sources["header.go"])
	if err := fixture.query(t); !errors.As(err, &unsupported) {
		t.Fatal(err)
	}
	if fixture.inspections != 6 {
		t.Fatalf("failed reuse did not discard its retained observation: inspections=%d", fixture.inspections)
	}
}

type headerPlanningErrorReader struct {
	io.Reader
	closeErr error
	closes   int
}

func (reader *headerPlanningErrorReader) Close() error {
	reader.closes++
	return reader.closeErr
}

func TestCPPHeaderPlanningSourceReadAndCloseFailures(t *testing.T) {
	readFailure, closeFailure := errors.New("source read failure"), errors.New("source close failure")
	for _, axis := range []string{"read", "close", "both", "bound"} {
		t.Run(axis, func(t *testing.T) {
			reader := &headerPlanningErrorReader{Reader: strings.NewReader("original source")}
			if axis == "read" || axis == "both" {
				reader.Reader = iotest.ErrReader(readFailure)
			}
			if axis == "close" || axis == "both" {
				reader.closeErr = closeFailure
			}
			if axis == "bound" {
				reader.Reader = strings.NewReader(strings.Repeat("x", 2<<20+1))
			}
			data, err := readDiscoveryHeaderPlanningInput(reader)
			if data != nil || err == nil || reader.closes != 1 ||
				(axis == "read" || axis == "both") && !errors.Is(err, readFailure) ||
				(axis == "close" || axis == "both") && !errors.Is(err, closeFailure) {
				t.Fatalf("bounded source read/close error was lost: bytes=%d closes=%d error=%v", len(data), reader.closes, err)
			}
		})
	}
}

func TestCPPHeaderPlanningNegativeReuseFreshObservationForClosedDomain(t *testing.T) {
	fixture := newHeaderPreflightReuseFixture(t, runtime.GOROOT())
	var unsupported *discoveryHeaderPlanningUnsupported
	if err := fixture.query(t); !errors.As(err, &unsupported) {
		t.Fatal(err)
	}
	// Replace the whole owned source snapshot, including its ZIP and captured
	// inputs, to exercise a domain becoming closed. Ordinary byte mutations
	// without a matching new snapshot are rejected in the binding tests.
	fixture.sources["header.go"] = "package header\nconst Value = 7\nfunc probe() uint64\n"
	replacement := fixtureProfileModuleDownload(t, fixture.candidate, fixture.sources)
	data, err := os.ReadFile(replacement.Zip)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, fixture.download.Zip, string(data))
	writeTestFile(t, filepath.Join(fixture.download.Dir, "header.go"), fixture.sources["header.go"])
	plan, err := captureOrdinarySelectionInputs(fixture.candidate, fixture.download.Dir, []string{"linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	fixture.plan.Sources = plan.Sources
	fixture.plan.Directories = plan.Directories
	fixture.plan.ZipSHA256 = discoveryFeatureBytesSHA256(data)
	failure := errors.New("fresh actual observation is required")
	fixture.cache.inspect = func(context.Context, string, []string, string, map[string]string) (*discoveryFeatureDriverState, error) {
		return nil, failure
	}
	if err := fixture.query(t); !errors.Is(err, failure) {
		t.Fatalf("closed domain borrowed retained observation instead of actual producer: %v", err)
	}
}

func TestCPPHeaderPlanningNegativeReuseBoundsAndOwnership(t *testing.T) {
	var reuse discoveryHeaderPreflightReuse
	observed := &discoveryTargetFeatures{Environment: map[string]string{"GOAMD64": "v1"}}
	if err := reuse.remember("owned", observed); err != nil {
		t.Fatal(err)
	}
	observed.Environment["GOAMD64"] = "v2"
	for index := 0; index < 2; index++ {
		owned, err := reuse.lookup("owned")
		if err != nil || owned.Environment["GOAMD64"] != "v1" {
			t.Fatalf("retained observation aliases a producer or consumer: %v %v", owned, err)
		}
		owned.Environment["GOAMD64"] = "v3"
	}
	for index := 0; index < discoveryHeaderPreflightEntryLimit; index++ {
		if err := reuse.remember(fmt.Sprint(index), observed); err != nil {
			t.Fatal(err)
		}
	}
	if len(reuse.profiles) != discoveryHeaderPreflightEntryLimit || reuse.bytes > discoveryHeaderPreflightByteLimit {
		t.Fatalf("retained entries/bytes are unbounded: %d/%d", len(reuse.profiles), reuse.bytes)
	}
	reuse.remove("owned")
	if value, err := reuse.lookup("owned"); value != nil || err != nil {
		t.Fatalf("removed entry remained usable: %v %v", value, err)
	}
	var large discoveryHeaderPreflightReuse
	if err := large.remember(strings.Repeat("k", discoveryHeaderPreflightByteLimit+1), observed); err != nil {
		t.Fatal(err)
	}
	observed.Environment["oversized"] = strings.Repeat("v", discoveryHeaderPreflightByteLimit)
	if err := large.remember("oversized", observed); err != nil {
		t.Fatal(err)
	}
	if len(large.profiles) != 0 || large.bytes != 0 {
		t.Fatal("oversized key or profile retained")
	}
}
