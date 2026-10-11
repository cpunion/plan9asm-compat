package main

import (
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// This is an original-source planning model, not an actual compiler/header or
// library pass. Its captured namespace and complete CPP inputs come from the
// existing query-only fixture. The callback follows the production preflight
// boundary so an unclosed import cannot silently supply a generated header.
const cppImportedHeaderIndependentSource = `package fixture

import "errors"

var unusedByHeader = errors.New("not a header property")

type Record struct { Value uint64 }

const Truth = true
const Text = "#ifdef GOAMD64_v3"

func Probe()
`

func TestCPPImportedHeaderPlanningKeepsNecessaryCPUProfiles(t *testing.T) {
	testCPPImportedHeaderPlanningKeepsNecessaryCPUProfiles(t, cppImportedHeaderIndependentSource)
}

func TestCPPUninstantiatedGenericImportedHeaderPlanningKeepsNecessaryCPUProfiles(t *testing.T) {
	source := cppImportedHeaderIndependentSource + "\ntype Frame[T any] struct { Value T; Next *Frame[T] }\n"
	testCPPImportedHeaderPlanningKeepsNecessaryCPUProfiles(t, source)
}

func testCPPImportedHeaderPlanningKeepsNecessaryCPUProfiles(t *testing.T, source string) {
	t.Helper()
	fixture := newConditionFreePlanningFixture(t, "linux/arm64", "", map[string]string{
		"pkg/decl.go": source,
	})
	requestsSeen := make(map[string]bool)
	fixture.plan.headerPlanningCapture = func(request discoveryFeatureProfileRequest,
		assembly string, tags []string,
	) (*gotoolprofile.GeneratedHeaderProof, error) {
		requestsSeen[discoveryHeaderPlanningKey(request, assembly, tags)] = true
		sources, err := fixture.selectedGoSources(request)
		if err != nil {
			return nil, err
		}
		if err := gotoolprofile.PreflightNativeGeneratedHeaderSource(
			fixture.plan.Module+"/pkg", request.Target, "go1.20", sources,
		); err != nil {
			if gotoolprofile.NativeHeaderSourceDomainUnsupported(err) {
				return nil, &discoveryHeaderPlanningUnsupported{err.Error()}
			}
			return nil, err
		}
		return fixture.header(t, request, assembly)
	}
	initial, found, err := planDiscoveryFeaturePair(fixture.context, fixture.baseline,
		fixture.assembly, "pkg/decl.go")
	if err != nil || !found {
		t.Fatalf("original source pair: found=%t error=%v", found, err)
	}
	requests, err := planDiscoveryCPPFeaturePair(fixture.plan, fixture.context,
		fixture.baseline, fixture.assembly, "pkg/decl.go", initial)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 0 || len(requestsSeen) != 1 {
		t.Fatalf("condition-free imported source expanded into %d extra CPU proposals and %d header requests; want one necessary baseline and no extra CPU proposals",
			len(requests), len(requestsSeen))
	}
}

func TestCPPImportedHeaderPlanningRetainsCPUSensitiveOriginalScopes(t *testing.T) {
	for _, axis := range []string{"CPP branch", "Go partner"} {
		t.Run(axis, func(t *testing.T) {
			extra := map[string]string{"pkg/decl.go": cppImportedHeaderIndependentSource}
			body := "#ifdef GOAMD64_v3\nGLOBL ·featureMarker(SB),$8\n#endif\n"
			if axis == "Go partner" {
				body = ""
				extra["pkg/feature.go"] = "//go:build amd64.v3 && goexperiment.fieldtrack\n\npackage fixture\ntype FeatureOnly struct { Value uint32 }\n"
			}
			fixture := newConditionFreePlanningFixture(t, "linux/amd64", body, extra)
			fixture.plan.headerPlanningCapture = func(request discoveryFeatureProfileRequest, assembly string, _ []string) (*gotoolprofile.GeneratedHeaderProof, error) {
				return fixture.header(t, request, assembly)
			}
			requests, err := planDiscoveryFeatureProfiles(fixture.plan, []string{fixture.assembly}, []*discoveryTargetFeatures{fixture.baseline})
			if err != nil || len(requests) < 2 {
				t.Fatalf("import-independent properties erased required original %s scopes: %+v %v", axis, requests, err)
			}
			var feature bool
			for _, request := range requests {
				feature = feature || request.Overrides["GOAMD64"] == "v3" &&
					(axis == "CPP branch" || request.Expected["goexperiment.fieldtrack"])
			}
			if !feature || len(fixture.queries) < 2 {
				t.Fatalf("original CPU/experiment distinction disappeared: requests=%+v queries=%d", requests, len(fixture.queries))
			}
		})
	}
}
