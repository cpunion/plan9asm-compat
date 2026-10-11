package main

import "testing"

func TestAlwaysDocumentationRequiresWholeValidOriginalGoDirectory(t *testing.T) {
	for name, fixture := range map[string]struct {
		entries map[string]string
		sources map[string][]byte
		want    bool
	}{
		"one original documentation": {
			map[string]string{"doc.go": "file"},
			map[string][]byte{"docs/doc.go": []byte("package documentation\n")}, true,
		},
		"hidden and test sources do not create ordinary role": {
			map[string]string{"doc.go": "file", "_hidden.go": "file", ".hidden.go": "file", "ordinary_test.go": "file"},
			map[string][]byte{"docs/doc.go": []byte("package documentation\n")}, true,
		},
		"no normal source": {
			map[string]string{"doc_test.go": "file"},
			map[string][]byte{"docs/doc_test.go": []byte("package documentation\n")}, false,
		},
		"missing normal source": {
			map[string]string{"doc.go": "file", "missing.go": "file"},
			map[string][]byte{"docs/doc.go": []byte("package documentation\n")}, false,
		},
		"invalid normal package clause": {
			map[string]string{"doc.go": "file"},
			map[string][]byte{"docs/doc.go": []byte("package !\n")}, false,
		},
		"ordinary source excluded by tags is still ordinary": {
			map[string]string{"doc.go": "file", "normal.go": "file"},
			map[string][]byte{
				"docs/doc.go":    []byte("package documentation\n"),
				"docs/normal.go": []byte("//go:build never\n\npackage ordinary\n"),
			}, false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if actual := alwaysDocumentationDirectory("docs", fixture.sources, fixture.entries); actual != fixture.want {
				t.Fatalf("whole original documentation role=%v, want %v", actual, fixture.want)
			}
		})
	}
}

func TestHistoricalDocumentationSourceSelectionKeepsOriginalMeaning(t *testing.T) {
	plan := fixtureOrdinarySelection(t, []string{"docs/foreign.s"}, []string{"linux/amd64"}, map[string]string{
		"docs/doc.go":    "package documentation\n",
		"docs/foreign.s": "#ifdef BOOT\n#endif BOOT\n",
	})
	// No actual profile/witness is consumed by the historical source-only
	// replay. Do not reinterpret an old CPP failure as a current exclusion.
	plan.DocumentationSourceProtocol = ""
	decisions, eligible, err := replayOrdinarySelection(plan, []string{"docs/foreign.s"})
	if err != nil || len(eligible) != 1 || len(decisions) != 1 || decisions[0].Kind != nativeLayoutSelected {
		t.Fatalf("historical source-only semantics changed: %v %v %v", decisions, eligible, err)
	}
}
