package main

import (
	"strings"
	"testing"
	"unsafe"
)

// Strings are immutable values. Share their backing bytes, but never the
// caller's mutable *string or directive projection. The byte identity check
// prevents full-text comparisons on every repeated source/profile query;
// it grants no source or graph authority.
func TestCPPPlanningIndexSharesTextWithoutAliasingProjection(t *testing.T) {
	text := strings.Repeat("DATA ·table(SB)/8,$0x0123456789abcdef\n", 256)
	source, err := discoveryReplayCPPSource("probe.s", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	index := &discoveryCPPPlanningSourceIndex{}
	resources, err := index.validate("probe.s", source)
	if err != nil {
		t.Fatal(err)
	}
	key := discoveryCPPPlanningSourceKey{file: "probe.s", text: *source.Original}
	parsed := index.sources[key]
	if parsed.Original == source.Original {
		t.Fatal("private parse aliases its caller's mutable original pointer")
	}
	if unsafe.StringData(resources.original) != unsafe.StringData(*source.Original) ||
		unsafe.StringData(*parsed.Original) != unsafe.StringData(*source.Original) {
		t.Error("private parser copied immutable text; warm resource comparisons reread all bytes")
	}
	*source.Original += "// changed caller projection\n"
	if resources.original != text || *parsed.Original != text {
		t.Fatal("caller projection mutation changed the private original value")
	}
	if _, err := index.validate("probe.s", source); err == nil {
		t.Fatal("shared text hid a caller change under the previous hash")
	}
	restored, err := discoveryReplayCPPSource("probe.s", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := index.validate("probe.s", restored); err != nil {
		t.Fatalf("caller mutation poisoned the earlier immutable parse: %v", err)
	}
}
