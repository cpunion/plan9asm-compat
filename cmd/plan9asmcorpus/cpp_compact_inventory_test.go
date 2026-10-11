package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCompactCPPInventoryRetainsCrossHeaderRawSourceOrder(t *testing.T) {
	sources := map[string][]byte{
		"module/pkg/original.s": []byte("USE\n#include \"defs.h\"\nMAKE(GOAMD64_v3)\nNEW\nUSE\n"),
		"module/pkg/defs.h":     []byte("#ifdef NEVER\n#define USE SELECT\n#endif\n#define SELECT() \\\n#ifdef GOAMD64_v4 \\\n#line 27 \"logical.s\" \\\n#include \"choice.h\" \\\n#endif \\\n\n#define MAKE(P) \\\n#define NEW 17 \\\n#ifdef P \\\n#undef NEW \\\n#endif \\\n\n"),
		"module/pkg/choice.h":   []byte("#define CHOSEN 1"),
	}
	got, err := captureDiscoveryCompactCPPInventory(sources, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != discoveryCompactCPPInventoryProtocol || len(got.Sources) != 3 ||
		!reflect.DeepEqual(got.InvocationNames, []string{"CHOSEN", "MAKE", "NEW", "SELECT", "USE"}) {
		t.Fatalf("raw cross-header macro closure changed: %+v", got)
	}
	for id, source := range sources {
		witness := got.Sources[id]
		if witness.SHA256 != discoveryFeatureBytesSHA256(source) || witness.ByteLength != len(source) ||
			witness.FinalNewline != (source[len(source)-1] == '\n') {
			t.Fatal("complete original source identity changed")
		}
		for index, record := range witness.Records {
			if record.Text != string(source[record.Start:record.End]) ||
				index != 0 && record.Start < witness.Records[index-1].End {
				t.Fatal("record text/order is not the original physical source")
			}
		}
	}
	asm := got.Sources["module/pkg/original.s"]
	if len(asm.Records) != 5 || asm.Records[0].Kind != "candidate" || asm.Records[0].Text != "USE\n" {
		t.Fatal("invocation before a header definition or generated definition disappeared")
	}
	header := got.Sources["module/pkg/defs.h"]
	if len(header.Records) != 5 || header.Records[3].Definition == nil ||
		!header.Records[3].Definition.Function || header.Records[3].Definition.Formals == nil ||
		len(header.Records[3].Definition.Formals) != 0 ||
		!strings.Contains(header.Records[3].Text, "#line 27 \"logical.s\"") ||
		!reflect.DeepEqual(header.Records[4].Definition.Formals, []string{"P"}) {
		t.Fatal("object/function/zero-formal/control payload changed")
	}
	if err := verifyDiscoveryCompactCPPInventory(got, sources, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCompactCPPInventoryOrdinaryInstructionBodiesStayCompact(t *testing.T) {
	source := "#ifdef GOAMD64_v3\n" + strings.Repeat("MOVQ $123456789, R0\n", 100000) + "#else\nRET\n#endif\n"
	got, err := captureDiscoveryCompactCPPInventory(map[string][]byte{"module/original.s": []byte(source)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	witness := got.Sources["module/original.s"]
	data, err := json.Marshal(witness)
	if err != nil || len(data) >= 1024 || strings.Contains(string(data), "123456789") || len(witness.Records) != 3 {
		t.Fatalf("ordinary instructions were embedded or control was dropped: bytes=%d err=%v", len(data), err)
	}
	if got.InvocationNames == nil || len(got.InvocationNames) != 0 || witness.SHA256 != discoveryFeatureBytesSHA256([]byte(source)) {
		t.Fatal("compact empty name set/full source identity changed")
	}
	changed := strings.Replace(source, "123456789", "123456788", 1)
	if err := verifyDiscoveryCompactCPPInventory(got, map[string][]byte{"module/original.s": []byte(changed)}, nil); err == nil {
		t.Fatal("an omitted ordinary instruction mutation borrowed the old full-source binding")
	}
}

func TestCompactCPPInventoryRequiresIndependentFullSourceRecapture(t *testing.T) {
	sources := map[string][]byte{"module/source.s": []byte("#define F() x·h\nF()\n#line 17 \"logical.s\"\n//go:build ignored\nRET")}
	got, err := captureDiscoveryCompactCPPInventory(sources, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*discoveryCompactCPPInventory){
		"paired names and calls deletion": func(value *discoveryCompactCPPInventory) {
			value.InvocationNames = []string{}
			file := value.Sources["module/source.s"]
			file.Records = append(file.Records[:1], file.Records[2:]...)
			value.Sources["module/source.s"] = file
		},
		"full hash only": func(value *discoveryCompactCPPInventory) {
			file := value.Sources["module/source.s"]
			file.Records = nil
			value.Sources["module/source.s"] = file
		},
		"object instead of zero-formal function": func(value *discoveryCompactCPPInventory) {
			file := value.Sources["module/source.s"]
			file.Records[0].Definition.Function = false
			file.Records[0].Definition.Formals = nil
		},
		"record reorder": func(value *discoveryCompactCPPInventory) {
			file := value.Sources["module/source.s"]
			file.Records[0], file.Records[1] = file.Records[1], file.Records[0]
		},
		"body": func(value *discoveryCompactCPPInventory) {
			file := value.Sources["module/source.s"]
			file.Records[0].Text = "#define F() x.h\n"
		},
		"line payload": func(value *discoveryCompactCPPInventory) {
			file := value.Sources["module/source.s"]
			file.Records[2].Text = "#line 18 \"logical.s\"\n"
		},
		"EOF": func(value *discoveryCompactCPPInventory) {
			file := value.Sources["module/source.s"]
			file.FinalNewline = true
			value.Sources["module/source.s"] = file
		},
		"source deletion": func(value *discoveryCompactCPPInventory) {
			delete(value.Sources, "module/source.s")
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var copy discoveryCompactCPPInventory
			if err := json.Unmarshal(encoded, &copy); err != nil {
				t.Fatal(err)
			}
			mutate(&copy)
			if err := verifyDiscoveryCompactCPPInventory(&copy, sources, nil); err == nil {
				t.Fatal("mutated compact JSON borrowed full-source authority")
			}
		})
	}
}

func TestCompactCPPInventoryUnclosedAndInvalidSourcesFail(t *testing.T) {
	cases := []map[string][]byte{
		nil,
		{"module/../escape.s": []byte("RET\n")},
		{"generated/pkg/go_asm.h": []byte("#define X 1\n")},
		{"module/source.s": []byte("#define MAKE(NAME) \\\n#define NAME 1 \\\n\nMAKE(NEW)\nNEW\n")},
		{"module/source.s": []byte("#define MAKE(CONTROL) \\\n#CONTROL NEW 1 \\\n\nMAKE(define)\nNEW\n")},
		{"module/source.s": []byte("#define F() X\n" + strings.Repeat("F()\n", 4097))},
	}
	for index, sources := range cases {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			if _, err := captureDiscoveryCompactCPPInventory(sources, nil); err == nil {
				t.Fatal("unclosed or unbounded compact source inventory accepted")
			}
		})
	}
}
