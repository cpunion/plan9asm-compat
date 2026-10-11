package main

import (
	"errors"
	"strings"
	"testing"
)

func TestPreCPPControlPrefixPreservesExactPhysicalBoundary(t *testing.T) {
	for _, source := range []string{"#Original example\ntrailing code\n", "// comment\r\n#Original example\r\ntrailing\n", "/* comment\nsecond */\n#Original example", "\n#Original example\n"} {
		_, err := discoveryCPPConditionsFromBytes("source.s", []byte(source))
		unsupported, ok := err.(*discoveryUnsupportedCPPError)
		if !ok {
			t.Fatalf("missing first unknown-control error: %v", err)
		}
		prefix, err := preCPPControlPrefix([]byte(source), unsupported.Line)
		if err != nil {
			t.Fatal(err)
		}
		proof := discoveryPreCPPRejection{Protocol: discoveryPreCPPRejectionProtocol, File: "source.s",
			Line: unsupported.Line, Directive: unsupported.Directive, ControlPrefix: prefix}
		if err := validatePreCPPControlPrefix(proof); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(source, prefix) {
			t.Fatal("prefix changed original bytes")
		}
	}
	for _, source := range []string{"", strings.Repeat("x", discoveryPreCPPControlPrefixLimit) + "\n#Original\n"} {
		if _, err := preCPPControlPrefix([]byte(source), 2); err == nil {
			t.Fatal("missing or oversized prefix was accepted")
		}
	}
}

func TestPreCPPRejectionNeverClaimsPriorCPPOrLexicalFailure(t *testing.T) {
	for _, source := range []string{
		"#ifdef NEVER\n#Original\n#endif\n", "#define X 1\n#Original\n",
		"#include \"missing.h\"\n#Original\n", "#line 40 \"alias.s\"\n#Original\n",
		"\"unterminated\n#Original\n", "#\n", "#Original /* unterminated\n",
	} {
		_, err := discoveryCPPConditionsFromBytes("source.s", []byte(source))
		var unsupported *discoveryUnsupportedCPPError
		if err == nil || errors.As(err, &unsupported) {
			t.Fatalf("conditional/unbound/lexical error acquired an unconditional rejection proof: %q: %v", source, err)
		}
	}
}
