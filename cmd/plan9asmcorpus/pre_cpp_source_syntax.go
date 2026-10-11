package main

import (
	"bytes"
	"text/scanner"
)

// This observer is for a complete selected assembly root, not an include
// fragment. Only the actual Go assembler can close a source rejection.
func preCPPSourceSyntax(file string, data []byte) error {
	if err := preCPPFirstTokenRejection(file, data); err != nil {
		return err
	}
	_, err := discoveryCPPConditionsFromBytes(file, data)
	return err
}

// cmd/asm Parser.line skips comments, newlines and semicolons, then requires
// an identifier. Stop at the first code/control token: a previous directive
// can change expansion, selection, includes or reported source positions.
// This never parses operands or rejects an instruction family.
func preCPPFirstTokenRejection(file string, data []byte) *discoveryUnsupportedCPPError {
	if len(data) > 64<<20 {
		return nil
	}
	var scan scanner.Scanner
	scan.Init(bytes.NewReader(data))
	scan.Filename = file
	scan.Whitespace = 1<<'\t' | 1<<'\r' | 1<<' '
	scan.Mode = scanner.ScanChars | scanner.ScanFloats | scanner.ScanIdents | scanner.ScanInts |
		scanner.ScanStrings | scanner.ScanComments | scanner.SkipComments
	scan.IsIdentRune = discoveryCPPIdentifierRune
	invalid := false
	scan.Error = func(*scanner.Scanner, string) { invalid = true }
	for {
		token := scan.Scan()
		if invalid {
			return nil
		}
		switch token {
		case '\n', ';':
			continue
		case scanner.EOF, scanner.Ident, '#':
			return nil
		default:
			return &discoveryUnsupportedCPPError{
				File: file, SHA256: discoveryFeatureBytesSHA256(data),
				Directive: scan.TokenText(), Line: scan.Position.Line, FirstToken: true,
			}
		}
	}
}
