package main

import (
	"fmt"
	"strconv"
	"strings"
	"text/scanner"
	"unicode"
)

type discoveryCPPDirective struct {
	Line      int    `json:"line"`
	Kind      string `json:"kind"`
	Name      string `json:"name,omitempty"`
	Include   string `json:"include,omitempty"`
	Generated bool   `json:"generated_from_macro_body,omitempty"`
}

type discoveryCPPSource struct {
	File       string                  `json:"file"`
	SHA256     string                  `json:"sha256"`
	Directives []discoveryCPPDirective `json:"directives"`
	Original   *string                 `json:"original_source,omitempty"`

	resourceIndex *discoveryCPPSourceResourceIndex
}

type discoveryCPPBranchState struct{ OuterActive, Then bool }

const discoveryCPPDirectiveLimit = 1024

// Only an unknown first control can take the narrow original-source assembler
// rejection route. Includes, conditional branches, expansion and resource
// errors retain their existing hard-failure behavior.
type discoveryUnsupportedCPPError struct {
	File, SHA256, Directive string
	Line                    int
	FirstToken              bool
}

func (err *discoveryUnsupportedCPPError) Error() string {
	if err.FirstToken {
		return fmt.Sprintf("assembly %s:%d: expected identifier, found %q (not N/A)", err.File, err.Line, err.Directive)
	}
	return fmt.Sprintf("CPP %s:%d: unsupported Go directive %s (not N/A)", err.File, err.Line, err.Directive)
}

func discoveryCPPConditionsFromBytes(file string, data []byte) (discoveryCPPSource, error) {
	input := discoveryCPPSource{File: file, SHA256: discoveryFeatureBytesSHA256(data), Directives: []discoveryCPPDirective{}}
	if len(data) > 64<<20 {
		return input, fmt.Errorf("CPP condition input exceeds the explicit 64 MiB source bound")
	}
	var scan scanner.Scanner
	scan.Init(strings.NewReader(string(data)))
	scan.Filename = file
	scan.Whitespace = 1<<'\t' | 1<<'\r' | 1<<' '
	scan.Mode = scanner.ScanChars | scanner.ScanFloats | scanner.ScanIdents | scanner.ScanInts | scanner.ScanStrings | scanner.ScanComments | scanner.SkipComments
	scan.IsIdentRune = discoveryCPPIdentifierRune
	var scanErr error
	scan.Error = func(scan *scanner.Scanner, message string) {
		if scanErr == nil {
			scanErr = fmt.Errorf("CPP condition source %s: %s", scan.Position, message)
		}
	}
	type cppToken struct {
		kind rune
		text string
		line int
	}
	readLine := func() ([]cppToken, bool) {
		var tokens []cppToken
		for {
			tok := scan.Scan()
			if tok == scanner.EOF || tok == '\n' {
				return tokens, tok == scanner.EOF
			}
			tokens = append(tokens, cppToken{tok, scan.TokenText(), scan.Position.Line})
		}
	}
	for {
		tokens, eof := readLine()
		if len(tokens) == 0 || tokens[0].kind != '#' {
			if eof {
				break
			}
			continue
		}
		if len(tokens) < 2 || tokens[1].kind != scanner.Ident {
			return input, fmt.Errorf("CPP %s:%d: unknown directive registration", file, tokens[0].line)
		}
		directive := discoveryCPPDirective{Line: tokens[0].line, Kind: tokens[1].text}
		if directive.Kind == "define" {
			// Go permits only escaped newlines/backslashes in macro bodies.
			// Preserve definedness, but refuse bodies which can generate CPP
			// directives through a later macro invocation.
			for !eof {
				backslashes := 0
				for index := len(tokens) - 1; index >= 0 && tokens[index].kind == '\\'; index-- {
					backslashes++
				}
				if backslashes%2 == 0 {
					break
				}
				tokens = tokens[:len(tokens)-1]
				continued, last := readLine()
				tokens = append(tokens, continued...)
				eof = last
			}
		}
		switch directive.Kind {
		case "ifdef", "ifndef", "undef":
			if len(tokens) != 3 || tokens[2].kind != scanner.Ident {
				return input, fmt.Errorf("CPP %s:%d: invalid %s predicate", file, directive.Line, directive.Kind)
			}
			directive.Name = tokens[2].text
		case "define":
			if len(tokens) < 3 || tokens[2].kind != scanner.Ident {
				return input, fmt.Errorf("CPP %s:%d: invalid defined macro", file, directive.Line)
			}
			directive.Name = tokens[2].text
			for _, token := range tokens[3:] {
				if token.kind == '#' {
					return input, fmt.Errorf("CPP %s:%d: directive-generating macro requires an explicit expansion proof", file, directive.Line)
				}
			}
		case "include":
			if len(tokens) != 3 || tokens[2].kind != scanner.String {
				return input, fmt.Errorf("CPP %s:%d: nonliteral include requires an explicit source proof", file, directive.Line)
			}
			name, err := strconv.Unquote(tokens[2].text)
			if err != nil || name == "" || strings.ContainsAny(name, "\x00\r\n") {
				return input, fmt.Errorf("CPP %s:%d: invalid literal include", file, directive.Line)
			}
			directive.Include = name
		case "else", "endif":
			if len(tokens) != 2 {
				return input, fmt.Errorf("CPP %s:%d: unexpected %s tokens", file, directive.Line, directive.Kind)
			}
		case "line":
			if len(tokens) != 4 || tokens[2].kind != scanner.Int || tokens[3].kind != scanner.String {
				return input, fmt.Errorf("CPP %s:%d: unknown line registration", file, directive.Line)
			}
		default:
			if len(input.Directives) == 0 && scanErr == nil {
				return input, &discoveryUnsupportedCPPError{File: file, SHA256: input.SHA256, Directive: directive.Kind, Line: directive.Line}
			}
			return input, fmt.Errorf("CPP %s:%d: unsupported Go directive %s (not N/A)", file, directive.Line, directive.Kind)
		}
		// This records original controls, not translation-unit acceptance.
		// cmd/asm's input stack resumes the parent tokenizer at include EOF;
		// a directive's required newline can therefore belong to that parent.
		// The actual assembler and active consumer must still validate syntax.
		if len(input.Directives) >= discoveryCPPDirectiveLimit {
			return input, fmt.Errorf("CPP directives exceed the explicit %d-item source bound", discoveryCPPDirectiveLimit)
		}
		input.Directives = append(input.Directives, directive)
	}
	if scanErr != nil {
		return input, scanErr
	}
	return input, nil
}

func discoveryCPPIdentifierRune(ch rune, index int) bool {
	return unicode.IsLetter(ch) || ch == '_' || ch == '\u00B7' || ch == '\u2215' || index > 0 && unicode.IsDigit(ch)
}

func validDiscoveryCPPMacroName(name string) bool {
	if name == "" {
		return false
	}
	for index, ch := range name {
		if !discoveryCPPIdentifierRune(ch, index) {
			return false
		}
	}
	return true
}

func replayDiscoveryCPPConditions(directives []discoveryCPPDirective, defines []string) (map[int]discoveryCPPBranchState, error) {
	if len(directives) > 4096 {
		return nil, fmt.Errorf("CPP translation unit exceeds the explicit 4096-directive bound")
	}
	macros := make(map[string]bool)
	for _, define := range defines {
		name := strings.SplitN(define, "=", 2)[0]
		if name == "" || macros[name] {
			return nil, fmt.Errorf("invalid or duplicate actual predefined CPP macro")
		}
		macros[name] = true
	}
	type frame struct{ outer, active bool }
	var stack []frame
	active := true
	states := make(map[int]discoveryCPPBranchState)
	for index, directive := range directives {
		switch directive.Kind {
		case "ifdef", "ifndef":
			if len(stack) >= 32 {
				return nil, fmt.Errorf("CPP conditional nesting exceeds the explicit 32-level bound")
			}
			value := macros[directive.Name]
			if directive.Kind == "ifndef" {
				value = !value
			}
			states[index] = discoveryCPPBranchState{OuterActive: active, Then: value}
			stack = append(stack, frame{outer: active, active: active && value})
			active = active && value
		case "else":
			if len(stack) == 0 {
				return nil, fmt.Errorf("unmatched CPP else")
			}
			top := &stack[len(stack)-1]
			if top.outer {
				top.active = !top.active
			}
			active = top.active
		case "endif":
			if len(stack) == 0 {
				return nil, fmt.Errorf("unmatched CPP endif")
			}
			active = stack[len(stack)-1].outer
			stack = stack[:len(stack)-1]
		case "define":
			if active {
				if macros[directive.Name] {
					return nil, fmt.Errorf("active CPP macro redefinition: %s", directive.Name)
				}
				macros[directive.Name] = true
			}
		case "undef":
			if active {
				if !macros[directive.Name] {
					return nil, fmt.Errorf("active CPP undef for undefined macro: %s", directive.Name)
				}
				delete(macros, directive.Name)
			}
		case "include":
			if active {
				return nil, fmt.Errorf("active CPP include has no bound source: %s", directive.Include)
			}
		case "line":
		default:
			return nil, fmt.Errorf("unregistered CPP directive %s", directive.Kind)
		}
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("unclosed CPP conditional")
	}
	return states, nil
}
