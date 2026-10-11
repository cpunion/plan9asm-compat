package main

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/xgo-dev/plan9asm"
)

const discoveryCompactCPPInventoryProtocol = "query_only_original_cpp_inventory_v1"

// This query result is not a report/consumer protocol. Only independently
// supplied original bytes and ordered driver inputs can validate it; it grants
// no source or CPP authority.
type discoveryCompactCPPInventory struct {
	Protocol          string                                 `json:"protocol"`
	DriverDefinitions []plan9asm.AssemblyCPPDriverDefinition `json:"driver_definitions"`
	InvocationNames   []string                               `json:"invocation_names"`
	Sources           map[string]discoveryCompactCPPSource   `json:"sources"`
}

type discoveryCompactCPPSource struct {
	File         string                      `json:"file"`
	SHA256       string                      `json:"sha256"`
	ByteLength   int                         `json:"byte_length"`
	FinalNewline bool                        `json:"final_newline"`
	Records      []discoveryCompactCPPRecord `json:"records"`
}

type discoveryCompactCPPRecord struct {
	Kind       string                    `json:"kind"`
	Start      int                       `json:"start"`
	End        int                       `json:"end"`
	Line       int                       `json:"line"`
	EndLine    int                       `json:"end_line"`
	Text       string                    `json:"text"`
	Definition *discoveryCompactCPPMacro `json:"definition,omitempty"`
}

type discoveryCompactCPPMacro struct {
	Name     string   `json:"name"`
	Function bool     `json:"function"`
	Formals  []string `json:"formals"`
}

func captureDiscoveryCompactCPPInventory(sources map[string][]byte, defines []string) (*discoveryCompactCPPInventory, error) {
	if len(sources) == 0 || len(sources) > 512 {
		return nil, fmt.Errorf("compact CPP query requires bounded original source bytes")
	}
	seeds, err := plan9asm.InspectAssemblyCPPDriverDefinitions(defines)
	if err != nil {
		return nil, err
	}
	names := make(map[string]bool)
	for _, seed := range seeds {
		names[seed.Definition.Name] = true
		if err := compactCPPGeneratedNames(&seed.Definition, names); err != nil {
			return nil, fmt.Errorf("driver CPP definition %q: %w", seed.Definition.Name, err)
		}
		if len(names) > 4096 {
			return nil, fmt.Errorf("compact CPP query exceeds its macro-name bound")
		}
	}
	ids := make([]string, 0, len(sources))
	for id := range sources {
		if _, _, err := discoveryCPPSourceIdentity(id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	totalBytes := 0
	for _, id := range ids {
		data := sources[id]
		if len(data) > 64<<20-totalBytes {
			return nil, fmt.Errorf("compact CPP query exceeds its original source byte bound")
		}
		totalBytes += len(data)
		physical, err := plan9asm.InspectAssemblyCPPSource(string(data), id, nil)
		if err != nil {
			return nil, err
		}
		for _, record := range physical.Records {
			if record.Definition == nil {
				continue
			}
			names[record.Definition.Name] = true
			if err := compactCPPGeneratedNames(record.Definition, names); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", id, record.Line, err)
			}
		}
		if len(names) > 4096 {
			return nil, fmt.Errorf("compact CPP query exceeds its macro-name bound")
		}
	}
	result := &discoveryCompactCPPInventory{
		Protocol:          discoveryCompactCPPInventoryProtocol,
		DriverDefinitions: seeds,
		InvocationNames:   sortedCompactCPPMacroNames(names),
		Sources:           make(map[string]discoveryCompactCPPSource, len(ids)),
	}
	for _, id := range ids {
		data := sources[id]
		physical, err := plan9asm.InspectAssemblyCPPSource(string(data), id, result.InvocationNames)
		if err != nil {
			return nil, err
		}
		_, file, _ := discoveryCPPSourceIdentity(id)
		compact := discoveryCompactCPPSource{
			File: file, SHA256: discoveryFeatureBytesSHA256(data), ByteLength: physical.ByteLength,
			FinalNewline: physical.FinalNewline, Records: []discoveryCompactCPPRecord{},
		}
		for _, record := range physical.Records {
			stored := discoveryCompactCPPRecord{
				Kind: record.Kind, Start: record.Start, End: record.End, Line: record.Line,
				EndLine: record.EndLine, Text: record.Text,
			}
			if definition := record.Definition; definition != nil {
				stored.Definition = &discoveryCompactCPPMacro{Name: definition.Name, Function: definition.Function}
				if definition.Function {
					stored.Definition.Formals = make([]string, len(definition.Parameters))
					copy(stored.Definition.Formals, definition.Parameters)
				}
			}
			compact.Records = append(compact.Records, stored)
		}
		result.Sources[id] = compact
	}
	return result, nil
}

// Only literal generated definition names are closed in this first split.
// A formal which manufactures a name/control requires a later exact executor
// proof; omitting its potential future invocations would be unsound.
func compactCPPGeneratedNames(macro *plan9asm.AssemblyCPPMacroDefinition, names map[string]bool) error {
	formal := make(map[string]bool, len(macro.Parameters))
	for _, name := range macro.Parameters {
		formal[name] = true
	}
	for index, token := range macro.Replacement {
		if token.Kind != "#" {
			continue
		}
		if index+1 == len(macro.Replacement) || macro.Replacement[index+1].Kind != "identifier" {
			return fmt.Errorf("generated CPP control lacks a closed literal name")
		}
		control := macro.Replacement[index+1]
		if formal[control.Text] {
			return fmt.Errorf("generated CPP control name needs an exact invocation proof")
		}
		if control.RecordedValue != "define" {
			continue
		}
		if index+2 >= len(macro.Replacement) || macro.Replacement[index+2].Kind != "identifier" {
			return fmt.Errorf("generated CPP definition lacks a closed literal macro name")
		}
		name := macro.Replacement[index+2]
		if formal[name.Text] {
			return fmt.Errorf("generated CPP macro name needs an exact invocation proof")
		}
		// Generated Slice tokens have sequential positions, not their original
		// physical whitespace. A following '(' can introduce a new formal
		// scope whose invocations manufacture names this raw query cannot close.
		if index+3 < len(macro.Replacement) && macro.Replacement[index+3].Kind == "(" {
			return fmt.Errorf("generated CPP function macro needs an exact invocation proof")
		}
		names[name.RecordedValue] = true
	}
	return nil
}

// Full-source recapture, not a JSON self-consistency check. Authenticating the
// supplied source/ZIP/tool bytes and exact ordered actual driver definitions
// remains the caller's separate responsibility. The required definitions must
// come from that independent input, never from the inventory being checked.
func verifyDiscoveryCompactCPPInventory(inventory *discoveryCompactCPPInventory, sources map[string][]byte, defines []string) error {
	actual, err := captureDiscoveryCompactCPPInventory(sources, defines)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(inventory, actual) {
		return fmt.Errorf("compact CPP query differs from complete original source recapture")
	}
	return nil
}

func sortedCompactCPPMacroNames(names map[string]bool) []string {
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
