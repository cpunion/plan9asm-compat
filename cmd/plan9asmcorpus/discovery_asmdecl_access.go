package main

import (
	"fmt"
	"strings"
)

// This table describes memory access width, not a vector result width or an
// instruction-name suffix heuristic. Go's complete _yvpbroadcastb family
// uses m8/m16/m32/m64 sources; its EVEX .Z forms have identical input widths.
// Translation still validates the selected operands and produces LLVM objects.
var discoveryAsmDeclPackedBroadcastBytes = map[string]int{
	"vpbroadcastb": 1,
	"vpbroadcastw": 2,
	"vpbroadcastd": 4,
	"vpbroadcastq": 8,
}

func isDiscoveryAsmDeclEqualWidthMove(line string) bool {
	_, diagnostic, ok := strings.Cut(line, ": invalid ")
	if !ok {
		return false
	}
	op, _, ok := strings.Cut(diagnostic, " of ")
	if !ok {
		return false
	}
	width, broadcast := discoveryAsmDeclPackedBroadcastBytes[strings.TrimSuffix(op, ".z")]
	if broadcast {
		if !strings.Contains(line, "[amd64]") && !strings.Contains(line, "[386]") {
			return false
		}
	} else {
		switch op {
		case "movo", "movou":
			width = 16
		case "movb":
			width = 1
		case "movw":
			width = 2
			// The same spelling names a 16-bit x86 word and a 32-bit ARM
			// word. Never carry an x86 analyzer exception across architectures.
			if strings.Contains(line, "[arm]") || strings.Contains(line, "[arm64]") {
				width = 4
			}
		case "movl", "fmovs":
			width = 4
		case "movq", "fmovd":
			width = 8
		default:
			return false
		}
	}
	_, value, ok := strings.Cut(diagnostic, "(fp); ")
	if !ok {
		return false
	}
	separator := strings.LastIndex(value, " is ")
	if separator < 0 {
		return false
	}
	var declared int
	_, err := fmt.Sscanf(value[separator+4:], "%d-byte value", &declared)
	return err == nil && declared == width
}
