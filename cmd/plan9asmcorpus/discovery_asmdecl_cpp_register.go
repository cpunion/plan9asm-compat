package main

import (
	"fmt"
	"reflect"
	"unicode"

	"github.com/xgo-dev/plan9asm"
)

// Bind a literal FP diagnostic to exactly one unchanged opcode/FP statement
// in the complete executed CPP tape. Only a bare symbolic register alias may
// differ. A label, opcode, native address, displacement, actual register or
// additional statement cannot borrow this parameter-read permission.
func resultAliasCPPRegisterInstruction(replay *resultAliasCPPReplay, file string, line int, function string, literal plan9asm.Instr) (plan9asm.Instr, error) {
	if replay == nil {
		return plan9asm.Instr{}, fmt.Errorf("FP instruction has no complete CPP replay")
	}
	var statement []plan9asm.AssemblyCPPOutputToken
	var selected *plan9asm.Instr
	current := ""
	for _, token := range replay.tokens {
		if token.Kind != '\n' {
			statement = append(statement, token)
		}
		if token.Kind != '\n' && token.Kind != ';' {
			continue
		}
		if len(statement) == 0 {
			continue
		}
		first, last := statement[0], statement[len(statement)-1]
		text := replay.observation.Output[first.Start:last.End]
		if first.Text == "TEXT" {
			parsed, err := plan9asm.Parse(plan9asm.ArchAMD64, text+"\n")
			current = ""
			if err == nil && len(parsed.Funcs) == 1 {
				current = parsed.Funcs[0].Sym
			}
		}
		touches := false
		for _, part := range statement {
			touches = touches || part.Position.File == file && part.Position.Line == line
		}
		if touches {
			if selected != nil || current != "·"+function || first.Expansion != 0 || first.Text != string(literal.Op) {
				return plan9asm.Instr{}, fmt.Errorf("CPP FP statement has a changed opcode, function or multiplicity")
			}
			for _, part := range statement {
				if part.Position.File != file || part.Position.Line != line {
					return plan9asm.Instr{}, fmt.Errorf("CPP FP statement crosses physical source positions")
				}
			}
			parsed, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT ·probe(SB),4,$0-0\n"+text+"\nRET\n")
			if err != nil || len(parsed.Funcs) != 1 || len(parsed.Funcs[0].Instrs) != 3 {
				return plan9asm.Instr{}, fmt.Errorf("CPP FP statement has an unclosed instruction shape: %v", err)
			}
			ins := parsed.Funcs[0].Instrs[1]
			if ins.Op != literal.Op || len(ins.Args) != len(literal.Args) {
				return plan9asm.Instr{}, fmt.Errorf("CPP FP instruction opcode/arity differs")
			}
			for index, operand := range literal.Args {
				if reflect.DeepEqual(operand, ins.Args[index]) {
					continue
				}
				if !resultAliasBareRegisterAlias(operand) || ins.Args[index].Kind != plan9asm.OpReg {
					return plan9asm.Instr{}, fmt.Errorf("CPP FP operand %d is not an exact register alias", index)
				}
			}
			selected = &ins
		}
		statement = nil
	}
	if len(statement) != 0 || selected == nil {
		return plan9asm.Instr{}, fmt.Errorf("CPP FP instruction has no unique terminated physical statement")
	}
	return *selected, nil
}

func resultAliasBareRegisterAlias(operand plan9asm.Operand) bool {
	name := operand.Sym
	if operand.Kind == plan9asm.OpIdent {
		name = operand.Ident
	} else if operand.Kind != plan9asm.OpSym {
		return false
	}
	if name == "" {
		return false
	}
	for index, character := range name {
		if character != '_' && !unicode.IsLetter(character) && (index == 0 || !unicode.IsDigit(character)) {
			return false
		}
	}
	// A pseudo register must not be reinterpreted as a symbolic alias even
	// when the shared parser retains it as a bare symbol.
	switch name {
	case "FP", "SP", "SB", "PC":
		return false
	}
	return true
}
