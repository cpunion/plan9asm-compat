package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm"
)

var discoveryAsmDeclNamedOffset = regexp.MustCompile(`^invalid offset ([^ +();]+)\+([0-9]+)\(FP\); expected (.+)$`)

var discoveryAsmDeclUnknownFPName = regexp.MustCompile(`^unknown variable ([^ ;]+); offset ([0-9]+) is ([^ +()]+)\+([0-9]+)\(FP\)$`)

type resultAliasDeclaration struct {
	sig   plan9asm.FuncSig
	fn    *types.Func
	sizes types.Sizes
}

type asmDeclFPComponent struct {
	name, outer  string
	offset, size int64
	leaf, result bool
	inner        []string
	order        int
}

// This map models the actual analyzer's declaration/component names, not a
// native incoming frame. The typed components determine the addressed bytes;
// names never rewrite an explicit displacement or confer initialization.
func asmDeclFPComponents(declaration resultAliasDeclaration) (map[string]*asmDeclFPComponent, error) {
	if declaration.fn == nil {
		return nil, fmt.Errorf("missing actual declaration")
	}
	signature, ok := declaration.fn.Type().(*types.Signature)
	if !ok || signature.Recv() != nil || signature.Variadic() || declaration.sizes == nil {
		return nil, fmt.Errorf("unclosed actual declaration")
	}
	components := make(map[string]*asmDeclFPComponent)
	count := 0
	var add func(types.Type, string, string, int64, bool, int) error
	add = func(typ types.Type, name, outer string, offset int64, result bool, depth int) error {
		size := declaration.sizes.Sizeof(typ)
		if depth > 64 || count >= 16384 || size < 0 || size > 1<<20 || offset < 0 || offset > (1<<20)-size {
			return fmt.Errorf("declaration component budget exceeded")
		}
		if _, duplicate := components[name]; duplicate {
			return fmt.Errorf("ambiguous declaration component name")
		}
		count++
		component := &asmDeclFPComponent{name: name, outer: outer, offset: offset, size: size, leaf: true, result: result, order: count}
		if parent := components[outer]; parent != nil {
			parent.inner = append(parent.inner, name)
		}
		components[name] = component
		word := declaration.sizes.Sizeof(types.Typ[types.Uintptr])
		child := func(t types.Type, suffix string, off int64) error {
			return add(t, name+suffix, name, offset+off, result, depth+1)
		}
		switch value := typ.Underlying().(type) {
		case *types.Basic:
			switch value.Kind() {
			case types.String:
				component.leaf = false
				if err := child(types.Typ[types.Uintptr], "_base", 0); err != nil {
					return err
				}
				return child(types.Typ[types.Int], "_len", word)
			case types.Complex64, types.Complex128:
				component.leaf = false
				part := types.Typ[types.Float64]
				if size == 8 {
					part = types.Typ[types.Float32]
				}
				if err := child(part, "_real", 0); err != nil {
					return err
				}
				return child(part, "_imag", size/2)
			}
		case *types.Slice:
			component.leaf = false
			if err := child(types.Typ[types.Uintptr], "_base", 0); err != nil {
				return err
			}
			if err := child(types.Typ[types.Int], "_len", word); err != nil {
				return err
			}
			return child(types.Typ[types.Int], "_cap", 2*word)
		case *types.Interface:
			component.leaf = false
			suffix := "_itable"
			if value.Empty() {
				suffix = "_type"
			}
			if err := child(types.Typ[types.Uintptr], suffix, 0); err != nil {
				return err
			}
			return child(types.Typ[types.Uintptr], "_data", word)
		case *types.Struct:
			component.leaf = false
			fields := make([]*types.Var, value.NumFields())
			for i := range fields {
				fields[i] = value.Field(i)
			}
			offsets := declaration.sizes.Offsetsof(fields)
			for i, field := range fields {
				// asmdecl's recursive composite self has itself as outer; only
				// synthetic subcomponents are appended to its expected list.
				if err := add(field.Type(), name+"_"+field.Name(), name+"_"+field.Name(), offset+offsets[i], result, depth+1); err != nil {
					return err
				}
			}
		case *types.Array:
			component.leaf = false
			if value.Len() > 16384 {
				return fmt.Errorf("array component budget exceeded")
			}
			stride := declaration.sizes.Sizeof(value.Elem())
			align := declaration.sizes.Alignof(value.Elem())
			stride = (stride + align - 1) &^ (align - 1)
			for i := int64(0); i < value.Len(); i++ {
				element := name + "_" + strconv.FormatInt(i, 10)
				if err := add(value.Elem(), element, element, offset+i*stride, result, depth+1); err != nil {
					return err
				}
			}
		}
		if component.leaf && size == 8 && word == 4 {
			component.leaf = false
			if err := child(types.Typ[types.Uint32], "_lo", 0); err != nil {
				return err
			}
			return child(types.Typ[types.Uint32], "_hi", 4)
		}
		return nil
	}
	var offset int64
	for _, tuple := range []struct {
		values *types.Tuple
		result bool
		prefix string
	}{
		{signature.Params(), false, "arg"}, {signature.Results(), true, "ret"},
	} {
		if tuple.result && tuple.values.Len() != 0 {
			align := declaration.sizes.Alignof(types.Typ[types.Int64])
			offset = (offset + align - 1) &^ (align - 1)
		}
		for i := 0; i < tuple.values.Len(); i++ {
			value := tuple.values.At(i)
			align, size := declaration.sizes.Alignof(value.Type()), declaration.sizes.Sizeof(value.Type())
			if align <= 0 || size < 0 || size > 1<<20 || offset > (1<<20)-size-align {
				return nil, fmt.Errorf("invalid declaration extent")
			}
			offset = (offset + align - 1) &^ (align - 1)
			name := value.Name()
			if name == "" {
				name = tuple.prefix
				if i != 0 {
					name += strconv.Itoa(i)
				}
			}
			if err := add(value.Type(), name, name, offset, tuple.result, 0); err != nil {
				return nil, err
			}
			offset += size
		}
	}
	return components, nil
}

// The analyzer sees the original literal instruction, whereas cmd/asm sees
// CPP output. Whole-function replay prevents a macro-redefined opcode,
// register, label or FP token from borrowing the literal's native-width proof.
// An unresolved integer immediate may consume its fully evaluated value from
// the caller's bound original CPP replay; result effects use that expanded
// function, never the unresolved literal. Other differences remain unclosed.
func resultAliasLiteralCPPFunction(source []byte, expanded plan9asm.Func) error {
	lines := discoveryAsmDeclUncommentedLines(source)
	start, end := -1, len(lines)
	for i, line := range lines {
		if text := discoveryAsmDeclLiteralText.FindStringSubmatch(line); text != nil {
			if text[1] == strings.TrimPrefix(expanded.Sym, "·") {
				if start != -1 {
					return fmt.Errorf("literal function is ambiguous")
				}
				start = i
			} else if start != -1 && end == len(lines) {
				end = i
			}
		}
	}
	if start < 0 || end <= start {
		return fmt.Errorf("literal function is missing")
	}
	for _, line := range lines[start:end] {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			return fmt.Errorf("literal function contains an unclosed CPP directive")
		}
	}
	literal, err := plan9asm.Parse(plan9asm.ArchAMD64, strings.Join(lines[start:end], "\n")+"\n")
	if err != nil {
		return fmt.Errorf("literal function parse: %w", err)
	}
	if len(literal.Funcs) != 1 {
		return fmt.Errorf("literal function count is not one")
	}
	left := literal.Funcs[0]
	if left.Sym != expanded.Sym || left.FrameSize != expanded.FrameSize || left.ArgSize != expanded.ArgSize || len(left.Instrs) != len(expanded.Instrs) {
		return fmt.Errorf("literal/expanded function shape differs")
	}
	for i, ins := range left.Instrs {
		right := expanded.Instrs[i]
		if ins.Op != right.Op || len(ins.Args) != len(right.Args) {
			return fmt.Errorf("literal/expanded instruction %d differs (%s / %s)", i, ins.Op, expanded.Instrs[i].Op)
		}
		for index, operand := range ins.Args {
			if !resultAliasCPPConstantOperand(operand, right.Args[index]) {
				return fmt.Errorf("literal/expanded instruction %d operand %d differs (%s)", i, index, ins.Op)
			}
		}
	}
	return nil
}

func resultAliasCPPConstantOperand(literal, expanded plan9asm.Operand) bool {
	if reflect.DeepEqual(literal, expanded) {
		return true
	}
	// The assembly parser retains a bare $name or $macro(args) as a symbol,
	// while parenthesized unresolved arithmetic is an immediate placeholder.
	// Only integer-expression syntax can cross that representation boundary;
	// effective addresses, selectors and relocations cannot borrow this role.
	if literal.Kind == plan9asm.OpSym && strings.HasPrefix(literal.Sym, "$") &&
		resultAliasCPPIntegerExpression(strings.TrimPrefix(literal.Sym, "$")) {
		literal.Kind, literal.ImmRaw, literal.Sym = plan9asm.OpImm, literal.Sym, ""
	}
	if literal.Kind != plan9asm.OpImm || literal.ImmRaw == "" || literal.ImmIsFloat ||
		expanded.Kind != plan9asm.OpImm || expanded.ImmRaw != "" || expanded.ImmIsFloat {
		return false
	}
	// Only the integer value may differ. Symbolic addresses, registers, FP
	// displacements, floating encodings and any other operand metadata retain
	// their exact identity. This helper supplies no initialization by itself.
	literal.ImmRaw = ""
	literal.Imm = expanded.Imm
	return reflect.DeepEqual(literal, expanded)
}

func resultAliasCPPIntegerExpression(text string) bool {
	expression, err := parser.ParseExpr(text)
	if err != nil {
		return false
	}
	valid := true
	ast.Inspect(expression, func(node ast.Node) bool {
		if !valid || node == nil {
			return false
		}
		switch node := node.(type) {
		case *ast.ParenExpr:
		case *ast.Ident:
			switch node.Name {
			case "FP", "SP", "SB", "PC":
				valid = false
			}
		case *ast.BasicLit:
			valid = node.Kind == token.INT || node.Kind == token.CHAR
		case *ast.UnaryExpr:
			valid = node.Op == token.ADD || node.Op == token.SUB || node.Op == token.XOR
		case *ast.BinaryExpr:
			switch node.Op {
			case token.ADD, token.SUB, token.MUL, token.QUO, token.REM,
				token.AND, token.OR, token.XOR, token.AND_NOT, token.SHL, token.SHR:
			default:
				valid = false
			}
		case *ast.CallExpr:
			_, valid = node.Fun.(*ast.Ident)
			valid = valid && !node.Ellipsis.IsValid()
		default:
			valid = false
		}
		return valid
	})
	return valid
}

// Parameter aliases require only a full native read of an actual declaration
// component. Result reads/writes and lexical ret names require the separate
// full CFG result proof; an alias must not hide the analyzer's RET obligation.
func resultAliasOriginalFP(source []byte, reported, function, warning, arch string, components map[string]*asmDeclFPComponent, file string, replay *resultAliasCPPReplay) (matched, requiresResultProof, boundComponent bool, reason error) {
	match := discoveryAsmDeclNamedOffset.FindStringSubmatch(warning)
	if components == nil {
		return false, false, false, fmt.Errorf("declaration components are unclosed")
	}
	var name, displacement string
	if match != nil && discoveryAsmDeclOffsetWarning.MatchString(warning) {
		component := components[match[1]]
		if component == nil {
			return false, false, false, fmt.Errorf("reported name has no declaration component")
		}
		expected := component.name + "+" + strconv.FormatInt(component.offset, 10) + "(FP)"
		for i, innerName := range component.inner {
			if len(component.inner) > 1 {
				expected += ","
			}
			expected += " "
			if i == len(component.inner)-1 {
				expected += "or "
			}
			inner := components[innerName]
			expected += inner.name + "+" + strconv.FormatInt(inner.offset, 10) + "(FP)"
		}
		if match[3] != expected {
			return false, false, false, fmt.Errorf("reported expected component differs from the declaration")
		}
		name, displacement = match[1], match[2]
	} else if unknown := discoveryAsmDeclUnknownFPName.FindStringSubmatch(warning); unknown != nil {
		if components[unknown[1]] != nil || unknown[2] != unknown[4] {
			return false, false, false, fmt.Errorf("reported unknown name/offset does not match the declaration")
		}
		offset, err := strconv.ParseInt(unknown[2], 10, 64)
		if err != nil {
			return false, false, false, fmt.Errorf("reported offset: %w", err)
		}
		// Stock asmdecl overwrites varByOffset with each ordered component.
		// Reconstruct that exact name, rather than trusting an invented alias.
		var last *asmDeclFPComponent
		for _, component := range components {
			if component.offset <= offset && offset-component.offset < component.size &&
				(last == nil || last.order < component.order) {
				last = component
			}
		}
		if last == nil || last.name != unknown[3] || last.offset != offset {
			return false, false, false, fmt.Errorf("reported offset has no exact ordered declaration component")
		}
		name, displacement = unknown[1], unknown[2]
	} else {
		return false, false, false, fmt.Errorf("reported diagnostic has no FP-name obligation")
	}
	line, err := strconv.Atoi(reported)
	lines := discoveryAsmDeclUncommentedLines(source)
	if err != nil || line < 1 || line > len(lines) || !resultAliasOriginalFunction(lines, line, function) {
		return false, false, false, fmt.Errorf("reported line is not in the literal function")
	}
	parsed, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT ·probe(SB),4,$0-0\n"+lines[line-1]+"\nRET\n")
	if err != nil {
		return false, false, false, fmt.Errorf("literal FP instruction parse: %w", err)
	}
	if len(parsed.Funcs) != 1 || len(parsed.Funcs[0].Instrs) != 3 {
		return false, false, false, fmt.Errorf("literal FP instruction shape is not closed")
	}
	ins := parsed.Funcs[0].Instrs[1]
	offset, err := strconv.ParseInt(displacement, 10, 64)
	if err != nil {
		return false, false, false, fmt.Errorf("literal displacement: %w", err)
	}
	for index, operand := range ins.Args {
		literalAddress := operand.FPName == name && operand.FPOffset == offset &&
			(operand.Kind == plan9asm.OpFP || operand.Kind == plan9asm.OpFPAddr)
		if operand.Kind == plan9asm.OpMem {
			literalAddress = operand.Mem.Sym == name+"+"+displacement+"(FP)"
		}
		if !literalAddress {
			continue
		}
		for _, component := range components {
			if component.offset == offset && component.size > 0 {
				boundComponent = true
			}
		}
		expanded, expansionErr := resultAliasCPPRegisterInstruction(replay, file, line, function, ins)
		if expansionErr != nil {
			return false, false, boundComponent, expansionErr
		}
		width, write, known := plan9asm.X86FPAccessBytes(expanded, index, arch)
		if !known || width <= 0 {
			return false, false, boundComponent, fmt.Errorf("native FP access width/direction is not closed for %s operand %d", ins.Op, index)
		}
		for _, addressed := range components {
			if addressed.offset != offset || addressed.size != width || !asmDeclFPComponentCovered(addressed, components) {
				continue
			}
			if write && !addressed.result {
				return false, false, boundComponent, fmt.Errorf("native FP access writes an incoming parameter")
			}
			return true, addressed.result || write || name == "ret" || strings.HasPrefix(name, "ret_"), boundComponent, nil
		}
	}
	return false, false, boundComponent, fmt.Errorf("native FP span does not match an occupied declaration component")
}

func asmDeclFPComponentCovered(component *asmDeclFPComponent, components map[string]*asmDeclFPComponent) bool {
	if component.leaf {
		return true
	}
	// A whole native SIMD component is not a permission to read type padding.
	// Only its complete occupied byte span may be observed; this says nothing
	// about a native pointer or a separately allocated LLVM FP backing.
	if component.size <= 0 || component.size > 64 {
		return false
	}
	for off := component.offset; off < component.offset+component.size; off++ {
		covered := false
		for _, leaf := range components {
			if leaf.leaf && leaf.result == component.result && leaf.offset <= off && off < leaf.offset+leaf.size {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func resultAliasOriginalFunction(lines []string, line int, function string) bool {
	name := ""
	for _, current := range lines[:line] {
		if text := discoveryAsmDeclLiteralText.FindStringSubmatch(current); text != nil {
			name = text[1]
		} else if strings.HasPrefix(strings.TrimSpace(current), "TEXT") {
			name = ""
		}
	}
	return name == function
}
