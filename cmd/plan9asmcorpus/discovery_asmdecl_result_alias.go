package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm"
)

var discoveryAsmDeclUnwrittenResult = regexp.MustCompile(`^RET without writing to ([1-9][0-9]*)-byte ret\+([0-9]+)\(FP\)$`)

// This is failure-only: it preserves the original completed analysis receipt,
// not a new diagnostic category or permission to exclude source. An incomplete
// Go-list/typecheck failure remains eligible for the existing testless retry.
func discoveryAsmDeclHasUnprovedResultWarning(err error) bool {
	failures, observed := discoveryAsmDeclObservedFailures(err)
	if !observed {
		return false
	}
	for _, failure := range failures {
		for _, line := range strings.Split(failure.output, "\n") {
			position := discoveryAsmDeclPosition(strings.TrimSpace(line))
			if position != nil && discoveryAsmDeclUnwrittenResult.MatchString(position[6]) {
				return true
			}
		}
	}
	return false
}

// Preserve a completed typed ABI obligation before testless retry can remove
// its declaration. Metadata padding/name warnings have already been filtered
// by the caller. This cannot turn a diagnostic into success or source N/A.
func discoveryAsmDeclHasCompletedABIObligation(err error) bool {
	failures, observed := discoveryAsmDeclObservedFailures(err)
	if !observed {
		return false
	}
	for _, failure := range failures {
		for _, line := range strings.Split(failure.output, "\n") {
			line = strings.TrimSpace(line)
			position := discoveryAsmDeclPosition(line)
			if position != nil && (discoveryAsmDeclUnwrittenResult.MatchString(position[6]) ||
				discoveryAsmDeclConcreteABIWarning(line)) {
				return true
			}
		}
	}
	return false
}

// This is a private, per-actual-unit diagnostic filter, not a portable proof,
// analyzer success receipt or translation permission. Precise FP-name warnings
// use declaration/native-width evidence; RET warnings additionally require the
// whole result-byte proof. The observed failure remains in the plan's raw
// receipt inventory; every other diagnostic and the real Wait result survive.
func (plan *directAsmDeclPlan) filterResultAliasWarnings(unit directAsmDeclUnit, original error) error {
	failure, observed := discoveryAsmDeclObservedFailure(original)
	command := strings.Join([]string{plan.GoBinary, "tool", "vet", "-asmdecl", unit.Filename}, " ")
	if !observed || failure.directory != plan.Dir || failure.command != command {
		return original
	}
	sealedUnit := false
	for _, actual := range plan.Units {
		if reflect.DeepEqual(actual, unit) {
			sealedUnit = true
		}
	}
	if !sealedUnit {
		return original
	}
	// This CPP reconstruction closes only the observed ordinary builtin
	// target/CPU defines and original package/SDK includes. Explicit flags can
	// change -D, -I, trimpath or build-mode routing; do not guess which are
	// harmless. Experiment/package-special assembler contexts stay unclosed.
	flags, flagsObserved := plan.SDK["GOFLAGS"]
	experiments, experimentsObserved := plan.SDK["GOEXPERIMENT"]
	ordinary := false
	packageMatches := 0
	for _, pkg := range plan.Packages {
		if pkg.ImportPath == unit.PackageID {
			packageMatches++
			ordinary = !pkg.Standard && pkg.Module != nil
		}
	}
	if !flagsObserved || flags != "" || !experimentsObserved || experiments != "" ||
		packageMatches != 1 || !ordinary {
		return original
	}
	lines := strings.Split(failure.output, "\n")
	hasAlias := false
	for _, line := range lines {
		if position := discoveryAsmDeclWarningPosition.FindStringSubmatch(strings.TrimSpace(line)); position != nil &&
			(discoveryAsmDeclUnwrittenResult.MatchString(position[6]) || discoveryAsmDeclNamedOffset.MatchString(position[6]) || discoveryAsmDeclUnknownFPName.MatchString(position[6])) {
			hasAlias = true
		}
	}
	if !hasAlias || plan.SDK["GOARCH"] != "amd64" && plan.SDK["GOARCH"] != "386" || plan.verifyUnitBytes(unit) != nil {
		return original
	}
	declarations, err := plan.resultAliasDeclarations(unit)
	if err != nil {
		return original // An unclosed type/import/header is not source N/A.
	}
	defines, err := plan9asm.GoAssemblerDefinesForEnvironment(plan.SDK["GOOS"], plan.SDK["GOARCH"], plan.SDK)
	if err != nil {
		return original
	}
	proofErrors := make(map[string]error)
	literalErrors := make(map[string]error)
	parsedSources := make(map[string]*resultAliasCPPReplay)
	parseErrors := make(map[string]error)
	componentMaps := make(map[string]map[string]*asmDeclFPComponent)
	componentCount := 0
	unclosedAlias := false
	var obligations []error
	// This only describes a source position already bound by the original
	// receipt, selected file, declaration and literal FP component. It is not
	// a new observed command, exclusion category or initialization permission.
	retainReason := func(stage, file string, position []string, reason error) {
		if relative, err := filepath.Rel(plan.Dir, file); err == nil {
			file = filepath.ToSlash(relative)
		}
		obligations = append(obligations, fmt.Errorf("FP alias proof stage=%s file=%s:%s arch=%s symbol=%s: %w",
			stage, file, position[2], position[4], position[5], reason))
	}
	unwrittenFunctions := make(map[string]bool)
	for _, line := range lines {
		if position := discoveryAsmDeclPosition(strings.TrimSpace(line)); position != nil &&
			discoveryAsmDeclUnwrittenResult.MatchString(position[6]) {
			unwrittenFunctions[position[5]] = true
		}
	}
	retained := make([]string, 0, len(lines))
	for _, line := range lines {
		position := discoveryAsmDeclWarningPosition.FindStringSubmatch(strings.TrimSpace(line))
		if position == nil || position[4] != plan.SDK["GOARCH"] {
			retained = append(retained, line)
			continue
		}
		warning := discoveryAsmDeclUnwrittenResult.FindStringSubmatch(position[6])
		declaration, declared := declarations[position[5]]
		if !declared {
			retained = append(retained, line)
			continue
		}
		sig := declaration.sig
		file, source := plan.resultAliasSource(unit, position[1])
		if file == "" {
			retained = append(retained, line)
			continue
		}
		replay, parsedBefore := parsedSources[file]
		if !parsedBefore {
			replay, parseErrors[file] = plan.resultAliasCPP(unit, file, source, defines)
			parsedSources[file] = replay
		}
		var function *plan9asm.Func
		if replay != nil {
			for index := range replay.parsed.Funcs {
				if replay.parsed.Funcs[index].Sym == "·"+position[5] {
					if function != nil {
						function = nil
						break
					}
					function = &replay.parsed.Funcs[index]
				}
			}
		}
		needsResult := true
		components, componentsChecked := componentMaps[position[5]]
		if warning == nil && !componentsChecked {
			components, _ = asmDeclFPComponents(declaration)
			if len(components) > 16384-componentCount {
				components = nil
			}
			componentCount += len(components)
			componentMaps[position[5]] = components
		}
		if warning != nil {
			if function == nil || len(sig.Frame.Results) != 1 {
				retained = append(retained, line)
				continue
			}
			offset, offsetErr := strconv.ParseInt(warning[2], 10, 64)
			width, widthErr := strconv.ParseInt(warning[1], 10, 64)
			result := sig.Frame.Results[0]
			if offsetErr != nil || widthErr != nil || result.Offset != offset || !resultAliasWarningWidth(sig.Ret, width) ||
				!resultAliasOriginalRET(source, position[2], position[5]) {
				retained = append(retained, line)
				continue
			}
		} else {
			matched, required, boundComponent, nativeErr := resultAliasOriginalFP(source, position[2], position[5], position[6], plan.SDK["GOARCH"], components, file, replay)
			// An existing real RET obligation already prevents source exclusion
			// and testless retry. Keep that original failure's identity when an
			// unknown-result name cannot close its byte proof. A name-only
			// warning must instead carry explicit failure-only Context.
			needsContext := discoveryAsmDeclNamedOffset.MatchString(position[6]) || !unwrittenFunctions[position[5]]
			key := file + "\x00" + position[5]
			literalErr, checked := literalErrors[key]
			// A closed parameter read needs its exact emitted instruction, not
			// unrelated literal macro bodies. Result authority still requires
			// the stricter whole-function literal/CPP and CFG proofs.
			if required && !checked && function != nil {
				literalErr = resultAliasLiteralCPPFunction(source, *function)
				literalErrors[key] = literalErr
			}
			if !matched || function == nil || required && literalErr != nil {
				unclosedAlias = unclosedAlias || boundComponent && needsContext
				if boundComponent && needsContext {
					switch {
					case parseErrors[file] != nil:
						retainReason("cpp-replay", file, position, parseErrors[file])
					case !matched:
						retainReason("native-access", file, position, nativeErr)
					case function == nil:
						retainReason("cpp-function", file, position, fmt.Errorf("expanded function is missing or ambiguous"))
					default:
						retainReason("literal-cpp", file, position, literalErr)
					}
				}
				retained = append(retained, line)
				continue
			}
			needsResult = required
		}
		if !needsResult {
			continue
		}
		key := file + "\x00" + position[5]
		if _, checked := proofErrors[key]; !checked {
			proofErrors[key] = plan9asm.CheckX86ABI0ResultInitialization(*function, sig, plan.SDK["GOARCH"])
		}
		if proofErrors[key] != nil {
			needsContext := warning == nil && (discoveryAsmDeclNamedOffset.MatchString(position[6]) || !unwrittenFunctions[position[5]])
			unclosedAlias = unclosedAlias || needsContext
			if needsContext {
				retainReason("result-bytes", file, position, proofErrors[key])
			}
			retained = append(retained, line)
		}
	}
	if unclosedAlias {
		// The actual declaration and literal locate a physical component, but
		// cannot certify this access/CPP/result obligation. Keep the entire
		// original receipt (including mixed diagnostics) as failure, not source
		// exclusion or a warning eligible for testless retry.
		return errors.Join(original, fmt.Errorf("%w: %w: original FP alias has an unclosed native byte/CPP/result obligation",
			errDiscoveryAsmDeclSourceProof, plan9asm.ErrProbeNeedsContext), errors.Join(obligations...))
	}
	if len(retained) == len(lines) {
		return original
	}
	plan.resultAliasRawFailures = append(plan.resultAliasRawFailures, failure)
	for _, line := range retained {
		trim := strings.TrimSpace(line)
		if trim != "" && trim != "# "+unit.PackageID && trim != "# "+unit.Config.ImportPath {
			copy := *failure
			copy.output = strings.Join(retained, "\n")
			copy.display = limitDiscoveryEvidence(copy.output, 64<<10)
			return &copy
		}
	}
	return nil
}

func resultAliasWarningWidth(typ plan9asm.LLVMType, width int64) bool {
	wanted := map[plan9asm.LLVMType]int64{
		plan9asm.I1: 1, plan9asm.I8: 1, plan9asm.I16: 2, plan9asm.I32: 4,
		plan9asm.I64: 8, "float": 4, "double": 8,
	}
	return width > 0 && wanted[typ] == width
}

type resultAliasImporter func(string) (*types.Package, error)

func (load resultAliasImporter) Import(path string) (*types.Package, error) { return load(path) }

func (plan *directAsmDeclPlan) resultAliasDeclarations(unit directAsmDeclUnit) (map[string]resultAliasDeclaration, error) {
	fset := token.NewFileSet()
	var files []*ast.File
	bodyless := make(map[string]bool)
	for _, name := range unit.Config.GoFiles {
		data, err := plan.resultAliasRead(name)
		if err != nil {
			return nil, err
		}
		file, err := parser.ParseFile(fset, name, data, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
		for _, declaration := range file.Decls {
			if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Body == nil && fn.Recv == nil {
				if bodyless[fn.Name.Name] {
					return nil, fmt.Errorf("duplicate actual bodyless declaration")
				}
				bodyless[fn.Name.Name] = true
			}
		}
	}
	compiler := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		name, present := unit.Config.PackageFile[path]
		if !present {
			return nil, fmt.Errorf("actual export edge is missing: %s", path)
		}
		data, err := plan.resultAliasRead(name)
		return io.NopCloser(bytes.NewReader(data)), err
	})
	sizes := types.SizesFor("gc", plan.SDK["GOARCH"])
	config := types.Config{Sizes: sizes, GoVersion: unit.Config.GoVersion, Importer: resultAliasImporter(func(path string) (*types.Package, error) {
		resolved, present := unit.Config.ImportMap[path]
		if !present {
			return nil, fmt.Errorf("actual import mapping is missing: %s", path)
		}
		return compiler.Import(resolved)
	})}
	pkg, err := config.Check(unit.Config.ImportPath, fset, files, nil)
	if err != nil {
		return nil, err
	}
	declarations := make(map[string]resultAliasDeclaration)
	for name := range bodyless {
		fn, ok := pkg.Scope().Lookup(name).(*types.Func)
		if !ok {
			return nil, fmt.Errorf("actual typed declaration is missing")
		}
		sig, err := plan9asm.DeriveGoFuncABI0Signature(pkg.Path()+"."+name, fn, plan.SDK["GOARCH"], sizes)
		if err == nil {
			declarations[name] = resultAliasDeclaration{sig: sig, fn: fn, sizes: sizes}
		}
	}
	return declarations, nil
}

func (plan *directAsmDeclPlan) resultAliasRead(name string) ([]byte, error) {
	input, bound := plan.fileIndex[name]
	if !bound || input.Size < 0 || input.Size > 64<<20 {
		return nil, fmt.Errorf("result proof input lacks bounded actual source binding: %s", name)
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 64<<20+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) != input.Size || sha256.Sum256(data) != input.SHA {
		return nil, fmt.Errorf("result proof input changed: %s (read %v, close %v)", name, readErr, closeErr)
	}
	return data, nil
}

func (plan *directAsmDeclPlan) resultAliasSource(unit directAsmDeclUnit, reported string) (string, []byte) {
	if !filepath.IsAbs(reported) {
		reported = filepath.Join(plan.Dir, reported)
	}
	for _, file := range unit.Config.NonGoFiles {
		if filepath.Clean(reported) == file && filepath.Ext(file) == ".s" {
			data, err := plan.resultAliasRead(file)
			if err == nil {
				return file, data
			}
		}
	}
	return "", nil
}

func resultAliasOriginalRET(source []byte, reported, function string) bool {
	line, err := strconv.Atoi(reported)
	lines := discoveryAsmDeclUncommentedLines(source)
	if err != nil || line < 1 || line > len(lines) || strings.TrimSpace(lines[line-1]) != "RET" {
		return false
	}
	name := ""
	for _, current := range lines[:line] {
		if text := discoveryAsmDeclLiteralText.FindStringSubmatch(current); text != nil {
			name = text[1]
		} else if strings.HasPrefix(strings.TrimSpace(current), "TEXT") {
			name = "" // Unknown original TEXT syntax cannot borrow another entry.
		}
	}
	return name == function
}

type resultAliasCPPReplay struct {
	parsed      *plan9asm.File
	observation plan9asm.AssemblyCPPObservation
	tokens      []plan9asm.AssemblyCPPOutputToken
}

func (plan *directAsmDeclPlan) resultAliasCPP(unit directAsmDeclUnit, file string, source []byte, defines []string) (*resultAliasCPPReplay, error) {
	total := len(source)
	observation, tokens, err := plan9asm.ObserveAssemblyCPPOutput(string(source), plan9asm.AssemblyPreprocessOptions{
		FileName: file, Defines: defines,
		ReadInclude: func(_ string, include string) (string, []byte, error) {
			// cmd/asm uses the fixed actual package CWD, not the containing
			// header's directory. Unbound generated/escaping inputs stay F.
			if filepath.Base(include) != include || include == "go_asm.h" {
				return "", nil, fmt.Errorf("unclosed result-proof include context")
			}
			name := filepath.Join(unit.Config.Dir, include)
			if _, err := os.Lstat(name); os.IsNotExist(err) {
				name = filepath.Join(plan.SDK["GOROOT"], "pkg", "include", include)
			}
			data, err := plan.resultAliasRead(name)
			if err != nil {
				return "", nil, err
			}
			if len(data) > (64<<20)-total {
				return "", nil, fmt.Errorf("result-proof CPP input budget exhausted")
			}
			total += len(data)
			return name, data, nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("result-proof CPP is unclosed: %w", err)
	}
	if len(observation.Output) > 64<<20 {
		return nil, fmt.Errorf("result-proof CPP expanded byte budget exhausted")
	}
	parsed, err := plan9asm.Parse(plan9asm.ArchAMD64, observation.Output)
	if err != nil {
		return nil, err
	}
	return &resultAliasCPPReplay{parsed: parsed, observation: observation, tokens: tokens}, nil
}
