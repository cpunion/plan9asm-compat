package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/scanner"

	"github.com/llgo-compat/plan9asm/internal/goabi"
)

var discoveryAsmDeclZeroArgs = regexp.MustCompile(
	`^(.+\.s):([0-9]+)(?::[0-9]+)?: \[([^]]+)\] ([^:]+): wrong argument size 0; expected \$\.\.\.-([1-9][0-9]*)$`,
)

var discoveryAsmDeclPaddedArgs = regexp.MustCompile(
	`^(.+\.s):([0-9]+)(?::[0-9]+)?: \[([^]]+)\] ([^:]+): wrong argument size ([1-9][0-9]*); expected \$\.\.\.-([0-9]+)$`,
)

var errDiscoveryAsmDeclSourceProof = errors.New("cannot verify asmdecl source metadata")

var errDiscoveryAsmDeclNoSelectedTests = errors.New("testless asmdecl retry found no selected test files")

var discoveryAsmDeclWarningPosition = regexp.MustCompile(
	`^(.+\.s):([1-9][0-9]*)(?::([1-9][0-9]*))?: \[(386|amd64|arm|arm64|wasm)\] ([^ :]+): (.+)$`,
)

var discoveryAsmDeclArgumentSizeWarning = regexp.MustCompile(
	`^wrong argument size ([0-9]+); expected \$\.\.\.-([0-9]+)$`,
)

var discoveryAsmDeclOffsetWarning = regexp.MustCompile(
	`^invalid offset [^ +();]+\+-?[0-9]+\(FP\); expected [^ +();]+\+-?[0-9]+\(FP\)(?:,? (?:or )?[^ +();]+\+-?[0-9]+\(FP\))*$`,
)

var discoveryAsmDeclResolvedNameWarning = regexp.MustCompile(
	`^(?:unknown variable [^ ;]+|use of unnamed argument [^;]+); offset ([0-9]+) is [^ +()]+\+([0-9]+)\(FP\)$`,
)

var discoveryAsmDeclCompleteWidthWarning = regexp.MustCompile(
	`^invalid [A-Za-z0-9.]+ of [^;]+\(FP\); .+ is [0-9]+-byte value(?: containing(?:,? (?:and )?[^ +(),]+\+[0-9]+\(FP\))+)?$`,
)

var discoveryAsmDeclPackageHeading = regexp.MustCompile(
	`^# [^ \t\r\n]+(?: \[[^ \t\r\n]+\])?$`,
)

// These warnings are not an assembler, type/layout or object certificate.
// They may reach the independent translator only after a completed actual
// analysis. Unknown diagnostics and real unwritten results are not warnings
// that this path can dismiss.
func discoveryAsmDeclOnlyKnownNonABIWarnings(err error) bool {
	failures, observed := discoveryAsmDeclObservedFailures(err)
	if !observed || isDiscoveryInfrastructureFailure(err) {
		return false
	}
	for _, failure := range failures {
		count := 0
		for _, line := range strings.Split(failure.output, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || discoveryAsmDeclPackageHeading.MatchString(line) {
				continue
			}
			if !discoveryAsmDeclKnownNonABIWarning(line) {
				return false
			}
			count++
		}
		if count == 0 {
			return false
		}
	}
	return true
}

func discoveryAsmDeclObservedFailure(err error) (*discoveryCapturedCommandError, bool) {
	failure, direct := err.(*discoveryCapturedCommandError)
	if !direct || failure == nil {
		return nil, false
	}
	exit, observed := failure.cause.(*exec.ExitError)
	return failure, observed && exit.ExitCode() == 1
}

// A batch retains the actual independent Wait receipts. It is created only
// after every selected unit and the final input guards finish, never from a
// report, an arbitrary errors.Join, or the first failing unit's exit status.
type discoveryAsmDeclAnalysisError struct {
	failures  []*discoveryCapturedCommandError
	completed int
	expected  int
}

func (batch *discoveryAsmDeclAnalysisError) Error() string {
	var messages []string
	for _, failure := range batch.failures {
		messages = append(messages, failure.Error())
	}
	return strings.Join(messages, "\n")
}

func (batch *discoveryAsmDeclAnalysisError) Unwrap() []error {
	failures := make([]error, len(batch.failures))
	for index, failure := range batch.failures {
		failures[index] = failure
	}
	return failures
}

func combineDiscoveryAsmDeclAnalysisFailures(failures []error, completed, expected int) error {
	if expected <= 0 || completed != expected || len(failures) > completed {
		return errors.Join(append(failures, fmt.Errorf("%w: incomplete official analysis batch (%d/%d units)", errDiscoveryAsmDeclSourceProof, completed, expected))...)
	}
	if len(failures) == 0 {
		return nil
	}
	if len(failures) == 1 {
		return failures[0]
	}
	batch := &discoveryAsmDeclAnalysisError{completed: completed, expected: expected}
	seen := make(map[*discoveryCapturedCommandError]bool, len(failures))
	for _, err := range failures {
		failure, observed := discoveryAsmDeclObservedFailure(err)
		if !observed || isDiscoveryInfrastructureFailure(err) || seen[failure] {
			return errors.Join(failures...)
		}
		seen[failure] = true
		batch.failures = append(batch.failures, failure)
	}
	return batch
}

func discoveryAsmDeclObservedFailures(err error) ([]*discoveryCapturedCommandError, bool) {
	if failure, observed := discoveryAsmDeclObservedFailure(err); observed {
		return []*discoveryCapturedCommandError{failure}, true
	}
	batch, direct := err.(*discoveryAsmDeclAnalysisError)
	if !direct || batch == nil || batch.expected <= 0 || batch.completed != batch.expected ||
		len(batch.failures) < 2 || len(batch.failures) > batch.completed {
		return nil, false
	}
	seen := make(map[*discoveryCapturedCommandError]bool, len(batch.failures))
	for _, failure := range batch.failures {
		if _, observed := discoveryAsmDeclObservedFailure(failure); !observed || isDiscoveryInfrastructureFailure(failure) || seen[failure] {
			return nil, false
		}
		seen[failure] = true
	}
	return batch.failures, true
}

func discoveryAsmDeclPosition(line string) []string {
	position := discoveryAsmDeclWarningPosition.FindStringSubmatch(line)
	if position == nil {
		return nil
	}
	for _, value := range position[2:4] {
		if value != "" {
			if _, err := strconv.ParseUint(value, 10, 32); err != nil {
				return nil
			}
		}
	}
	// Stock asmdecl chooses an explicit filename architecture before build
	// tags. Such a source cannot borrow another architecture's width rules.
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		if strings.HasSuffix(position[1], "_"+arch+".s") && position[4] != arch {
			return nil
		}
	}
	return position
}

func discoveryAsmDeclKnownNonABIWarning(line string) bool {
	position := discoveryAsmDeclPosition(line)
	if position == nil {
		return false
	}
	diagnostic := position[6]
	if diagnostic == "function "+position[5]+" missing Go declaration" {
		return true
	}
	if alias := discoveryAsmDeclResolvedNameWarning.FindStringSubmatch(diagnostic); alias != nil {
		actual, actualErr := strconv.ParseInt(alias[1], 10, 64)
		expected, expectedErr := strconv.ParseInt(alias[2], 10, 64)
		return actualErr == nil && expectedErr == nil && actual == expected
	}
	return discoveryAsmDeclCompleteWidthWarning.MatchString(diagnostic) &&
		isDiscoveryAsmDeclEqualWidthMove(strings.ToLower(line))
}

func discoveryAsmDeclConcreteABIWarning(line string) bool {
	position := discoveryAsmDeclPosition(line)
	if position == nil || !isDiscoveryAsmDeclABIMismatch(line) {
		return false
	}
	diagnostic := position[6]
	if size := discoveryAsmDeclArgumentSizeWarning.FindStringSubmatch(diagnostic); size != nil {
		actual, actualErr := strconv.ParseInt(size[1], 10, 64)
		expected, expectedErr := strconv.ParseInt(size[2], 10, 64)
		return actualErr == nil && expectedErr == nil && actual != expected
	}
	return discoveryAsmDeclOffsetWarning.MatchString(diagnostic) ||
		discoveryAsmDeclCompleteWidthWarning.MatchString(diagnostic)
}

// Validate the entire completed analysis before excluding any source. One
// attributable ABI line must never swallow another file's RET/typecheck or
// unknown diagnostic, nor an unexplained outer/capture failure.
func discoveryAsmDeclCompleteABIDiagnostics(candidateFiles []string, err error) ([]string, bool) {
	failures, observed := discoveryAsmDeclObservedFailures(err)
	if !observed || isDiscoveryInfrastructureFailure(err) {
		return nil, false
	}
	var abiLines []string
	for _, failure := range failures {
		count := 0
		for _, line := range strings.Split(filepath.ToSlash(failure.output), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || discoveryAsmDeclPackageHeading.MatchString(line) {
				continue
			}
			matched := false
			for _, file := range candidateFiles {
				if discoveryAsmDeclLineNamesFile(line, file) {
					matched = true
					break
				}
			}
			if !matched {
				return nil, false
			}
			count++
			if discoveryAsmDeclKnownNonABIWarning(line) {
				continue
			}
			if !discoveryAsmDeclConcreteABIWarning(line) {
				return nil, false
			}
			abiLines = append(abiLines, line)
		}
		if count == 0 {
			return nil, false
		}
	}
	return abiLines, len(abiLines) > 0
}

func discoveryAsmDeclOriginalDiagnosticFile(line string, err error) string {
	if failures, observed := discoveryAsmDeclObservedFailures(err); observed && len(failures) > 1 {
		var original string
		for _, failure := range failures {
			contains := false
			for _, outputLine := range strings.Split(filepath.ToSlash(failure.output), "\n") {
				if strings.TrimSpace(outputLine) == strings.TrimSpace(line) {
					contains = true
					break
				}
			}
			if !contains {
				continue
			}
			physical := discoveryAsmDeclOriginalDiagnosticFile(line, failure)
			if physical == "" || original != "" && original != physical {
				return ""
			}
			original = physical
		}
		return original
	}
	failure, observed := discoveryAsmDeclObservedFailure(err)
	position := discoveryAsmDeclPosition(line)
	if !observed || position == nil || !filepath.IsAbs(failure.directory) {
		return ""
	}
	// An absolute diagnostic cannot borrow an unobserved/nonexistent CWD.
	// A removed owned retry stage may resolve only through its one exact
	// producer binding to an original directory that still exists.
	directory, bound := discoveryAsmDeclOriginalPath(failure, failure.directory)
	if !bound {
		return ""
	}
	directoryInfo, directoryErr := os.Stat(directory)
	if directoryErr != nil || !directoryInfo.IsDir() {
		return ""
	}
	reported := filepath.FromSlash(position[1])
	if !filepath.IsAbs(reported) {
		reported = filepath.Join(failure.directory, reported)
	}
	physical, bound := discoveryAsmDeclOriginalPath(failure, reported)
	if !bound {
		return ""
	}
	info, statErr := os.Stat(physical)
	if statErr != nil || !info.Mode().IsRegular() {
		return ""
	}
	return physical
}

func discoveryAsmDeclOriginalPath(failure *discoveryCapturedCommandError, filename string) (string, bool) {
	if !filepath.IsAbs(filename) {
		return "", false
	}
	for stage, original := range failure.asmdeclOrigins {
		if !filepath.IsAbs(stage) || stage != filepath.Clean(stage) ||
			!filepath.IsAbs(original) || original != filepath.Clean(original) || stage == original {
			return "", false
		}
		// Reject overlapping maps before looking up a path. Otherwise map
		// iteration order could assign one original file to different modules.
		for other := range failure.asmdeclOrigins {
			if other != stage {
				if _, nested := discoveryAsmDeclRelativeUnder(stage, other); nested {
					return "", false
				}
			}
		}
	}
	for stage, original := range failure.asmdeclOrigins {
		if relative, inside := discoveryAsmDeclRelativeUnder(stage, filename); inside {
			filename = filepath.Join(original, relative)
			break
		}
	}
	physical, pathErr := filepath.EvalSymlinks(filename)
	return physical, pathErr == nil
}

func discoveryAsmDeclRelativeUnder(directory, filename string) (string, bool) {
	relative, err := filepath.Rel(directory, filename)
	return relative, err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func discoveryAsmDeclLineMatchesOriginalFile(moduleDir, line, file string, err error) bool {
	if !filepath.IsAbs(moduleDir) || filepath.IsAbs(file) {
		return false
	}
	relative := filepath.Clean(filepath.FromSlash(file))
	if relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	physicalRoot, rootErr := filepath.EvalSymlinks(moduleDir)
	expected, pathErr := filepath.EvalSymlinks(filepath.Join(moduleDir, relative))
	if rootErr != nil || pathErr != nil {
		return false
	}
	if _, inside := discoveryAsmDeclRelativeUnder(physicalRoot, expected); !inside {
		return false
	}
	return discoveryAsmDeclOriginalDiagnosticFile(line, err) == expected
}

func discoveryAsmDeclLocationsBelongToCandidate(moduleDir string, candidateFiles []string, err error) bool {
	failures, observed := discoveryAsmDeclObservedFailures(err)
	if !observed {
		return false
	}
	for _, failure := range failures {
		for _, line := range strings.Split(filepath.ToSlash(failure.output), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || discoveryAsmDeclPackageHeading.MatchString(line) {
				continue
			}
			matched := false
			for _, file := range candidateFiles {
				if discoveryAsmDeclLineMatchesOriginalFile(moduleDir, line, file, err) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	return true
}

// Only literal TEXT declarations are conclusive here. A macro/expression,
// different symbol, stale line number or unselected source must not turn an
// actual ABI failure into an unspecified-argument warning.
var discoveryAsmDeclLiteralText = regexp.MustCompile(
	`^\s*TEXT\s+[^,\s]*·([^\s(]+)\(SB\)\s*,\s*(?:[0-9A-Z|+()]+\s*,\s*)?\$(-?[0-9]+)(?:-([0-9]+))?\s*$`,
)

func filterDiscoveryAsmDeclTextMetadata(
	ctx context.Context,
	dir string,
	env, buildTags, patterns []string,
	modfilePath string,
	err error,
) error {
	if err == nil || isDiscoveryInfrastructureFailure(err) {
		return err
	}
	if failures, observed := discoveryAsmDeclObservedFailures(err); observed && len(failures) > 1 {
		var retained []error
		for _, failure := range failures {
			filtered := filterDiscoveryAsmDeclTextMetadata(ctx, dir, env, buildTags, patterns, modfilePath, failure)
			if filtered != nil {
				retained = append(retained, filtered)
			}
		}
		batch := err.(*discoveryAsmDeclAnalysisError)
		return combineDiscoveryAsmDeclAnalysisFailures(retained, batch.completed, batch.expected)
	}
	var failure *discoveryCapturedCommandError
	if !errors.As(err, &failure) {
		return err
	}
	lines := strings.Split(failure.output, "\n")
	hasMetadataWarning := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if discoveryAsmDeclZeroArgs.MatchString(line) || discoveryAsmDeclPaddedArgs.MatchString(line) {
			hasMetadataWarning = true
			break
		}
	}
	if !hasMetadataWarning {
		return err
	}
	// A diagnostic-shaped string does not establish a completed vet analysis.
	// Capture supplies a direct Wait result on an ordinary failure; wrappers,
	// joined failures and any other exit must remain visible for retry instead
	// of acquiring the narrow metadata-only filtering permission.
	exit, observed := failure.cause.(*exec.ExitError)
	if err != failure || !observed || exit.ExitCode() != 1 {
		return errors.Join(err, fmt.Errorf("%w: metadata filtering requires an observed plain exit 1", errDiscoveryAsmDeclSourceProof))
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# ") && !discoveryAsmDeclPackageHeading.MatchString(trimmed) {
			return err
		}
	}
	requestedDirectory, directoryErr := filepath.Abs(dir)
	if directoryErr == nil {
		requestedDirectory, directoryErr = filepath.EvalSymlinks(requestedDirectory)
	}
	observedDirectory, observedErr := filepath.EvalSymlinks(failure.directory)
	if directoryErr != nil || observedErr != nil || !filepath.IsAbs(failure.directory) || requestedDirectory != observedDirectory {
		return errors.Join(err, fmt.Errorf("%w: metadata lookup differs from the observed command directory", errDiscoveryAsmDeclSourceProof))
	}

	args := []string{"list", "-json"}
	if modfilePath != "" {
		args = append(args, "-modfile="+modfilePath)
	}
	if len(buildTags) != 0 {
		args = append(args, "-tags="+strings.Join(buildTags, ","))
	}
	args = append(args, patterns...)
	output, listErr := runCapturedCommandOutput(ctx, dir, env, "go", args...)
	if listErr != nil {
		return errors.Join(err, fmt.Errorf("%w: resolve selected sources: %w", errDiscoveryAsmDeclSourceProof, listErr))
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	var packages []discoveryGoListPackage
	for {
		var pkg discoveryGoListPackage
		if decodeErr := decoder.Decode(&pkg); decodeErr != nil {
			if decodeErr == io.EOF {
				break
			}
			return errors.Join(err, fmt.Errorf("%w: decode selected sources: %w", errDiscoveryAsmDeclSourceProof, decodeErr))
		}
		packages = append(packages, pkg)
	}
	commandDir, pathErr := filepath.Abs(dir)
	if pathErr == nil {
		commandDir, pathErr = filepath.EvalSymlinks(commandDir)
	}
	if pathErr != nil {
		return errors.Join(err, fmt.Errorf("%w: resolve command directory: %w", errDiscoveryAsmDeclSourceProof, pathErr))
	}
	for index := range packages {
		if !filepath.IsAbs(packages[index].Dir) {
			return errors.Join(err, fmt.Errorf("%w: selected package directory is not absolute", errDiscoveryAsmDeclSourceProof))
		}
		packages[index].Dir, pathErr = filepath.EvalSymlinks(packages[index].Dir)
		if pathErr != nil {
			return errors.Join(err, fmt.Errorf("%w: resolve selected package directory: %w", errDiscoveryAsmDeclSourceProof, pathErr))
		}
	}
	filtered := filterDiscoveryAsmDeclTextMetadataLines(lines, packages, commandDir)
	if strings.Join(filtered, "\n") == failure.output {
		return err
	}
	// Only package headings may remain when the ignored warning was the whole
	// failure. Other diagnostics retain the original exit and classification.
	onlyHeadings := true
	for _, line := range filtered {
		line = strings.TrimSpace(line)
		if line != "" && !discoveryAsmDeclPackageHeading.MatchString(line) {
			onlyHeadings = false
			break
		}
	}
	if onlyHeadings {
		return nil
	}
	copy := *failure
	copy.output = strings.Join(filtered, "\n")
	copy.display = limitDiscoveryEvidence(copy.output, 64<<10)
	return &copy
}

func filterDiscoveryAsmDeclTextMetadataLines(lines []string, packages []discoveryGoListPackage, commandDir string) []string {
	retained := make([]string, 0, len(lines))
	packagePath := ""
	for _, line := range lines {
		if strings.HasPrefix(line, "# ") {
			packagePath = strings.TrimSpace(strings.TrimPrefix(line, "# "))
			// Vet prints both '# package' and '# [package]' headings.
			packagePath = strings.Trim(packagePath, "[]")
		}
		trimmed := strings.TrimSpace(line)
		if discoveryAsmDeclPosition(trimmed) == nil {
			retained = append(retained, line)
			continue
		}
		match := discoveryAsmDeclZeroArgs.FindStringSubmatch(trimmed)
		if match != nil && discoveryAsmDeclHasLiteralUnspecifiedArgs(match, packagePath, packages, commandDir) {
			continue
		}
		match = discoveryAsmDeclPaddedArgs.FindStringSubmatch(trimmed)
		if match != nil && discoveryAsmDeclHasLiteralPaddedArgs(match, packagePath, packages, commandDir) {
			continue
		}
		retained = append(retained, line)
	}
	return retained
}

func discoveryAsmDeclHasLiteralUnspecifiedArgs(match []string, packagePath string, packages []discoveryGoListPackage, commandDir string) bool {
	if _, err := strconv.ParseInt(match[5], 10, 64); err != nil {
		return false
	}
	text := discoveryAsmDeclSelectedText(match[1], match[2], packagePath, packages, commandDir)
	if text == nil {
		return false
	}
	symbol := text[1]
	if beforeABI, _, ok := strings.Cut(symbol, "<ABI"); ok {
		symbol = beforeABI
	}
	if text[3] != "" {
		args, err := strconv.ParseInt(text[3], 10, 64)
		if err != nil || args != 0 {
			return false
		}
	}
	return symbol == match[4]
}

func discoveryAsmDeclHasLiteralPaddedArgs(match []string, packagePath string, packages []discoveryGoListPackage, commandDir string) bool {
	text := discoveryAsmDeclSelectedText(match[1], match[2], packagePath, packages, commandDir)
	if text == nil || text[3] == "" || strings.Contains(text[1], "<ABIInternal>") {
		return false
	}
	symbol := strings.TrimSuffix(text[1], "<ABI0>")
	declared, declaredErr := strconv.ParseInt(match[5], 10, 64)
	expected, expectedErr := strconv.ParseInt(match[6], 10, 64)
	actual, actualErr := strconv.ParseInt(text[3], 10, 64)
	return symbol == match[4] && declaredErr == nil && expectedErr == nil && actualErr == nil &&
		actual == declared && goabi.MatchesABI0TextSize(match[3], declared, expected)
}

func discoveryAsmDeclSelectedText(filename, reportedLine, packagePath string, packages []discoveryGoListPackage, commandDir string) []string {
	reported := filepath.Clean(filepath.FromSlash(filename))
	commandRelative := ""
	if commandDir != "" {
		if filepath.IsAbs(reported) {
			// Go may retain a logical PWD spelling for a selected package.
			// Resolve its directory, not a final file symlink or its basename.
			if physical, err := filepath.EvalSymlinks(filepath.Dir(reported)); err == nil {
				reported = filepath.Join(physical, filepath.Base(reported))
			}
		} else {
			// Vet positions are relative to its working directory, not the
			// selected package directory. Bind the complete reported path.
			commandRelative = filepath.Join(commandDir, reported)
		}
	}
	var selected string
	for _, pkg := range packages {
		if packagePath != "" && pkg.ImportPath != packagePath {
			continue
		}
		for _, name := range pkg.SFiles {
			file := filepath.Join(pkg.Dir, name)
			unboundBasename := commandDir == "" && reported == name
			if reported != file && !unboundBasename && commandRelative != file {
				continue
			}
			if selected != "" && selected != file {
				return nil
			}
			selected = file
		}
	}
	if selected == "" {
		return nil
	}
	source, err := os.ReadFile(selected)
	if err != nil {
		return nil
	}
	lineNumber, err := strconv.Atoi(reportedLine)
	lines := discoveryAsmDeclUncommentedLines(source)
	if err != nil || lineNumber < 1 || lineNumber > len(lines) {
		return nil
	}
	return discoveryAsmDeclLiteralText.FindStringSubmatch(lines[lineNumber-1])
}

// Go's assembly lexer uses text/scanner comments. Mask them without moving
// physical line numbers, including block-comment licenses before TEXT, while
// keeping comment delimiters inside DATA strings intact.
func discoveryAsmDeclUncommentedLines(source []byte) []string {
	var lexer scanner.Scanner
	lexer.Init(bytes.NewReader(source))
	lexer.Mode = scanner.ScanComments | scanner.ScanStrings | scanner.ScanRawStrings | scanner.ScanChars
	valid := true
	lexer.Error = func(*scanner.Scanner, string) { valid = false }
	uncommented := bytes.Clone(source)
	for token := lexer.Scan(); token != scanner.EOF; token = lexer.Scan() {
		if token != scanner.Comment {
			continue
		}
		start := lexer.Position.Offset
		end := start + len(lexer.TokenText())
		for index := start; index < end; index++ {
			if uncommented[index] != '\n' && uncommented[index] != '\r' {
				uncommented[index] = ' '
			}
		}
	}
	if !valid {
		return nil
	}
	return strings.Split(string(uncommented), "\n")
}
