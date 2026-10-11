package main

import (
	"go/build/constraint"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func benchmarkDiscoveryShortConstraintHeader(b *testing.B) {
	const source = "//go:build alpha && !beta\n\npackage fixture\n"
	open := func(string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(source)), nil
	}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		expression, err := discoveryFileBuildExpression("fixture.go", open)
		if err != nil || expression == nil || expression.String() != "alpha && !beta" {
			b.Fatalf("short original constraint changed: %v %v", expression, err)
		}
	}
}

func TestDiscoveryConstraintExpressionShortHeaderAllocationBound(t *testing.T) {
	result := testing.Benchmark(benchmarkDiscoveryShortConstraintHeader)
	t.Logf("short original header: %d B/op; %d allocs/op", result.AllocedBytesPerOp(), result.AllocsPerOp())
	// This measures only the original-source parser, not fixture creation or
	// any compiler/proof work. Leave headroom for reader, scanner and AST data,
	// but reject a fixed 64 KiB allocation for this tiny ordinary header.
	if result.AllocedBytesPerOp() >= 16<<10 {
		t.Fatalf("short constraint header allocates an oversized initial buffer: %d B/op", result.AllocedBytesPerOp())
	}
}

func BenchmarkDiscoveryConstraintExpressionShortHeader(b *testing.B) {
	benchmarkDiscoveryShortConstraintHeader(b)
}

func TestDiscoveryConstraintExpressionScannerGrowthAndLimit(t *testing.T) {
	const limit = 4 << 20
	for _, test := range []struct {
		name     string
		lineSize int
		wantErr  bool
	}{
		{name: "longer than the former initial buffer", lineSize: 70 << 10},
		{name: "largest delimited line within the scanner limit", lineSize: limit - 1},
		{name: "scanner limit remains an error", lineSize: limit, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, file := range []string{"fixture.go", "fixture.s"} {
				source := strings.Repeat("/", test.lineSize) + "\n//go:build alpha\n\npackage fixture\n"
				if file == "fixture.s" {
					source = strings.ReplaceAll(source, "package fixture", "TEXT ·Probe(SB),$0-0\nRET")
				}
				ctx := discoveryHeaderBoundaryContext(map[string]string{file: source})
				expression, err := discoveryFileBuildExpression(filepath.Join("virtual", file), ctx.OpenFile)
				if test.wantErr {
					if err == nil || expression != nil || !strings.Contains(err.Error(), "token too long") {
						t.Fatalf("%s lost the original scanner limit: expression=%v error=%v", file, expression, err)
					}
					continue
				}
				if err != nil || expression == nil || expression.String() != "alpha" {
					t.Fatalf("%s lost a constraint after buffer growth: expression=%v error=%v", file, expression, err)
				}
				ctx.BuildTags = []string{"alpha"}
				selected, err := ctx.MatchFile("virtual", file)
				if err != nil || !selected || !expression.Eval(func(tag string) bool { return tag == "alpha" }) {
					t.Fatalf("%s differs from the original Go header after buffer growth: selected=%v error=%v", file, selected, err)
				}
			}
		})
	}
}

type discoveryConstraintReadFailure struct{}

func (discoveryConstraintReadFailure) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

type discoveryConstraintClosingReader struct {
	io.Reader
	closed *bool
}

func (reader *discoveryConstraintClosingReader) Close() error {
	*reader.closed = true
	return nil
}

func TestDiscoveryConstraintExpressionReadFailureStillCloses(t *testing.T) {
	closed := false
	open := func(string) (io.ReadCloser, error) {
		return &discoveryConstraintClosingReader{
			Reader: io.MultiReader(strings.NewReader("//go:build alpha\n"), discoveryConstraintReadFailure{}),
			closed: &closed,
		}, nil
	}
	var expression constraint.Expr
	expression, err := discoveryFileBuildExpression("fixture.go", open)
	if err == nil || expression != nil || !strings.Contains(err.Error(), io.ErrUnexpectedEOF.Error()) || !closed {
		t.Fatalf("original read error or owned close disappeared: expression=%v error=%v closed=%v", expression, err, closed)
	}
}
