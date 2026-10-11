package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestInvalidSM3SourceEvidenceIsPinnedPerExactVersion(t *testing.T) {
	skips, err := loadInvalidMachineCodeSkips(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		module  string
		version string
		sha256  string
	}{
		{
			module: "gitee.com/zhaochuninhefei/gmgo", version: "v0.1.1",
			sha256: "b22e4380d11a11777021d72bb1688283850d52c3ce3f9b36d31cb60802951d77",
		},
		{
			module: "github.com/initLijing/gmsm", version: "v0.15.6",
			sha256: "4f4a7ff92198391b93b6addcffb90735eba4fd8d3b5fa4d5d904874eacca0538",
		},
	} {
		t.Run(test.module, func(t *testing.T) {
			want := discoveryInvalidMachineCodeEvidence{
				AsmFile: "sm3/sm3blockni_arm64.s", SHA256: test.sha256,
				SourceExpression: "WORD $0x05254bce", Word: "0x05254bce",
				Architecture: "arm64",
			}
			skip := skips[test.module+"@"+test.version]
			for _, item := range skip.Evidence {
				if item == want {
					return
				}
			}
			t.Fatal("missing independently authenticated SM3 source witness")
		})
	}
}

func TestInvalidSM3EncodingCannotExcludeTheValidLittleEndianWord(t *testing.T) {
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal("required LLVM 22 llc: ", err)
	}
	decoder, err := discoveryLLVMDecoder(llc)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		word    uint32
		invalid bool
	}{
		{name: "original byte-swapped WORD", word: 0x05254bce, invalid: true},
		{name: "valid SM3SS1 word", word: 0xce4b2505},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := rejectInvalidMachineCodeWithLLVM(ctx, decoder, "arm64", test.word)
			if (err == nil) != test.invalid {
				t.Fatalf("word %#08x: invalid=%t, independent LLVM result=%v", test.word, test.invalid, err)
			}
		})
	}
}
