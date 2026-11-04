package main

import (
	"bytes"
	stdhex "encoding/hex"
	"fmt"
	"runtime"
	"strings"

	fasthex "github.com/tmthrgd/go-hex"
	"golang.org/x/sys/cpu"
)

func require(ok bool, format string, args ...any) {
	if !ok {
		panic(fmt.Sprintf(format, args...))
	}
}

func canary(data []byte, width int) bool {
	for _, value := range append(append([]byte(nil), data[:16]...), data[16+width:]...) {
		if value != 0xa5 {
			return false
		}
	}
	return true
}

func digestBytes(digest *uint64, data []byte) {
	for _, value := range data {
		*digest = (*digest ^ uint64(value)) * 1099511628211
	}
}

func main() {
	// Preserve actual detection. This never enables unsupported hardware or
	// labels the source's generic fallback as executed assembly coverage.
	require(runtime.GOARCH == "amd64", "gohex assembly requires amd64")
	path := "avx"
	if !cpu.X86.HasAVX {
		require(cpu.X86.HasSSE41, "gohex assembly requires actual AVX or SSE4.1")
		path = "sse41"
	}
	digest := uint64(14695981039346656037)
	cases := 0
	for _, n := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 257, 4096} {
		source := make([]byte, n)
		for i := range source {
			source[i] = byte(i*73 + n*11)
		}
		want := stdhex.EncodeToString(source)
		for _, uppercase := range []bool{false, true} {
			storage := bytes.Repeat([]byte{0xa5}, 2*n+32)
			encoded := storage[16 : 16+2*n]
			written := fasthex.Encode(encoded, source)
			expected := want
			if uppercase {
				written = fasthex.EncodeUpper(encoded, source)
				expected = strings.ToUpper(want)
			}
			require(written == 2*n && string(encoded) == expected && canary(storage, 2*n), "encode n=%d uppercase=%t", n, uppercase)
			decodedStorage := bytes.Repeat([]byte{0xa5}, n+32)
			decoded := decodedStorage[16 : 16+n]
			count, err := fasthex.Decode(decoded, encoded)
			reference := make([]byte, n)
			refCount, refErr := stdhex.Decode(reference, encoded)
			require(err == nil && refErr == nil && count == n && refCount == n && bytes.Equal(decoded, reference) && bytes.Equal(decoded, source) && canary(decodedStorage, n), "decode n=%d uppercase=%t err=%v", n, uppercase, err)
			digestBytes(&digest, encoded)
			digestBytes(&digest, decoded)
			cases++
		}
		if n == 0 {
			continue
		}
		for _, position := range []int{0, len(want) / 2, len(want) - 1} {
			invalid := []byte(want)
			invalid[position] = '!'
			storage := bytes.Repeat([]byte{0xa5}, n+32)
			count, err := fasthex.Decode(storage[16:16+n], invalid)
			_, refErr := stdhex.Decode(make([]byte, n), invalid)
			bad, typed := err.(fasthex.InvalidByteError)
			refBad, refTyped := refErr.(stdhex.InvalidByteError)
			require(count == 0 && typed && refTyped && byte(bad) == '!' && byte(refBad) == '!' && canary(storage, n), "invalid n=%d position=%d err=%v", n, position, err)
			cases++
		}
	}
	// Odd input is an explicit public-Go control; it does not execute the ASM.
	_, err := fasthex.Decode(make([]byte, 2), []byte("123"))
	require(err != nil, "odd length was accepted")
	fmt.Printf("gohex verified path=%s cases=%d digest=%x\n", path, cases, digest)
}
