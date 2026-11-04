package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/klauspost/compress/s2"
)

func require(ok bool, format string, args ...any) {
	if !ok {
		panic(fmt.Sprintf(format, args...))
	}
}

// Independently construct only the standard literal and COPY_2 wire forms.
// In particular this does not call the tested encoder to prepare decoder input.
func literal(dst, source []byte) []byte {
	x := len(source) - 1
	switch {
	case x < 60:
		dst = append(dst, byte(x<<2))
	case x <= 0xff:
		dst = append(dst, 60<<2, byte(x))
	case x <= 0xffff:
		dst = append(dst, 61<<2, byte(x), byte(x>>8))
	default:
		dst = append(dst, 62<<2, byte(x), byte(x>>8), byte(x>>16))
	}
	return append(dst, source...)
}

func block(length int, body []byte) []byte {
	header := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(header, uint64(length))
	return append(header[:n], body...)
}

func decode(encoded, want []byte) {
	length, err := s2.DecodedLen(encoded)
	require(err == nil && length == len(want), "decoded header: len=%d err=%v", length, err)
	for _, preallocated := range []bool{false, true} {
		var dst []byte
		if preallocated {
			dst = make([]byte, len(want))
		}
		got, err := s2.Decode(dst, encoded)
		require(err == nil && bytes.Equal(got, want), "decode bytes=%d preallocated=%t err=%v", len(want), preallocated, err)
	}
}

func digestBytes(digest *uint64, data []byte) {
	for _, value := range data {
		*digest = (*digest ^ uint64(value)) * 1099511628211
	}
}

func main() {
	digest := uint64(14695981039346656037)
	roundtrips := 0
	// The five relevant ASM encoder ranges begin at 32, 512, 4096, 16384,
	// and 4MiB. The large entry is exercised once, not in a size cross product.
	for _, n := range []int{0, 1, 16, 31, 32, 511, 512, 4095, 4096, 16383, 16384, 4 << 20} {
		source := make([]byte, n)
		for i := range source {
			source[i] = byte((i%97)*17 + i/97%3)
		}
		encoded := s2.Encode(nil, source)
		decode(encoded, source)
		digestBytes(&digest, encoded)
		digestBytes(&digest, source)
		roundtrips++
	}
	manual := 0
	for _, n := range []int{1, 16, 17, 60, 61, 256, 257, 65536} {
		want := make([]byte, n)
		for i := range want {
			want[i] = byte(i*29 + n)
		}
		decode(block(n, literal(nil, want)), want)
		digestBytes(&digest, want)
		manual++
	}
	for _, offset := range []int{1, 3, 8, 9, 16} {
		seed := make([]byte, offset)
		for i := range seed {
			seed[i] = byte('a' + i)
		}
		want := append([]byte(nil), seed...)
		body := literal(nil, seed)
		for repeat := 0; repeat < 3; repeat++ {
			body = append(body, byte((64-1)<<2|2), byte(offset), byte(offset>>8))
			for i := 0; i < 64; i++ {
				want = append(want, want[len(want)-offset])
			}
		}
		// Only the decoder's output match ranges overlap. The public API's
		// encoded source and output destination remain separate allocations.
		decode(block(len(want), body), want)
		digestBytes(&digest, want)
		manual++
	}
	for _, invalid := range [][]byte{{1}, {1, 2, 0, 0}, {4, 0, 'a'}} {
		_, err := s2.Decode(nil, invalid)
		require(err != nil, "invalid block was accepted: %x", invalid)
	}
	fmt.Printf("s2 verified roundtrips=%d manual=%d digest=%x\n", roundtrips, manual, digest)
}
