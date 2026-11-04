package main

import (
	"fmt"
	"runtime"
	"unsafe"

	"modernc.org/libc"
)

func main() {
	tls := libc.NewTLS()
	defer tls.Close()
	for _, tc := range []struct {
		a, b, want libc.Uint128
		overflow   int32
	}{
		{a: libc.Uint128{Lo: 7, Hi: 3}, b: libc.Uint128{Lo: 9}, want: libc.Uint128{Lo: 63, Hi: 27}},
		{a: libc.Uint128{Lo: ^uint64(0)}, b: libc.Uint128{Lo: 2}, want: libc.Uint128{Lo: ^uint64(1), Hi: 1}},
		{a: libc.Uint128{Lo: ^uint64(0), Hi: ^uint64(0)}, b: libc.Uint128{Lo: 2}, want: libc.Uint128{Lo: ^uint64(1), Hi: ^uint64(0)}, overflow: 1},
	} {
		var result libc.Uint128
		got := libc.Y__builtin_mul_overflowUint128(tls, tc.a, tc.b, uintptr(unsafe.Pointer(&result)))
		runtime.KeepAlive(&result)
		if got != tc.overflow || result != tc.want {
			panic(fmt.Sprintf("%+v * %+v: result=%+v overflow=%d, want %+v/%d", tc.a, tc.b, result, got, tc.want, tc.overflow))
		}
	}
	if got := libc.Y__builtin_copysign(tls, 2.5, -1); got != -2.5 {
		panic(got)
	}
	if got := libc.Y__builtin_copysignf(tls, 3.25, -1); got != -3.25 {
		panic(got)
	}
	fmt.Println("libc ABI0 wrappers verified")
}
