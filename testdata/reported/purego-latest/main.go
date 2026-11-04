package main

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: purego-extended MODE NATIVE_LIBRARY")
	}
	mode := os.Args[1]
	library := os.Args[2]
	if mode == "strlen" || mode == "qsort" {
		library = "libc.so.6"
	}
	handle, err := purego.Dlopen(library, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		panic(err)
	}
	defer purego.Dlclose(handle)

	switch mode {
	case "strlen":
		var strlen func(string) uintptr
		purego.RegisterLibFunc(&strlen, handle, "strlen")
		if got := strlen("purego ABI boundary"); got != 19 {
			panic(got)
		}
	case "ints15":
		var call func(uintptr, uintptr, uintptr, uintptr, uintptr,
			uintptr, uintptr, uintptr, uintptr, uintptr,
			uintptr, uintptr, uintptr, uintptr, uintptr) uintptr
		purego.RegisterLibFunc(&call, handle, "probe_ints15")
		var args [15]uintptr
		var want uintptr
		for i := range args {
			args[i] = uintptr(1)<<40 + uintptr(3*i+1)
			want += args[i] * uintptr(i+1)
		}
		got := call(args[0], args[1], args[2], args[3], args[4],
			args[5], args[6], args[7], args[8], args[9],
			args[10], args[11], args[12], args[13], args[14])
		if got != want {
			panic(fmt.Sprintf("15 integer arguments: got %d want %d", got, want))
		}
	case "floats15":
		var call func(float64, float64, float64, float64, float64,
			float64, float64, float64, float64, float64,
			float64, float64, float64, float64, float64) float64
		purego.RegisterLibFunc(&call, handle, "probe_floats15")
		var args [15]float64
		var want float64
		for i := range args {
			args[i] = float64(i+1) / 2
			want += args[i] * float64(i+1)
		}
		got := call(args[0], args[1], args[2], args[3], args[4],
			args[5], args[6], args[7], args[8], args[9],
			args[10], args[11], args[12], args[13], args[14])
		if got != want {
			panic(fmt.Sprintf("15 floating arguments: got %g want %g", got, want))
		}
	case "mixed15":
		var call func(uintptr, float64, uintptr, float64, uintptr,
			float64, uintptr, float64, uintptr, float64,
			uintptr, float64, uintptr, float64, uintptr) float64
		purego.RegisterLibFunc(&call, handle, "probe_mixed15")
		got := call(3, 1.25, 6, 2.5, 9, 3.75, 12, 5,
			15, 6.25, 18, 7.5, 21, 8.75, 24)
		var want float64
		for i := 1; i <= 8; i++ {
			want += float64(3 * i * i)
		}
		for i := 1; i <= 7; i++ {
			want += float64(i) * 1.25 * float64(i+16)
		}
		if got != want {
			panic(fmt.Sprintf("15 mixed arguments: got %g want %g", got, want))
		}
	case "qsort":
		data := []int64{17, -4, 99, 0, -4, 8, 1}
		want := []int64{-4, -4, 0, 1, 8, 17, 99}
		calls := 0
		compare := func(a, b *int64) int32 {
			runtime.GC()
			calls++
			if *a < *b {
				return -1
			}
			if *a > *b {
				return 1
			}
			return 0
		}
		callback := purego.NewCallback(compare)
		runtime.GC()
		var qsort func(unsafe.Pointer, uintptr, uintptr, uintptr)
		purego.RegisterLibFunc(&qsort, handle, "qsort")
		qsort(unsafe.Pointer(&data[0]), uintptr(len(data)), unsafe.Sizeof(data[0]), callback)
		runtime.KeepAlive(compare)
		runtime.KeepAlive(data)
		if calls == 0 {
			panic("qsort did not invoke the Go callback")
		}
		for i := range data {
			if data[i] != want[i] {
				panic(fmt.Sprintf("qsort output %v want %v", data, want))
			}
		}
		runtime.GC()
	default:
		panic("unknown purego mode: " + mode)
	}
	fmt.Println("purego " + mode + " verified")
}
