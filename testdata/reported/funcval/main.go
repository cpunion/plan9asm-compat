package main

import (
	"fmt"
	"unsafe"
)

func encode(f any) uintptr {
	type iface [2]uintptr
	return (*iface)(unsafe.Pointer(&f))[1]
}

func twice(n int) int { return 2 * n }

func main() {
	p := encode(twice)
	f := *(*func(int) int)(unsafe.Pointer(&struct{ uintptr }{p}))
	fmt.Println("function value bytes:", unsafe.Sizeof(f))
	if got := f(21); got != 42 {
		panic(got)
	}
	fmt.Println("function pointer round trip verified")
}
