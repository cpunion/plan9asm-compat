package main

import (
	"fmt"

	"github.com/ebitengine/purego"
)

func main() {
	h, err := purego.Dlopen("libc.so.6", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		panic(err)
	}
	defer purego.Dlclose(h)
	var strlen func(string) uintptr
	purego.RegisterLibFunc(&strlen, h, "strlen")
	if n := strlen("purego ABI boundary"); n != 19 {
		panic(n)
	}
	fmt.Println("purego native call verified")
}
