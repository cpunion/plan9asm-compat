package main

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

// These addresses come from the selected assembly, never a guessed Go signature.
var alignedPC uintptr
var eightAlignedPC uintptr
var dispatchCall = dispatch
var saved reflect.Value

type report struct {
	entryMod uintptr
	callMod  uintptr
	calls    uintptr
	result   int64
}

func dispatch(pointer unsafe.Pointer) {
	r := (*report)(pointer)
	if saved.Type().Kind() != reflect.Func {
		panic("stored callback is not a function")
	}
	runtime.GC()
	r.result = saved.Call([]reflect.Value{reflect.ValueOf(int64(1))})[0].Int()
	r.calls++
}

func main() {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		panic("this diagnostic requires Linux/amd64")
	}
	if len(os.Args) != 2 {
		panic("choose aligned or eight-aligned; execute each in its own process")
	}
	pc, want := alignedPC, uintptr(0)
	if os.Args[1] == "eight-aligned" {
		pc, want = eightAlignedPC, 8
	} else if os.Args[1] != "aligned" {
		panic("unknown stack-entry case")
	}
	captured := int64(41)
	saved = reflect.ValueOf(func(value int64) int64 { return captured + value })
	runtime.GC()
	r := new(report)
	defer func() {
		fmt.Printf("%s entry=%d call=%d callbacks=%d result=%d\n", os.Args[1], r.entryMod, r.callMod, r.calls, r.result)
	}()
	var invoke func(unsafe.Pointer)
	purego.RegisterFunc(&invoke, pc)
	invoke(unsafe.Pointer(r))
	runtime.KeepAlive(r)
	if r.entryMod != 8 || r.callMod != want || r.calls != 1 || r.result != 42 {
		panic("callback entry, stack or captured result differs")
	}
}
