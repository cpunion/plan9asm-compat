//go:build !linux || !amd64

package main

func main() {
	panic("libc ABI0 probe requires linux/amd64")
}
