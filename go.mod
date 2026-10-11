module github.com/llgo-compat/plan9asm

go 1.27.1

replace github.com/xgo-dev/plan9asm => github.com/cpunion/plan9asm v0.0.0-20261011095332-77a70d89c818

require (
	github.com/xgo-dev/plan9asm v0.0.0
	golang.org/x/arch v0.14.0
	golang.org/x/mod v0.20.0
	golang.org/x/sys v0.20.0
)

require github.com/xgo-dev/llvm v0.9.9 // indirect
