#include "textflag.h"

DATA ·alignedPC+0(SB)/8, $alignedEntry(SB)
GLOBL ·alignedPC(SB), NOPTR, $8
DATA ·eightAlignedPC+0(SB)/8, $eightAlignedEntry(SB)
GLOBL ·eightAlignedPC(SB), NOPTR, $8

// Both are ordinary native C entry points. The second deliberately reproduces
// the existing Go-assembler caller's 8-byte-aligned CALL to crosscall2; it does
// not assert that this is a standard C ABI call to an arbitrary C function.
TEXT alignedEntry(SB), NOSPLIT|NOFRAME, $0
	MOVQ SP, AX
	ANDQ $15, AX
	MOVQ AX, 0(DI)
	MOVQ DI, SI
	PUSHQ BX
	MOVQ SP, AX
	ANDQ $15, AX
	MOVQ AX, 8(SI)
	MOVQ ·dispatchCall(SB), DI
	MOVQ (DI), DI
	XORL DX, DX
	XORL CX, CX
	CALL crosscall2(SB)
	POPQ BX
	RET

TEXT eightAlignedEntry(SB), NOSPLIT|NOFRAME, $0
	MOVQ SP, AX
	ANDQ $15, AX
	MOVQ AX, 0(DI)
	MOVQ DI, SI
	MOVQ SP, AX
	ANDQ $15, AX
	MOVQ AX, 8(SI)
	MOVQ ·dispatchCall(SB), DI
	MOVQ (DI), DI
	XORL DX, DX
	XORL CX, CX
	CALL crosscall2(SB)
	RET
