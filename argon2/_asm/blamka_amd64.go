// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
	_ "golang.org/x/crypto/argon2"
)

//go:generate go run . -out ../blamka_amd64.s -pkg argon2

func main() {
	Package("golang.org/x/crypto/argon2")
	ConstraintExpr("amd64,gc,!purego")

	blamkaSSE4()
	mixBlocksSSE2()
	xorBlocksSSE2()
	processBlockAVX2()
	blockStage1()
	blockStage2()
	prefetchBlock()
	processBlockAVX512()
	blockStage1AVX512()
	blockStage2AVX512()
	Generate()
}

func blamkaSSE4() {
	Implement("blamkaSSE4")
	Attributes(NOSPLIT)
	AllocLocal(0)

	Load(Param("b"), RAX)

	c40 := c40_DATA()
	c48 := c48_DATA()

	MOVOU(c40, X10)
	MOVOU(c48, X11)

	BLAMKA_ROUND_0(AX, 0, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 16, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 32, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 48, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 64, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 80, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 96, X8, X9, X10, X11)
	BLAMKA_ROUND_0(AX, 112, X8, X9, X10, X11)

	BLAMKA_ROUND_1(AX, 0, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 2, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 4, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 6, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 8, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 10, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 12, X8, X9, X10, X11)
	BLAMKA_ROUND_1(AX, 14, X8, X9, X10, X11)
	RET()
}

func mixBlocksSSE2() {
	Implement("mixBlocksSSE2")
	Attributes(NOSPLIT)
	AllocLocal(0)

	Load(Param("out"), RDX)
	Load(Param("a"), RAX)
	Load(Param("b"), RBX)
	Load(Param("c"), RCX)
	MOVQ(U32(128), RDI)

	Label("loop")
	MOVOU(Mem{Base: AX}.Offset(0), X0)
	MOVOU(Mem{Base: BX}.Offset(0), X1)
	MOVOU(Mem{Base: CX}.Offset(0), X2)
	PXOR(X1, X0)
	PXOR(X2, X0)
	MOVOU(X0, Mem{Base: DX}.Offset(0))
	ADDQ(Imm(16), RAX)
	ADDQ(Imm(16), RBX)
	ADDQ(Imm(16), RCX)
	ADDQ(Imm(16), RDX)
	SUBQ(Imm(2), RDI)
	JA(LabelRef("loop"))
	RET()
}

func xorBlocksSSE2() {
	Implement("xorBlocksSSE2")
	Attributes(NOSPLIT)
	AllocLocal(0)

	Load(Param("out"), RDX)
	Load(Param("a"), RAX)
	Load(Param("b"), RBX)
	Load(Param("c"), RCX)
	MOVQ(U32(128), RDI)

	Label("loop")
	MOVOU(Mem{Base: AX}.Offset(0), X0)
	MOVOU(Mem{Base: BX}.Offset(0), X1)
	MOVOU(Mem{Base: CX}.Offset(0), X2)
	MOVOU(Mem{Base: DX}.Offset(0), X3)
	PXOR(X1, X0)
	PXOR(X2, X0)
	PXOR(X3, X0)
	MOVOU(X0, Mem{Base: DX}.Offset(0))
	ADDQ(Imm(16), RAX)
	ADDQ(Imm(16), RBX)
	ADDQ(Imm(16), RCX)
	ADDQ(Imm(16), RDX)
	SUBQ(Imm(2), RDI)
	JA(LabelRef("loop"))
	RET()
}

func SHUFFLE(v2, v3, v4, v5, v6, v7, t1, t2 VecPhysical) {
	MOVO(v4, t1)
	MOVO(v5, v4)
	MOVO(t1, v5)
	MOVO(v6, t1)
	PUNPCKLQDQ(v6, t2)
	PUNPCKHQDQ(v7, v6)
	PUNPCKHQDQ(t2, v6)
	PUNPCKLQDQ(v7, t2)
	MOVO(t1, v7)
	MOVO(v2, t1)
	PUNPCKHQDQ(t2, v7)
	PUNPCKLQDQ(v3, t2)
	PUNPCKHQDQ(t2, v2)
	PUNPCKLQDQ(t1, t2)
	PUNPCKHQDQ(t2, v3)
}

func SHUFFLE_INV(v2, v3, v4, v5, v6, v7, t1, t2 VecPhysical) {
	MOVO(v4, t1)
	MOVO(v5, v4)
	MOVO(t1, v5)
	MOVO(v2, t1)
	PUNPCKLQDQ(v2, t2)
	PUNPCKHQDQ(v3, v2)
	PUNPCKHQDQ(t2, v2)
	PUNPCKLQDQ(v3, t2)
	MOVO(t1, v3)
	MOVO(v6, t1)
	PUNPCKHQDQ(t2, v3)
	PUNPCKLQDQ(v7, t2)
	PUNPCKHQDQ(t2, v6)
	PUNPCKLQDQ(t1, t2)
	PUNPCKHQDQ(t2, v7)
}

func HALF_ROUND(v0, v1, v2, v3, v4, v5, v6, v7, t0, c40, c48 VecPhysical) {
	MOVO(v0, t0)
	PMULULQ(v2, t0)
	PADDQ(v2, v0)
	PADDQ(t0, v0)
	PADDQ(t0, v0)
	PXOR(v0, v6)
	PSHUFD(Imm(0xB1), v6, v6)
	MOVO(v4, t0)
	PMULULQ(v6, t0)
	PADDQ(v6, v4)
	PADDQ(t0, v4)
	PADDQ(t0, v4)
	PXOR(v4, v2)
	PSHUFB(c40, v2)
	MOVO(v0, t0)
	PMULULQ(v2, t0)
	PADDQ(v2, v0)
	PADDQ(t0, v0)
	PADDQ(t0, v0)
	PXOR(v0, v6)
	PSHUFB(c48, v6)
	MOVO(v4, t0)
	PMULULQ(v6, t0)
	PADDQ(v6, v4)
	PADDQ(t0, v4)
	PADDQ(t0, v4)
	PXOR(v4, v2)
	MOVO(v2, t0)
	PADDQ(v2, t0)
	PSRLQ(Imm(63), v2)
	PXOR(t0, v2)
	MOVO(v1, t0)
	PMULULQ(v3, t0)
	PADDQ(v3, v1)
	PADDQ(t0, v1)
	PADDQ(t0, v1)
	PXOR(v1, v7)
	PSHUFD(Imm(0xB1), v7, v7)
	MOVO(v5, t0)
	PMULULQ(v7, t0)
	PADDQ(v7, v5)
	PADDQ(t0, v5)
	PADDQ(t0, v5)
	PXOR(v5, v3)
	PSHUFB(c40, v3)
	MOVO(v1, t0)
	PMULULQ(v3, t0)
	PADDQ(v3, v1)
	PADDQ(t0, v1)
	PADDQ(t0, v1)
	PXOR(v1, v7)
	PSHUFB(c48, v7)
	MOVO(v5, t0)
	PMULULQ(v7, t0)
	PADDQ(v7, v5)
	PADDQ(t0, v5)
	PADDQ(t0, v5)
	PXOR(v5, v3)
	MOVO(v3, t0)
	PADDQ(v3, t0)
	PSRLQ(Imm(63), v3)
	PXOR(t0, v3)
}

func LOAD_MSG_0(block GPPhysical, off int) {
	var registers = []VecPhysical{X0, X1, X2, X3, X4, X5, X6, X7}
	for i, r := range registers {
		MOVOU(Mem{Base: block}.Offset(8*(off+(i*2))), r)
	}
}

func STORE_MSG_0(block GPPhysical, off int) {
	var registers = []VecPhysical{X0, X1, X2, X3, X4, X5, X6, X7}
	for i, r := range registers {
		MOVOU(r, Mem{Base: block}.Offset(8*(off+(i*2))))
	}
}

func LOAD_MSG_1(block GPPhysical, off int) {
	var registers = []VecPhysical{X0, X1, X2, X3, X4, X5, X6, X7}
	for i, r := range registers {
		MOVOU(Mem{Base: block}.Offset(8*off+i*16*8), r)
	}
}

func STORE_MSG_1(block GPPhysical, off int) {
	var registers = []VecPhysical{X0, X1, X2, X3, X4, X5, X6, X7}
	for i, r := range registers {
		MOVOU(r, Mem{Base: block}.Offset(8*off+i*16*8))
	}
}

func BLAMKA_ROUND_0(block GPPhysical, off int, t0, t1, c40, c48 VecPhysical) {
	LOAD_MSG_0(block, off)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, t0, c40, c48)
	SHUFFLE(X2, X3, X4, X5, X6, X7, t0, t1)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, t0, c40, c48)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, t0, t1)
	STORE_MSG_0(block, off)
}

func BLAMKA_ROUND_1(block GPPhysical, off int, t0, t1, c40, c48 VecPhysical) {
	LOAD_MSG_1(block, off)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, t0, c40, c48)
	SHUFFLE(X2, X3, X4, X5, X6, X7, t0, t1)
	HALF_ROUND(X0, X1, X2, X3, X4, X5, X6, X7, t0, c40, c48)
	SHUFFLE_INV(X2, X3, X4, X5, X6, X7, t0, t1)
	STORE_MSG_1(block, off)
}

// ##------------------DATA SECTION-------------------##

var c40_DATA_ptr, c48_DATA_ptr *Mem

func c40_DATA() Mem {
	if c40_DATA_ptr != nil {
		return *c40_DATA_ptr
	}

	c40_DATA := GLOBL("·c40", NOPTR|RODATA)
	c40_DATA_ptr = &c40_DATA
	DATA(0x00, U64(0x0201000706050403))
	DATA(0x08, U64(0x0a09080f0e0d0c0b))
	return c40_DATA
}
func c48_DATA() Mem {
	if c48_DATA_ptr != nil {
		return *c48_DATA_ptr
	}

	c48_DATA := GLOBL("·c48", NOPTR|RODATA)
	c48_DATA_ptr = &c48_DATA
	DATA(0x00, U64(0x0100070605040302))
	DATA(0x08, U64(0x09080f0e0d0c0b0a))
	return c48_DATA
}

// AVX2 implementation of the Argon2 compression function G.
//
// The block t = in1 ^ in2 is processed in two passes of the permutation P:
// pass 1 over the 8 rows of 16 words, pass 2 over the 8 groups of 2 words
// from each row. Pass 1 stores to a 1 KiB scratch block; pass 2 writes the
// final result out (^)= in1 ^ in2 ^ P(t) directly.
//
// Register use:
//
//	Y0-Y7   two independent states, interleaved to hide latency
//	Y8,Y9   temporaries
//	Y10,Y11 VPSHUFB selectors (rotate right by 24 and 16 bits)
//	Y12,Y13 diagonalized vectors in pass 2
//
// General purpose: DI=out, SI=in1, DX=in2, R8=scratch, R10=byte offset,
// R11B=xor flag.

// avxMem addresses disp(base)(R10*1).
func avxMem(base GPPhysical, disp int) Mem {
	return Mem{Base: base, Index: R10, Scale: 1, Disp: disp}
}

// mulAdd2 sets a = a + b + 2*lo32(a)*lo32(b) for two states at once.
func mulAdd2(a, b, t, A, B, T VecPhysical) {
	VPMULUDQ(b, a, t)
	VPMULUDQ(B, A, T)
	VPADDQ(t, t, t)
	VPADDQ(T, T, T)
	VPADDQ(b, a, a)
	VPADDQ(B, A, A)
	VPADDQ(t, a, a)
	VPADDQ(T, A, A)
}

// g2 applies the Blamka G function to four lanes of two states at once.
// Y10 and Y11 must hold the rotate-by-24 and rotate-by-16 byte selectors.
func g2(a, b, c, d, t, A, B, C, D, T VecPhysical) {
	mulAdd2(a, b, t, A, B, T)
	VPXOR(a, d, d)
	VPXOR(A, D, D)
	VPSHUFD(U8(0xB1), d, d) // rotate right by 32
	VPSHUFD(U8(0xB1), D, D)
	mulAdd2(c, d, t, C, D, T)
	VPXOR(c, b, b)
	VPXOR(C, B, B)
	VPSHUFB(Y10, b, b) // rotate right by 24
	VPSHUFB(Y10, B, B)
	mulAdd2(a, b, t, A, B, T)
	VPXOR(a, d, d)
	VPXOR(A, D, D)
	VPSHUFB(Y11, d, d) // rotate right by 16
	VPSHUFB(Y11, D, D)
	mulAdd2(c, d, t, C, D, T)
	VPXOR(c, b, b)
	VPXOR(C, B, B)
	VPADDQ(b, b, t) // rotate right by 63 == rotate left by 1
	VPADDQ(B, B, T)
	VPSRLQ(U8(63), b, b)
	VPSRLQ(U8(63), B, B)
	VPXOR(t, b, b)
	VPXOR(T, B, B)
}

// round2 applies the permutation P to two states held as row vectors
// (Y0-Y3 and Y4-Y7 = v0..v3, v4..v7, v8..v11, v12..v15): columns, then
// diagonals (lanes of b, c, d rotated by 1, 2, 3 and back).
func round2() {
	g2(Y0, Y1, Y2, Y3, Y8, Y4, Y5, Y6, Y7, Y9)
	VPERMQ(U8(0x39), Y1, Y1)
	VPERMQ(U8(0x39), Y5, Y5)
	VPERMQ(U8(0x4E), Y2, Y2)
	VPERMQ(U8(0x4E), Y6, Y6)
	VPERMQ(U8(0x93), Y3, Y3)
	VPERMQ(U8(0x93), Y7, Y7)
	g2(Y0, Y1, Y2, Y3, Y8, Y4, Y5, Y6, Y7, Y9)
	VPERMQ(U8(0x93), Y1, Y1)
	VPERMQ(U8(0x93), Y5, Y5)
	VPERMQ(U8(0x4E), Y2, Y2)
	VPERMQ(U8(0x4E), Y6, Y6)
	VPERMQ(U8(0x39), Y3, Y3)
	VPERMQ(U8(0x39), Y7, Y7)
}

// round256 applies P to a pair of word-pair groups in the "pair" layout:
// Yr holds, for row r, the words 4k..4k+3 (lanes 0,1 = group 2k, lanes 2,3 =
// group 2k+1). Columns need no shuffles: {Y0,Y2,Y4,Y6} hold columns 0,1 and
// {Y1,Y3,Y5,Y7} columns 2,3. The diagonal step regroups lanes with VSHUFPD.
// On return row r = 0..7 is in Y0,Y1,Y6,Y7,Y4,Y5,Y12,Y13.
func round256() {
	g2(Y0, Y2, Y4, Y6, Y8, Y1, Y3, Y5, Y7, Y9)
	// diagonalize: B0=[v5,v6] B1=[v7,v4] D0=[v15,v12] D1=[v13,v14]
	VSHUFPD(U8(5), Y3, Y2, Y12)
	VSHUFPD(U8(5), Y2, Y3, Y13)
	VSHUFPD(U8(5), Y6, Y7, Y2)
	VSHUFPD(U8(5), Y7, Y6, Y3)
	g2(Y0, Y12, Y5, Y2, Y8, Y1, Y13, Y4, Y3, Y9)
	// undiagonalize
	VSHUFPD(U8(5), Y12, Y13, Y6)
	VSHUFPD(U8(5), Y13, Y12, Y7)
	VSHUFPD(U8(5), Y3, Y2, Y12)
	VSHUFPD(U8(5), Y2, Y3, Y13)
}

// avxSetup loads the arguments out, in1, in2 (and the xor flag) and the
// rotate selectors. VPSHUFB selects within 128-bit lanes, so the 16-byte
// SSE selectors are broadcast to both lanes.
func avxSetup() {
	Load(Param("out"), RDI)
	Load(Param("in1"), RSI)
	Load(Param("in2"), RDX)
	Load(Param("xor"), R11B)
	VBROADCASTI128(c40_DATA(), Y10)
	VBROADCASTI128(c48_DATA(), Y11)
}

// avxRows runs pass 1 over all 8 rows: it reads in1^in2 (SI, DX), computes P
// row-wise and stores the result to the scratch block at R8.
func avxRows() {
	XORQ(R10, R10)
	Label("rows")
	for i, y := range []VecPhysical{Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7} {
		VMOVDQU(avxMem(RSI, 32*i), y)
		VPXOR(avxMem(RDX, 32*i), y, y)
	}
	round2()
	for i, y := range []VecPhysical{Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7} {
		VMOVDQU(y, avxMem(R8, 32*i))
	}
	ADDQ(U32(256), R10)
	CMPQ(R10, U32(1024))
	JNE(LabelRef("rows"))
}

// avxCols processes one iteration of pass 2 (two word-pair groups, see
// round256) reading the scratch block at R8 and writing the final result to
// out at byte offset R10. If xor is set, out ^= in1 ^ in2 ^ P(t); otherwise
// out = in1 ^ in2 ^ P(t) and out is not read.
func avxCols(xor bool) {
	for r, y := range []VecPhysical{Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7} {
		VMOVDQU(avxMem(R8, 128*r), y)
	}
	round256()
	rows := []VecPhysical{Y0, Y1, Y6, Y7, Y4, Y5, Y12, Y13}
	for r, y := range rows {
		VMOVDQU(avxMem(RSI, 128*r), Y8)
		VPXOR(avxMem(RDX, 128*r), Y8, Y8)
		VPXOR(y, Y8, Y8)
		if xor {
			VPXOR(avxMem(RDI, 128*r), Y8, Y8)
		}
		VMOVDQU(Y8, avxMem(RDI, 128*r))
	}
}

// avxPass2 dispatches on the xor flag and runs the pass-2 iterations for
// byte offsets start, start+32, ... < 128 (a single iteration if !loop).
func avxPass2(prefix string, start int, loop bool) {
	TESTB(R11B, R11B)
	JZ(LabelRef(prefix + "overwrite"))
	for _, xor := range []bool{true, false} {
		name := prefix + "overwrite"
		if xor {
			name = prefix + "xor"
		} else {
			Label(name)
		}
		MOVQ(U32(uint32(start)), R10)
		if loop {
			Label(name + "_loop")
		}
		avxCols(xor)
		if loop {
			ADDQ(U32(32), R10)
			CMPQ(R10, U32(128))
			JNE(LabelRef(name + "_loop"))
		}
		if xor {
			JMP(LabelRef(prefix + "done"))
		}
	}
	Label(prefix + "done")
}

// processBlockAVX2 computes the whole compression function using a stack
// scratch block. out may alias in1.
func processBlockAVX2() {
	Implement("processBlockAVX2")
	scratch := AllocLocal(1024)
	avxSetup()
	LEAQ(scratch, R8)
	avxRows()
	avxPass2("", 0, true)
	VZEROUPPER()
	RET()
}

// blockStage1 is the first part of processBlockAVX2 with a caller-supplied
// scratch block: pass 1 plus the first quarter of pass 2. When it returns,
// the first words of every row of out (in particular out[0]) are final.
func blockStage1() {
	Implement("blockStage1")
	AllocLocal(0)
	avxSetup()
	Load(Param("scratch"), R8)
	avxRows()
	avxPass2("s1_", 0, false)
	VZEROUPPER()
	RET()
}

// blockStage2 is the remaining three quarters of pass 2 after blockStage1.
func blockStage2() {
	Implement("blockStage2")
	AllocLocal(0)
	avxSetup()
	Load(Param("scratch"), R8)
	avxPass2("s2_", 32, true)
	VZEROUPPER()
	RET()
}

// prefetchBlock issues a cache prefetch for each of the 16 lines of b.
func prefetchBlock() {
	Implement("prefetchBlock")
	Attributes(NOSPLIT)
	AllocLocal(0)
	Load(Param("b"), RAX)
	for i := 0; i < 16; i++ {
		PREFETCHT0(Mem{Base: RAX, Disp: 64 * i})
	}
	RET()
}

// AVX-512 implementation of the Argon2 compression function G.
//
// It follows the AVX2 code above but uses AVX512F instructions: VPRORQ for
// all rotations, VPTERNLOGQ for the three-way xor of the result, and 32
// vector registers.
//
// Pass 1 (rows) keeps four 4-word state vectors a, b, c, d per row. Two rows
// are packed into one zmm register ([a_r | a_r'] and so on), so all 8 rows are
// four interleaved states; they are gathered from and scattered to memory with
// VSHUFI64X2. Pass 2 (columns) uses the same "pair" layout as the AVX2 code,
// with four word-pair groups per register, so the loads are contiguous and the
// diagonal step is VSHUFPD.
//
// Register use:
//
//	Z0-Z15  four pass 1 states of four vectors each
//	Z16-Z19 pass 1 temporaries
//	Z20-Z23 pass 1 load/store staging
//
// and in pass 2 two sets of Z0-Z7, Z8,Z9 (temporaries), Z12,Z13 and Z16-Z23,
// Z24,Z25 (temporaries), Z26,Z27 (see p2sets).
//
// General purpose: DI=out, SI=in1, DX=in2, R8=scratch, R10=byte offset,
// R11B=xor flag.

var zmmRegs = []VecPhysical{Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, Z12, Z13, Z14, Z15, Z16, Z17, Z18, Z19, Z20, Z21, Z22, Z23, Z24, Z25, Z26, Z27}

// vecSize is the size of a zmm register in bytes.
const vecSize = 64

// gstate is the four row vectors of one G state and a temporary.
type gstate struct {
	r [4]VecPhysical // a, b, c, d
	t VecPhysical
}

// gEVEX applies the Blamka G function to all states at once.
func gEVEX(ss ...gstate) {
	step := func(x, y, z int, rot uint8) {
		// x = x + y + 2*lo32(x)*lo32(y); z = (z ^ x) >>> rot
		for _, s := range ss {
			VPMULUDQ(s.r[y], s.r[x], s.t)
		}
		for _, s := range ss {
			VPADDQ(s.r[y], s.r[x], s.r[x])
		}
		for _, s := range ss {
			VPADDQ(s.t, s.t, s.t)
		}
		for _, s := range ss {
			VPADDQ(s.t, s.r[x], s.r[x])
		}
		for _, s := range ss {
			VPXORQ(s.r[x], s.r[z], s.r[z])
		}
		for _, s := range ss {
			VPRORQ(U8(rot), s.r[z], s.r[z])
		}
	}
	step(0, 1, 3, 32)
	step(2, 3, 1, 24)
	step(0, 1, 3, 16)
	step(2, 3, 1, 63)
}

// avx512Round1 applies P to the states of pass 1: columns, then diagonals (b, c, d
// rotated by 1, 2, 3 words within each 256-bit lane, and back).
func avx512Round1(ss ...gstate) {
	gEVEX(ss...)
	for _, s := range ss {
		VPERMQ(U8(0x39), s.r[1], s.r[1])
		VPERMQ(U8(0x4E), s.r[2], s.r[2])
		VPERMQ(U8(0x93), s.r[3], s.r[3])
	}
	gEVEX(ss...)
	for _, s := range ss {
		VPERMQ(U8(0x93), s.r[1], s.r[1])
		VPERMQ(U8(0x4E), s.r[2], s.r[2])
		VPERMQ(U8(0x39), s.r[3], s.r[3])
	}
}

// p2set is the register set for one iteration of pass 2: rows 0..7 on
// entry, two temporaries, and two extra vectors for the diagonal step.
type p2set struct {
	rows           [8]VecPhysical
	t0, t1, e0, e1 VecPhysical
}

// p2sets returns n (at most 2) disjoint register sets.
func p2sets(n int) []p2set {
	V := zmmRegs
	all := []p2set{
		{[8]VecPhysical{V[0], V[1], V[2], V[3], V[4], V[5], V[6], V[7]}, V[8], V[9], V[12], V[13]},
		{[8]VecPhysical{V[16], V[17], V[18], V[19], V[20], V[21], V[22], V[23]}, V[24], V[25], V[26], V[27]},
	}
	return all[:n]
}

// result returns the vectors that hold rows 0..7 after avx512Round2.
func (s p2set) result() [8]VecPhysical {
	r := s.rows
	return [8]VecPhysical{r[0], r[1], r[6], r[7], r[4], r[5], s.e0, s.e1}
}

// avx512Round2 applies P to sets of word-pair groups in the pair layout of the AVX2
// round256, interleaving all sets. The rows are in set.result() on return.
func avx512Round2(sets []p2set) {
	imm := U8(0x55) // low element of src1, high element of src2, per 128-bit lane
	var ss []gstate
	for _, s := range sets {
		r := s.rows
		ss = append(ss, gstate{[4]VecPhysical{r[0], r[2], r[4], r[6]}, s.t0}, gstate{[4]VecPhysical{r[1], r[3], r[5], r[7]}, s.t1})
	}
	gEVEX(ss...)
	for _, s := range sets {
		r := s.rows
		VSHUFPD(imm, r[3], r[2], s.e0)
		VSHUFPD(imm, r[2], r[3], s.e1)
		VSHUFPD(imm, r[6], r[7], r[2])
		VSHUFPD(imm, r[7], r[6], r[3])
	}
	ss = nil
	for _, s := range sets {
		r := s.rows
		ss = append(ss, gstate{[4]VecPhysical{r[0], s.e0, r[5], r[2]}, s.t0}, gstate{[4]VecPhysical{r[1], s.e1, r[4], r[3]}, s.t1})
	}
	gEVEX(ss...)
	for _, s := range sets {
		r := s.rows
		VSHUFPD(imm, s.e0, s.e1, r[6])
		VSHUFPD(imm, s.e1, s.e0, r[7])
		VSHUFPD(imm, r[3], r[2], s.e0)
		VSHUFPD(imm, r[2], r[3], s.e1)
	}
}

// avx512Align rounds the scratch pointer R8 up to a multiple of 64 so that no
// vector access of the scratch block crosses a cache line. The scratch buffer
// has at least 56 bytes of slack for this.
func avx512Align() {
	ADDQ(U8(63), R8)
	ANDQ(I8(-64), R8)
}

func avx512Setup() {
	Load(Param("out"), RDI)
	Load(Param("in1"), RSI)
	Load(Param("in2"), RDX)
	Load(Param("xor"), R11B)
}

// avx512Rows runs pass 1 over all 8 rows: it reads in1^in2 (SI, DX), computes
// P row-wise and stores the result to the scratch block at R8.
func avx512Rows() {
	V := zmmRegs
	ss := make([]gstate, 4)
	for p := range ss {
		ss[p] = gstate{[4]VecPhysical{V[4*p], V[4*p+1], V[4*p+2], V[4*p+3]}, V[16+p]}
	}
	// Row i is [a|b] at 128*i and [c|d] at 128*i+64. Rows 2p and 2p+1 are
	// packed into state p ([a_2p | a_2p+1] and so on) through the staging
	// registers V20-V23.
	lo0, hi0, lo1, hi1 := V[20], V[21], V[22], V[23]
	for p, s := range ss {
		for i, r := range []VecPhysical{lo0, hi0, lo1, hi1} {
			VMOVDQU64(Mem{Base: RSI, Disp: 256*p + 64*i}, r)
			VPXORQ(Mem{Base: RDX, Disp: 256*p + 64*i}, r, r)
		}
		VSHUFI64X2(U8(0x44), lo1, lo0, s.r[0])
		VSHUFI64X2(U8(0xEE), lo1, lo0, s.r[1])
		VSHUFI64X2(U8(0x44), hi1, hi0, s.r[2])
		VSHUFI64X2(U8(0xEE), hi1, hi0, s.r[3])
	}
	avx512Round1(ss...)
	for p, s := range ss {
		VSHUFI64X2(U8(0x44), s.r[1], s.r[0], lo0)
		VSHUFI64X2(U8(0xEE), s.r[1], s.r[0], lo1)
		VSHUFI64X2(U8(0x44), s.r[3], s.r[2], hi0)
		VSHUFI64X2(U8(0xEE), s.r[3], s.r[2], hi1)
		for i, r := range []VecPhysical{lo0, hi0, lo1, hi1} {
			VMOVDQU64(r, Mem{Base: R8, Disp: 256*p + 64*i})
		}
	}
}

// avx512Cols processes one iteration of pass 2 (see avx512Round2) for each of the n
// interleaved register sets, reading the scratch block at R8 and writing the
// final result to out at byte offset R10 (+ set*64). If xor is set,
// out ^= in1 ^ in2 ^ P(t); otherwise out = in1 ^ in2 ^ P(t) and out is not
// read.
func avx512Cols(xor bool, n int) {
	sets := p2sets(n)
	for k, s := range sets {
		for r := 0; r < 8; r++ {
			VMOVDQU64(avxMem(R8, 128*r+k*vecSize), s.rows[r])
		}
	}
	avx512Round2(sets)
	for k, s := range sets {
		for r, y := range s.result() {
			off := 128*r + k*vecSize
			VMOVDQU64(avxMem(RSI, off), s.t0)
			VPTERNLOGQ(U8(0x96), avxMem(RDX, off), y, s.t0)
			if xor {
				VPXORQ(avxMem(RDI, off), s.t0, s.t0)
			}
			VMOVDQU64(s.t0, avxMem(RDI, off))
		}
	}
}

// avx512Pass2 dispatches on the xor flag and runs the pass-2 iterations, n
// sets at a time, for byte offsets start, start+n*64, ... < 128 (a single
// iteration if !loop).
func avx512Pass2(prefix string, start, n int, loop bool) {
	TESTB(R11B, R11B)
	JZ(LabelRef(prefix + "overwrite"))
	for _, xor := range []bool{true, false} {
		name := prefix + "overwrite"
		if xor {
			name = prefix + "xor"
		} else {
			Label(name)
		}
		MOVQ(U32(uint32(start)), R10)
		if loop {
			Label(name + "_loop")
		}
		avx512Cols(xor, n)
		if loop {
			ADDQ(U32(uint32(n*vecSize)), R10)
			CMPQ(R10, U32(128))
			JNE(LabelRef(name + "_loop"))
		}
		if xor {
			JMP(LabelRef(prefix + "done"))
		}
	}
	Label(prefix + "done")
}

// processBlockAVX512 computes the whole compression function using a stack
// scratch block. out may alias in1.
func processBlockAVX512() {
	Implement("processBlockAVX512")
	scratch := AllocLocal(1024 + 64)
	avx512Setup()
	LEAQ(scratch, R8)
	avx512Align()
	avx512Rows()
	avx512Pass2("", 0, 2, true)
	VZEROUPPER()
	RET()
}

// blockStage1AVX512 is pass 1 plus the first iteration of pass 2; out[0] is
// final when it returns.
func blockStage1AVX512() {
	Implement("blockStage1AVX512")
	AllocLocal(0)
	avx512Setup()
	Load(Param("scratch"), R8)
	avx512Align()
	avx512Rows()
	avx512Pass2("s1_", 0, 1, false)
	VZEROUPPER()
	RET()
}

// blockStage2AVX512 is the remaining iteration of pass 2 after
// blockStage1AVX512.
func blockStage2AVX512() {
	Implement("blockStage2AVX512")
	AllocLocal(0)
	avx512Setup()
	Load(Param("scratch"), R8)
	avx512Align()
	avx512Pass2("s2_", vecSize, 1, true)
	VZEROUPPER()
	RET()
}
