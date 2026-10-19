// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package argon2

import (
	"bytes"
	"flag"
	"math/rand"
	"sort"
	"testing"
	"time"
)

// dirty fills all the working memory of m, including the part beyond the
// blocks the next call will use, with garbage.
func dirty(m *Memory, rng *rand.Rand) {
	b := m.b[:cap(m.b)]
	for i := range b {
		for j := range b[i] {
			b[i][j] = rng.Uint64()
		}
	}
}

// TestMemoryMatches checks that hashing into a reused Memory, whatever it held
// before, gives the same result as freshly allocated memory, for every
// implementation, mode and a range of parameters that make the Memory grow,
// shrink and be reused with a different number of lanes.
func TestMemoryMatches(t *testing.T) {
	defer func(sse4, avx2, avx512, lsx bool) {
		useSSE4, useAVX2, useAVX512, useLSX = sse4, avx2, avx512, lsx
	}(useSSE4, useAVX2, useAVX512, useLSX)
	password, salt := []byte("password"), []byte("some salt value!")
	rng := rand.New(rand.NewSource(1))
	levels := []struct {
		name string
		off  func()
	}{
		{"default", func() {}},
		{"no AVX512", func() { useAVX512 = false }},
		{"no AVX2", func() { useAVX2 = false }},
		{"no SSE4.1, no LSX", func() { useSSE4, useLSX = false, false }},
	}
	for _, level := range levels {
		level.off()
		var m Memory
		for _, mode := range []int{argon2d, argon2i, argon2id} {
			for _, time := range []uint32{1, 3} {
				for _, memory := range []uint32{8, 64, 1000, 100, 4097, 64} {
					for _, threads := range []uint8{1, 3, 4, 2} {
						want := deriveKey(mode, password, salt, nil, nil, time, memory, threads, 32)
						dirty(&m, rng)
						got := deriveKeyIn(&m, mode, password, salt, nil, nil, time, memory, threads, 32)
						if !bytes.Equal(got, want) {
							t.Fatalf("%s: mode=%d time=%d memory=%d threads=%d: reused Memory gives a different result", level.name, mode, time, memory, threads)
						}
					}
				}
			}
		}
	}
}

// TestOverwriteIgnoresOut checks, for every implementation of the compression
// function available on the CPU, the property that Memory relies on: the
// overwriting variant never reads its output block (so any previous contents
// are irrelevant), while the xor variant does combine with it. It also checks
// that the two-stage variant, which gets a scratch block of arbitrary contents,
// gives the same results, and that everything agrees with the generic
// implementation, including when out aliases in1.
func TestOverwriteIgnoresOut(t *testing.T) {
	defer func(sse4, avx2, avx512, lsx bool) {
		useSSE4, useAVX2, useAVX512, useLSX = sse4, avx2, avx512, lsx
	}(useSSE4, useAVX2, useAVX512, useLSX)
	rng := rand.New(rand.NewSource(1))
	fill := func(b *block) {
		for i := range b {
			b[i] = rng.Uint64()
		}
	}
	levels := []struct {
		name string
		off  func()
	}{
		{"default", func() {}},
		{"no AVX512", func() { useAVX512 = false }},
		{"no AVX2", func() { useAVX2 = false }},
		{"no SSE4.1, no LSX", func() { useSSE4, useLSX = false, false }},
	}
	for _, level := range levels {
		level.off()
		for n := 0; n < 200; n++ {
			var in1, in2, dirty, want block
			var scratch scratchBlock
			fill(&in1)
			fill(&in2)
			fill(&dirty)
			for i := range scratch {
				scratch[i] = rng.Uint64()
			}
			processBlockGeneric(&want, &in1, &in2, false)

			var got block
			processBlock(&got, &in1, &in2)
			if got != want {
				t.Fatalf("%s: processBlock into zeroed out differs from generic", level.name)
			}
			got = dirty
			processBlock(&got, &in1, &in2)
			if got != want {
				t.Fatalf("%s: processBlock depends on the previous contents of out", level.name)
			}
			got = dirty
			called := 0
			processBlockXORMid(&got, &in1, &in2, &scratch, false, func() { called++ })
			if called != 1 || got != want {
				t.Fatalf("%s: processBlockXORMid (overwrite) depends on out or scratch, or mid called %d times", level.name, called)
			}

			// The xor variants: out ^= G(in1, in2).
			xored := dirty
			for i := range xored {
				xored[i] ^= want[i]
			}
			got = dirty
			processBlockXOR(&got, &in1, &in2)
			if got != xored {
				t.Fatalf("%s: processBlockXOR differs from out ^ G(in1, in2)", level.name)
			}
			got = dirty
			called = 0
			processBlockXORMid(&got, &in1, &in2, &scratch, true, func() { called++ })
			if called != 1 || got != xored {
				t.Fatalf("%s: processBlockXORMid (xor) differs from out ^ G(in1, in2), or mid called %d times", level.name, called)
			}

			// Argon2i address generation overwrites in1 in place.
			got = in1
			processBlock(&got, &got, &in2)
			if got != want {
				t.Fatalf("%s: processBlock with out aliasing in1 differs from generic", level.name)
			}
		}
	}
}

func TestMemoryAPI(t *testing.T) {
	password, salt := []byte("password"), []byte("some salt value!")
	var m Memory
	if got, want := m.IDKey(password, salt, 1, 64, 1, 32), IDKey(password, salt, 1, 64, 1, 32); !bytes.Equal(got, want) {
		t.Errorf("Memory.IDKey differs from IDKey")
	}
	if got, want := m.Key(password, salt, 2, 64, 2, 32), Key(password, salt, 2, 64, 2, 32); !bytes.Equal(got, want) {
		t.Errorf("Memory.Key differs from Key")
	}
	if len(m.b) == 0 {
		t.Fatal("no memory retained")
	}
	m.Clear()
	for i := range m.b {
		if m.b[i] != (block{}) {
			t.Fatalf("block %d not cleared", i)
		}
	}
	if got, want := m.IDKey(password, salt, 1, 64, 1, 32), IDKey(password, salt, 1, 64, 1, 32); !bytes.Equal(got, want) {
		t.Errorf("Memory.IDKey after Clear differs from IDKey")
	}
	var empty Memory
	empty.Clear() // must not panic
}

func TestMemoryConcurrentUse(t *testing.T) {
	var m Memory
	m.busy.Store(true) // as if another call were running
	defer func() {
		if recover() == nil {
			t.Error("no panic on concurrent use")
		}
	}()
	m.IDKey([]byte("p"), []byte("saltsalt"), 1, 64, 1, 32)
}

var memoryInterleave = flag.Duration("argon2.memory-interleave", 0, "if non-zero, run TestInterleaveMemory for this long")
var memoryOnly = flag.Int("argon2.memory-only", -1, "if >= 0, run only this variant of TestInterleaveMemory, to measure it without the other variants' live memory affecting the garbage collector")

// TestInterleaveMemory compares allocating the working memory on every call
// with reusing a Memory, on the OWASP-recommended Argon2id parameters
// (m=47104 KiB, t=1, p=1), alternating one hash of each in turn. It reports
// throughput and p50/p95 latency. It is skipped unless
// -argon2.memory-interleave is set. For stable numbers pin to one core, for
// example:
//
//	GOMAXPROCS=1 taskset -c 2 go test -run TestInterleaveMemory \
//		-argon2.memory-interleave=60s -v -timeout 10m
//
// The variants that keep a Memory keep 46 MiB live, which raises the garbage
// collector's heap goal and so flatters the variant that allocates on every
// call. -argon2.memory-only=N runs variant N alone for an unbiased number.
func TestInterleaveMemory(t *testing.T) {
	if *memoryInterleave == 0 {
		t.Skip("set -argon2.memory-interleave=<duration> to run")
	}
	password, salt := []byte("password"), []byte("choosing random salts is hard")
	var reused, cleared Memory
	impls := []struct {
		name string
		f    func() []byte
		lat  []time.Duration
	}{
		{"IDKey (allocate per call)", func() []byte { return IDKey(password, salt, 1, 47104, 1, 32) }, nil},
		{"Memory.IDKey (reused)", func() []byte { return reused.IDKey(password, salt, 1, 47104, 1, 32) }, nil},
		{"Memory.IDKey + Clear", func() []byte {
			k := cleared.IDKey(password, salt, 1, 47104, 1, 32)
			cleared.Clear()
			return k
		}, nil},
	}
	if *memoryOnly >= 0 {
		impls = impls[*memoryOnly : *memoryOnly+1]
	}
	for i := range impls {
		impls[i].f()
	}
	for start := time.Now(); time.Since(start) < *memoryInterleave; {
		var first []byte
		for i := range impls {
			s := time.Now()
			k := impls[i].f()
			impls[i].lat = append(impls[i].lat, time.Since(s))
			if first == nil {
				first = k
			} else if !bytes.Equal(first, k) {
				t.Fatalf("%s: output differs", impls[i].name)
			}
		}
	}
	var base float64
	for i := range impls {
		s := impls[i].lat
		var total time.Duration
		for _, d := range s {
			total += d
		}
		sort.Slice(s, func(a, b int) bool { return s[a] < s[b] })
		rate := float64(len(s)) / total.Seconds()
		if i == 0 {
			base = rate
		}
		t.Logf("%-27s hashes=%d hash/s=%.2f (%.2fx) p50=%v p95=%v", impls[i].name, len(s), rate, rate/base, s[len(s)/2], s[len(s)*95/100])
	}
}
