// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build amd64 && gc && !purego

package argon2

import (
	"math/rand"
	"testing"
)

// TestAVX2MatchesGeneric compares processBlockAVX2 and the split
// blockStage1/blockStage2 pair against the pure-Go reference on random and
// edge-case blocks, for both the xor and the overwrite variants and including
// the aliased out == in1 form used for Argon2i address generation.
func TestAVX2MatchesGeneric(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 not supported")
	}
	rng := rand.New(rand.NewSource(1))
	edge := []uint64{0, 1, 0xFFFFFFFF, 0x100000000, 0xFFFFFFFFFFFFFFFF, 0x8000000000000000}
	for n := 0; n < 1000; n++ {
		var in1, in2, out, scratch block
		for i := range in1 {
			in1[i], in2[i], out[i] = rng.Uint64(), rng.Uint64(), rng.Uint64()
			if n < 100 {
				in1[i], in2[i] = edge[rng.Intn(len(edge))], edge[rng.Intn(len(edge))]
			}
		}
		xor := n%2 == 1

		want := out
		processBlockGeneric(&want, &in1, &in2, xor)

		got := out
		processBlockAVX2(&got, &in1, &in2, xor)
		if got != want {
			t.Fatalf("iteration %d (xor=%v): processBlockAVX2 differs from generic", n, xor)
		}

		got = out
		blockStage1(&got, &in1, &in2, &scratch, xor)
		blockStage2(&got, &in1, &in2, &scratch, xor)
		if got != want {
			t.Fatalf("iteration %d (xor=%v): blockStage1+2 differs from generic", n, xor)
		}

		aliased, wantAliased := in1, in1
		processBlockAVX2(&aliased, &aliased, &in2, xor)
		processBlockGeneric(&wantAliased, &wantAliased, &in2, xor)
		if aliased != wantAliased {
			t.Fatalf("iteration %d (xor=%v): aliased processBlockAVX2 differs from generic", n, xor)
		}
	}
}
