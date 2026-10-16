// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build amd64 && gc && !purego

package argon2

import (
	"bytes"
	"flag"
	"sort"
	"testing"
	"time"
)

var interleave = flag.Duration("argon2.interleave", 0, "if non-zero, run TestInterleaveAVX2vsSSE4 for this long")

// TestInterleaveAVX2vsSSE4 compares the AVX2 and SSE4.1 implementations on
// the OWASP-recommended Argon2id parameters (m=47104 KiB, t=1, p=1),
// alternating one hash of each so that host load drift affects both equally.
// It reports throughput and p50/p95 latency and checks that the outputs agree.
// It is skipped unless -argon2.interleave is set. For stable numbers pin to
// one core, for example:
//
//	GOMAXPROCS=1 taskset -c 2 go test -run TestInterleaveAVX2vsSSE4 \
//		-argon2.interleave=60s -v -timeout 10m
func TestInterleaveAVX2vsSSE4(t *testing.T) {
	if *interleave == 0 {
		t.Skip("set -argon2.interleave=<duration> to run")
	}
	if !useAVX2 || !useSSE4 {
		t.Skip("needs both AVX2 and SSE4.1")
	}
	defer func(avx2 bool) { useAVX2 = avx2 }(useAVX2)

	password, salt := []byte("password"), []byte("choosing random salts is hard")
	var lat [2][]time.Duration // index 0: SSE4.1, 1: AVX2
	hash := func(i int, record bool) []byte {
		useAVX2 = i == 1
		start := time.Now()
		key := IDKey(password, salt, 1, 47104, 1, 32)
		if record {
			lat[i] = append(lat[i], time.Since(start))
		}
		return key
	}

	hash(0, false)
	hash(1, false)
	for start := time.Now(); time.Since(start) < *interleave; {
		sse, avx := hash(0, true), hash(1, true)
		if !bytes.Equal(sse, avx) {
			t.Fatal("SSE4.1 and AVX2 outputs differ")
		}
	}
	for i, name := range []string{"SSE4.1", "AVX2"} {
		s := lat[i]
		var total time.Duration
		for _, d := range s {
			total += d
		}
		sort.Slice(s, func(a, b int) bool { return s[a] < s[b] })
		t.Logf("%-6s hashes=%d hash/s=%.2f p50=%v p95=%v", name, len(s),
			float64(len(s))/total.Seconds(), s[len(s)/2], s[len(s)*95/100])
	}
}
