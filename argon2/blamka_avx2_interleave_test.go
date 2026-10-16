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

var interleave = flag.Duration("argon2.interleave", 0, "if non-zero, run TestInterleave for this long")

// TestInterleave compares the amd64 implementations available on this CPU on
// the OWASP-recommended Argon2id parameters (m=47104 KiB, t=1, p=1),
// alternating one hash of each in turn so that host load drift affects all
// equally. It reports throughput and p50/p95 latency per implementation and
// checks that the outputs agree. It is skipped unless -argon2.interleave is
// set. For stable numbers pin to one core, for example:
//
//	GOMAXPROCS=1 taskset -c 2 go test -run TestInterleave$ \
//		-argon2.interleave=60s -v -timeout 10m
func TestInterleave(t *testing.T) {
	if *interleave == 0 {
		t.Skip("set -argon2.interleave=<duration> to run")
	}
	defer func(sse4, avx2, avx512 bool) {
		useSSE4, useAVX2, useAVX512 = sse4, avx2, avx512
	}(useSSE4, useAVX2, useAVX512)

	type impl struct {
		name      string
		ok        bool
		set       func()
		latencies []time.Duration
	}
	impls := []*impl{
		{"SSE4.1", useSSE4, func() { useAVX2, useAVX512 = false, false }, nil},
		{"AVX2", useAVX2, func() { useAVX2, useAVX512 = true, false }, nil},
		{"AVX512", useAVX512, func() { useAVX2, useAVX512 = false, true }, nil},
	}
	var active []*impl
	for _, im := range impls {
		if im.ok {
			active = append(active, im)
		}
	}
	if len(active) < 2 {
		t.Skip("needs at least two implementations")
	}

	password, salt := []byte("password"), []byte("choosing random salts is hard")
	hash := func(im *impl, record bool) []byte {
		im.set()
		start := time.Now()
		key := IDKey(password, salt, 1, 47104, 1, 32)
		if record {
			im.latencies = append(im.latencies, time.Since(start))
		}
		return key
	}

	for _, im := range active {
		hash(im, false)
	}
	for start := time.Now(); time.Since(start) < *interleave; {
		var first []byte
		for _, im := range active {
			key := hash(im, true)
			if first == nil {
				first = key
			} else if !bytes.Equal(first, key) {
				t.Fatalf("%s output differs from %s", im.name, active[0].name)
			}
		}
	}
	var base float64
	for i, im := range active {
		s := im.latencies
		var total time.Duration
		for _, d := range s {
			total += d
		}
		sort.Slice(s, func(a, b int) bool { return s[a] < s[b] })
		rate := float64(len(s)) / total.Seconds()
		if i == 0 {
			base = rate
		}
		t.Logf("%-9s hashes=%d hash/s=%.2f (%.2fx) p50=%v p95=%v", im.name, len(s),
			rate, rate/base, s[len(s)/2], s[len(s)*95/100])
	}
}
