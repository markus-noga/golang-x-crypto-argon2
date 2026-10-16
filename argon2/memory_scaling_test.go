// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package argon2_test

import (
	"bytes"
	"flag"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

var (
	scalingWorkers = flag.Int("argon2.scaling-workers", 0, "if non-zero, run TestScaling with this many workers")
	scalingMode    = flag.String("argon2.scaling-mode", "reuse", "TestScaling: \"classic\" (IDKey allocates on every call) or \"reuse\" (one Memory per worker)")
	scalingDur     = flag.Duration("argon2.scaling-dur", 15*time.Second, "TestScaling: measured duration")
	scalingWarm    = flag.Duration("argon2.scaling-warm", 2*time.Second, "TestScaling: warm-up before measuring")
)

// TestScaling measures how Argon2id on the OWASP-recommended parameters
// (m=47104 KiB, t=1, p=1) scales with the number of workers, for the two ways
// of allocating the working memory. The workers model a server with one worker
// per core: they take requests from a bounded queue as fast as they can, and
// either call IDKey, which allocates on every call, or each use their own
// Memory. It reports throughput and the p50/p95 latency of a hash (service
// time, without queueing), the number of garbage collections and the peak
// resident set size. It is skipped unless -argon2.scaling-workers is set.
//
// Run each variant in a process of its own, so that the garbage of one does
// not affect the other, with GOMAXPROCS equal to the number of workers and the
// process pinned to that many cores, alternating the variants to see drift.
// For example, with four workers on cores 0, 2, 4 and 6 (one thread per
// physical core):
//
//	go test -c -o argon2.test golang.org/x/crypto/argon2
//	for mode in classic reuse reuse classic; do
//		GOMAXPROCS=4 taskset -c 0,2,4,6 ./argon2.test -test.run TestScaling \
//			-argon2.scaling-workers=4 -argon2.scaling-mode=$mode -test.v
//	done
func TestScaling(t *testing.T) {
	workers := *scalingWorkers
	if workers == 0 {
		t.Skip("set -argon2.scaling-workers=<n> to run")
	}
	reuse := false
	switch *scalingMode {
	case "classic":
	case "reuse":
		reuse = true
	default:
		t.Fatalf("unknown -argon2.scaling-mode %q", *scalingMode)
	}
	password, salt := []byte("password"), []byte("choosing random salts is hard")
	want := argon2.IDKey(password, salt, 1, 47104, 1, 32)

	jobs := make(chan struct{}, workers) // the bounded queue
	warmEnd := time.Now().Add(*scalingWarm)
	end := warmEnd.Add(*scalingDur)
	go func() {
		for time.Now().Before(end) {
			jobs <- struct{}{}
		}
		close(jobs)
	}()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	latencies := make([][]time.Duration, workers)
	var wg sync.WaitGroup
	for w := range latencies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var m argon2.Memory
			for range jobs {
				start := time.Now()
				var key []byte
				if reuse {
					key = m.IDKey(password, salt, 1, 47104, 1, 32)
				} else {
					key = argon2.IDKey(password, salt, 1, 47104, 1, 32)
				}
				done := time.Now()
				if !bytes.Equal(key, want) {
					t.Error("unexpected output")
					return
				}
				if done.After(warmEnd) && !done.After(end) {
					latencies[w] = append(latencies[w], done.Sub(start))
				}
			}
		}()
	}
	wg.Wait()
	runtime.ReadMemStats(&after)

	var all []time.Duration
	var total time.Duration
	fewest, most := int(^uint(0)>>1), 0
	for _, l := range latencies {
		all = append(all, l...)
		for _, d := range l {
			total += d
		}
		fewest, most = min(fewest, len(l)), max(most, len(l))
	}
	if len(all) == 0 {
		t.Fatal("no hashes finished in the measured time")
	}
	sort.Slice(all, func(a, b int) bool { return all[a] < all[b] })
	peak := ""
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "VmHWM") {
				peak = strings.Join(strings.Fields(l), " ")
			}
		}
	}
	round := func(d time.Duration) time.Duration { return d.Round(10 * time.Microsecond) }
	t.Logf("%-7s workers=%d hashes=%d (per worker %d..%d) hash/s=%.2f p50=%v p95=%v mean=%v GCs=%d %s",
		*scalingMode, workers, len(all), fewest, most, float64(len(all))/scalingDur.Seconds(),
		round(all[len(all)/2]), round(all[len(all)*95/100]), round(total/time.Duration(len(all))),
		after.NumGC-before.NumGC, peak)
}
