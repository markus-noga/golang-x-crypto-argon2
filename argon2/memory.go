// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package argon2

import "sync/atomic"

// A Memory is reusable working memory for Argon2. Key and IDKey allocate, and
// the garbage collector reclaims, the memory of every call; a Memory instead
// keeps it between calls, which saves the allocation and the zeroing of it,
// and the garbage collection pressure of memory-hard parameters.
//
// The zero value is ready to use. The memory is allocated by the first call
// and grows if a later call needs more; it is never shrunk. The results are
// the same as those of the package-level Key and IDKey.
//
// A Memory holds data derived from the passwords it was used with until it is
// overwritten by a later call, cleared with [Memory.Clear] or garbage
// collected.
//
// A Memory must not be used by more than one call at a time; doing so panics.
// To hash concurrently use one Memory per goroutine, for example one per
// worker of a fixed-size pool.
type Memory struct {
	b    []block
	busy atomic.Bool
}

// Key is like the package-level function Key, using m as working memory.
func (m *Memory) Key(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKeyIn(m, argon2i, password, salt, nil, nil, time, memory, threads, keyLen)
}

// IDKey is like the package-level function IDKey, using m as working memory.
func (m *Memory) IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKeyIn(m, argon2id, password, salt, nil, nil, time, memory, threads, keyLen)
}

// Clear overwrites the working memory with zeros and keeps it for reuse.
func (m *Memory) Clear() {
	m.acquire()
	defer m.release()
	clear(m.b)
}

func (m *Memory) acquire() {
	if !m.busy.CompareAndSwap(false, true) {
		panic("argon2: Memory used by concurrent calls")
	}
}

func (m *Memory) release() { m.busy.Store(false) }

// blocks returns n blocks of working memory with arbitrary contents. A nil m
// allocates new memory.
func (m *Memory) blocks(n uint32) []block {
	if m == nil {
		return make([]block, n)
	}
	if uint32(cap(m.b)) < n {
		m.b = make([]block, n)
	}
	return m.b[:n]
}
