package storage

import "sync/atomic"

// testHook is a package value a test replaces (an Override*ForTest). It is
// read and written atomically: a Bounded call the caller gave up on keeps
// running in its goroutine after the caller — and the test — has moved on,
// so it can read a hook while the test's cleanup restores it. Production
// never writes one.
type testHook[T any] struct{ p atomic.Pointer[T] }

func newTestHook[T any](v T) *testHook[T] {
	h := &testHook[T]{}
	h.p.Store(&v)
	return h
}

// get is the hook's current value.
func (h *testHook[T]) get() T { return *h.p.Load() }

// set replaces the value and returns what restores the previous one.
func (h *testHook[T]) set(v T) (restore func()) {
	prev := h.p.Swap(&v)
	return func() { h.p.Store(prev) }
}
