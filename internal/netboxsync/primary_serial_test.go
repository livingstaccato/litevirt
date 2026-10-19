package netboxsync

import (
	"context"
	"sync"
	"testing"
	"time"
)

// wholeRowVirt saves a VM's primaries the way NetBox does: a PATCH reads the
// whole row, and writes the whole row back with its one field changed. Each
// call waits, after its read, until another has read too (or a short time
// passes), so two calls that overlap both read the row before either writes.
type wholeRowVirt struct {
	*stubVirt
	rowMu    sync.Mutex
	p4, p6   int
	reads    int
	readOnce chan struct{}
}

func (w *wholeRowVirt) patch(set func(p4, p6 *int)) {
	w.rowMu.Lock()
	p4, p6 := w.p4, w.p6
	w.reads++
	if w.reads == 2 {
		close(w.readOnce)
	}
	w.rowMu.Unlock()
	select {
	case <-w.readOnce:
	case <-time.After(300 * time.Millisecond):
	}
	set(&p4, &p6)
	w.rowMu.Lock()
	w.p4, w.p6 = p4, p6
	w.rowMu.Unlock()
}

func (w *wholeRowVirt) SetPrimaryIP4(_ context.Context, _, ipID int) error {
	w.patch(func(p4, _ *int) { *p4 = ipID })
	return nil
}

func (w *wholeRowVirt) SetPrimaryIP6(_ context.Context, _, ipID int) error {
	w.patch(func(_, p6 *int) { *p6 = ipID })
	return nil
}

// A dual-stack VM's two primaries are set in one pass. Run concurrently
// against a whole-row save, the second write put back the field the first had
// just set, and the pass stamped convergence with one primary missing.
func TestBothPrimariesOfOneVMSurviveAWholeRowSave(t *testing.T) {
	w := &wholeRowVirt{stubVirt: &stubVirt{}, readOnce: make(chan struct{})}
	r := newTestReconciler(t, w)
	if err := r.apply(context.Background(), []Action{
		{Kind: kindVM, Op: opPrimaryIP, Key: vmIdent("u1"), ParentNetBoxID: 11, IPID: 41},
		{Kind: kindVM, Op: opPrimaryIP6, Key: vmIdent("u1"), ParentNetBoxID: 11, IPID: 60},
	}, desiredIndex{}, fp); err != nil {
		t.Fatal(err)
	}
	if w.p4 != 41 || w.p6 != 60 {
		t.Fatalf("primaries after the pass: ip4=%d ip6=%d, want 41 and 60", w.p4, w.p6)
	}
}
