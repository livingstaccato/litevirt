package storage

import (
	"context"
	"strings"
	"testing"
)

func (f *recordISCSIAdm) teardown(portal string) error {
	d := &iscsiDriver{target: prepTarget, opts: map[string]string{"portal": portal, "lun": "1"}, run: f.run}
	return d.Teardown(context.Background())
}

// A pool delete logs out of its target AND removes the target's node record
// at the pool's portal, so nothing logs back in to a removed target: a record
// with node.startup=automatic is logged in to again by iscsid at its next
// start (lab 2). Another target's record on the same portal is not touched.
//
// On 458db618 the record stayed: Teardown only logged out.
func TestISCSITeardown_LogsOutAndRemovesTheNodeRecord(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 1}, {prepOther, 1}}
	f.tpgt[prepTarget] = 1
	f.accept[prepTarget] = "op:op-secret"
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, operatorRecord)
	f.setRecord(t, prepOther, "10.0.0.5:3260", 1, operatorRecord)
	other := f.recordFile(prepOther, "10.0.0.5:3260", 1)
	if err := f.prepare("10.0.0.5:3260"); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	if err := f.teardown("10.0.0.5:3260"); err != nil {
		t.Fatalf("Teardown: %v; calls %v", err, f.calls)
	}
	if f.sessions["10.0.0.5:3260 "+prepTarget] {
		t.Fatal("still logged in")
	}
	if rs := f.recs(prepTarget, "10.0.0.5:3260"); len(rs) != 0 {
		t.Fatalf("the target's node record is left (%d), so iscsid logs back in to it; calls %v", len(rs), f.calls)
	}
	if got := f.recordFile(prepOther, "10.0.0.5:3260", 1); got != other {
		t.Fatalf("another target's record changed: %q, was %q", got, other)
	}
	// Idempotent: a second delete finds nothing to do and succeeds.
	if err := f.teardown("10.0.0.5:3260"); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
}

// A record with no session (the host was never logged in, or a reboot logged
// it out) is removed too.
func TestISCSITeardown_RemovesTheRecordWithNoSession(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, operatorRecord)
	if err := f.teardown("10.0.0.5:3260"); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if rs := f.recs(prepTarget, "10.0.0.5:3260"); len(rs) != 0 {
		t.Fatalf("the record of a target with no session is left; calls %v", f.calls)
	}
}

// A logout that fails keeps the record (and says so): deleting the record of
// a session still up is refused by iscsiadm, and the pool delete must not
// report a teardown that did not happen.
func TestISCSITeardown_FailedLogoutKeepsTheRecord(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 1}}
	f.tpgt[prepTarget] = 1
	f.accept[prepTarget] = "op:op-secret"
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, operatorRecord)
	if err := f.prepare("10.0.0.5:3260"); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	f.logoutErr = "iscsiadm: initiator reported error (8 - connection timed out)"
	err := f.teardown("10.0.0.5:3260")
	if err == nil || !strings.Contains(err.Error(), "logout") {
		t.Fatalf("Teardown = %v, want the logout failure", err)
	}
	if rs := f.recs(prepTarget, "10.0.0.5:3260"); len(rs) != 1 {
		t.Fatalf("the record went with a failed logout")
	}
}
