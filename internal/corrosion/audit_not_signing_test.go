package corrosion

import (
	"context"
	"reflect"
	"testing"
)

// NotSigning answers the question a bare Unsigned count cannot: is this history,
// or is a host still writing rows nobody can check?
//
// The kvm003-f3 lab is why it exists. Five hosts, signing never switched on, and
// verify said "212 predate tamper-evidence" — every row, including one written
// minutes earlier, described as old. Nothing on screen said that no host was
// signing at all.

func TestNotSigning_HostsThatNeverSignedAreListed(t *testing.T) {
	c := newAuditTestClient(t)
	ins(t, c, "a1", "node-0", "2026-10-01T06:00:01Z")
	ins(t, c, "a2", "node-0", "2026-10-01T06:00:02Z")
	ins(t, c, "a3", "node-0", "2026-10-01T06:00:03Z")
	ins(t, c, "b1", "node-1", "2026-10-01T06:00:01Z")

	res := verify(t, c)
	want := []string{"node-0: 3 unsigned rows", "node-1: 1 unsigned rows"}
	if !reflect.DeepEqual(res.NotSigning, want) {
		t.Fatalf("NotSigning = %q, want %q", res.NotSigning, want)
	}
	if res.Unsigned != 4 || res.Tampered() || res.Unverified() {
		t.Fatalf("hosts that never signed are not a finding: %+v", res)
	}
}

// History from before a host adopted its key is ordinary, and the host is
// signing now — so it is not listed, though its old rows are still counted.
func TestNotSigning_HistoryBeforeAdoptionIsNotListed(t *testing.T) {
	ctx := context.Background()
	const host = "node-0"
	c := newAuditTestClient(t)
	ins(t, c, "old1", host, "2026-10-01T06:00:01Z")
	ins(t, c, "old2", host, "2026-10-01T06:00:02Z")

	kr, err := LoadAuditKeyring(testPKI(t, host), host)
	if err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}
	c.SetAuditKeyring(kr)
	if _, err := AdoptAuditKey(ctx, c, kr, host); err != nil {
		t.Fatalf("AdoptAuditKey: %v", err)
	}
	ins(t, c, "new1", host, "2026-10-01T06:00:03Z")

	res := verify(t, c)
	if len(res.NotSigning) != 0 {
		t.Fatalf("a host that is signing now is listed as not signing: %q", res.NotSigning)
	}
	if res.Unsigned != 2 || res.Tampered() {
		t.Fatalf("pre-adoption history should be 2 unsigned rows and no finding: %+v", res)
	}
}

// A host that retired its key and kept writing has stopped signing, deliberately.
// Its rows are not evidence — the retirement closed the contract — but it IS not
// signing now, and that is what the list reports.
func TestNotSigning_AHostThatRetiredItsKeyIsListed(t *testing.T) {
	ctx := context.Background()
	const host = "node-0"
	c, kr, dir := signedClient(t, host)
	ins(t, c, "s1", host, "2026-10-01T06:00:01Z")
	seq, err := HostTailSeq(ctx, c, host)
	if err != nil {
		t.Fatalf("HostTailSeq: %v", err)
	}
	if err := RetireAuditKey(ctx, c, kr, host, kr.KeyID(), seq); err != nil {
		t.Fatalf("RetireAuditKey: %v", err)
	}
	verifier, err := LoadAuditVerifier(dir)
	if err != nil {
		t.Fatalf("LoadAuditVerifier: %v", err)
	}
	c.SetAuditKeyring(verifier)
	ins(t, c, "u1", host, "2026-10-01T06:00:02Z")

	res := verify(t, c)
	if want := []string{"node-0: 1 unsigned rows"}; !reflect.DeepEqual(res.NotSigning, want) {
		t.Fatalf("NotSigning = %q, want %q", res.NotSigning, want)
	}
	if res.Tampered() {
		t.Fatalf("rows after a signed retirement are not evidence: %+v", res)
	}
}

// A host under a live contract that writes an unsigned row is EVIDENCE, and is
// reported as such. Listing it as merely "not signing" too would put a finding
// and an excuse for it side by side.
func TestNotSigning_AContractedHostIsReportedAsEvidenceNotListed(t *testing.T) {
	const host = "node-0"
	c, _, dir := signedClient(t, host)
	ins(t, c, "s1", host, "2026-10-01T06:00:01Z")
	verifier, err := LoadAuditVerifier(dir)
	if err != nil {
		t.Fatalf("LoadAuditVerifier: %v", err)
	}
	c.SetAuditKeyring(verifier) // the key went away; the contract did not
	ins(t, c, "u1", host, "2026-10-01T06:00:02Z")

	res := verify(t, c)
	if len(res.UnsignedAfterSigned) != 1 {
		t.Fatalf("an unsigned row under a live contract was not reported: %+v", res)
	}
	if len(res.NotSigning) != 0 {
		t.Fatalf("a contracted host is also listed as not signing: %q", res.NotSigning)
	}
}

// A daemon publishes its certificate at start and records the adoption about a
// minute later. In between it has no contract, but its rows are already signed:
// it is signing now and must not be listed, or every restart would name the host.
func TestNotSigning_AStartingDaemonIsNotListed(t *testing.T) {
	ctx := context.Background()
	const host = "node-0"
	c := newAuditTestClient(t)
	ins(t, c, "old1", host, "2026-10-01T06:00:01Z")
	kr, err := LoadAuditKeyring(testPKI(t, host), host)
	if err != nil {
		t.Fatalf("LoadAuditKeyring: %v", err)
	}
	c.SetAuditKeyring(kr)
	if err := kr.PublishSigningKey(ctx, c); err != nil {
		t.Fatalf("PublishSigningKey: %v", err)
	}
	ins(t, c, "new1", host, "2026-10-01T06:00:02Z")

	res := verify(t, c)
	if len(res.NotSigning) != 0 || len(res.NeverAdopted) != 0 {
		t.Fatalf("a host whose latest row is signed is reported: NotSigning=%q NeverAdopted=%q",
			res.NotSigning, res.NeverAdopted)
	}
}

// A host already reported as never adopted is not listed a second time.
func TestNotSigning_ANeverAdoptedHostIsNotDoubleReported(t *testing.T) {
	const host = "node-0"
	c, _, dir := signedClient(t, host)
	publishCertOnlyAged(t, c, dir, host)
	ins(t, c, "u1", host, "2026-10-01T06:00:01Z")
	verifier, err := LoadAuditVerifier(dir)
	if err != nil {
		t.Fatalf("LoadAuditVerifier: %v", err)
	}
	c.SetAuditKeyring(verifier)

	res := verify(t, c)
	if len(res.NeverAdopted) != 1 || len(res.NotSigning) != 0 {
		t.Fatalf("NeverAdopted = %q, NotSigning = %q; want the host in the first only",
			res.NeverAdopted, res.NotSigning)
	}
}
