package corrosion

import (
	"context"
	"encoding/json"
	"github.com/litevirt/litevirt/internal/pki"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReceiverEstablishedLegacyNeedsExplicitReestablishment(t *testing.T) {
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{1, 1}})
	ctx := context.Background()
	rows, err := f.local.c.Query(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name='local_automation_receiver_established'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) > 0 {
		if _, err = f.local.c.db.Exec(`DELETE FROM local_automation_receiver_established`); err != nil {
			t.Fatal(err)
		}
	}
	f.receiver.Close()
	reopened := NewAutomationReceiver(f.local.c, f.local.pki)
	defer reopened.Close()
	if a, err := reopened.Begin(ctx, f.attempt.request, nil); a != nil || err == nil || !strings.Contains(err.Error(), "receiver establishment") {
		t.Fatalf("legacy inert receiver rows silently became established ownership: attempt=%v err=%v", a != nil, err)
	}
}

func TestReceiverEstablishedArtifactExactOriginals(t *testing.T) {
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{1, 1}})
	ctx := context.Background()
	a := f.attempt
	original, err := a.view.PublicEvidence()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := decodeReceiverBinding(a.id, a.request.Job, a.request.Revision, a.binding)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.receiver.prepareEstablishment(ctx, a, original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeReceiverEstablished(raw, binding, original, f.local.name); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"signature", "chain", "host", "purpose", "job", "original", "root", "noncanonical", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			var signed receiverEstablishedArtifact
			if err := json.Unmarshal(raw, &signed); err != nil {
				t.Fatal(err)
			}
			target := f.local.name
			retained := original
			pin := *binding
			switch mode {
			case "signature":
				signed.Signature[0] ^= 1
			case "chain":
				pair, e := pki.ServedHostKeyPair(f.voters[0].pki)
				if e != nil {
					t.Fatal(e)
				}
				signed.Chain = pair.Certificate
			case "host":
				target = f.voters[0].name
			case "purpose":
				var m receiverEstablishedManifest
				_ = json.Unmarshal(signed.Manifest, &m)
				m.Purpose = "automation-membership-source"
				signed.Manifest, _ = json.Marshal(m)
			case "job":
				pin.binding = append(append([]byte(nil), pin.binding...), byte(' '))
			case "original":
				view, e := pki.CaptureHostTrust(ctx, f.voters[0].pki, f.voters[0].name)
				if e != nil {
					t.Fatal(e)
				}
				retained, e = view.PublicEvidence()
				if e != nil {
					t.Fatal(e)
				}
			case "root":
				ca := newClaimTestCA(t)
				dir := ca.pkiDir(t, f.local.name)
				view, e := pki.CaptureHostTrust(ctx, dir, f.local.name)
				if e != nil {
					t.Fatal(e)
				}
				retained, e = view.PublicEvidence()
				if e != nil {
					t.Fatal(e)
				}
			case "oversized":
				signed.Signature = make([]byte, 257)
			}
			changed, e := json.Marshal(signed)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "noncanonical" {
				changed = append(changed, ' ')
			}
			if _, e = decodeReceiverEstablished(changed, &pin, retained, target); e == nil {
				t.Fatal("accepted altered receiver establishment", mode)
			}
		})
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = f.receiver.prepareEstablishment(ctx, a, original); err == nil {
		t.Fatal("canceled owner signed establishment")
	}
}

func TestReceiverEstablishedExpiredSignerRenewedOwner(t *testing.T) {
	ctx := context.Background()
	expires := time.Now().Truncate(time.Second).Add(6 * time.Second)
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{1, 1}, Initial: func(t *testing.T, v *claimTestVoter, ca claimTestCA) {
		if v.name != "receiver" {
			return
		}
		v.signer = currentShortSigner(t, ca, v, expires)
		if err := os.WriteFile(filepath.Join(v.pki, "host.crt"), []byte(v.signer.certPEM), 0600); err != nil {
			t.Fatal(err)
		}
	}})
	a := f.attempt
	original, err := a.view.PublicEvidence()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := decodeReceiverBinding(a.id, a.request.Job, a.request.Revision, a.binding)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.receiver.prepareEstablishment(ctx, a, original)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(expires) + 25*time.Millisecond)
	if _, err = decodeReceiverEstablished(raw, binding, original, f.local.name); err != nil {
		t.Fatal("expired authentic artifact lost recorded provenance", err)
	}
	if cap, e := a.view.ValidateServedHost(ctx, a.pair); e == nil {
		cap.Discard()
		t.Fatal("expired artifact signer became current authority")
	}
	if _, _, err = pki.RenewLocal(f.ca.cert, f.ca.key, f.local.pki, f.local.name); err != nil {
		t.Fatal(err)
	}
	fresh, err := f.receiver.Begin(ctx, a.request, nil)
	if err != nil {
		t.Fatal("renewed local owner cannot reauthenticate", err)
	}
	repaired, err := f.receiver.prepareEstablishment(ctx, fresh, original)
	if err != nil {
		t.Fatal("current owner cannot explicitly establish original legacy evidence", err)
	}
	if _, err = decodeReceiverEstablished(repaired, binding, original, f.local.name); err != nil {
		t.Fatal(err)
	}
	if _, err = f.receiver.prepareEstablishment(ctx, a, original); err == nil {
		t.Fatal("old process trust revived after renewal")
	}
}
