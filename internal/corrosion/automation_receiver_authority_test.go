package corrosion

import (
	"context"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

func TestReceiverInitialAuthorityRefusals(t *testing.T) {
	for _, mode := range []string{"foreign-CA", "missing-genesis", "uncertified-genesis", "wrong-transition", "forced-transition", "wrong-target", "wrong-incarnation", "foreign-roster", "duplicate-roster", "duplicate-incarnation", "missing-source"} {
		t.Run(mode, func(t *testing.T) {
			_, r, q, _, _ := receiverFixture(t)
			ctx := context.Background()
			var err error
			switch mode {
			case "foreign-CA":
				r.dir = newClaimTestCA(t).pkiDir(t, "b")
			case "missing-genesis":
				_, err = r.client.db.Exec(`DELETE FROM voter_configs WHERE generation=1`)
			case "uncertified-genesis":
				_, err = r.client.db.Exec(`UPDATE voter_configs SET certificate='{}' WHERE generation=1`)
			case "wrong-transition":
				_, err = r.client.db.Exec(`UPDATE voter_configs SET created_by='foreign' WHERE generation=2`)
			case "forced-transition":
				_, err = r.client.db.Exec(`UPDATE voter_configs SET change='force:reseed' WHERE generation=2`)
			case "wrong-target":
				q.Intent.Target = "a"
			case "wrong-incarnation":
				_, err = r.client.ReplaceVoterIncarnationForTest(ctx)
			case "foreign-roster":
				q.Intent.Sources = []VoterMember{{Name: "foreign", Incarnation: "not-old"}}
			case "duplicate-roster":
				q.Intent.Sources = append(q.Intent.Sources, q.Intent.Sources[0])
			case "duplicate-incarnation":
				q.Intent.Sources = append(q.Intent.Sources, VoterMember{Name: "other", Incarnation: q.Intent.Sources[0].Incarnation})
			case "missing-source":
				q.Intent.Sources = nil
			}
			if err != nil {
				t.Fatal(err)
			}
			active := receiverActive(t, r.client)
			if _, err = r.Begin(ctx, q.Intent, nil); err == nil {
				t.Fatal("unanchored or wrong local receiver authority accepted")
			}
			rows, err := r.client.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_receiver_jobs`)
			if err != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
				t.Fatal("failed authorization selected durable attempt", err)
			}
			if receiverActive(t, r.client) != active {
				t.Fatal("failed initial receiver authorization mutated active state")
			}
		})
	}
}
func TestReceiverWholeOldElectorateRoster(t *testing.T) {
	ctx := context.Background()
	ca := newClaimTestCA(t)
	a, b, c, d := newClaimTestVoter(t, ca, "a"), newClaimTestVoter(t, ca, "b"), newClaimTestVoter(t, ca, "c"), newClaimTestVoter(t, ca, "d")
	voters := []*claimTestVoter{a, b, c, d}
	choose := func(value VoterConfigValue, signers []*claimTestVoter) {
		key := ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: value.Generation - 1}
		ballot := testBallot(1, "a")
		digest, _ := (ClaimValue{Config: &value}).Digest()
		cert := ClaimCertificate{Key: key, ConfigGeneration: key.OwnerEpoch, Ballot: ballot, ValueDigest: digest}
		for _, v := range signers {
			result, err := v.c.ClaimAccept(ctx, key, ballot, ClaimValue{Config: &value}, key.OwnerEpoch, v.signer, nil)
			if err != nil || !result.Accepted {
				t.Fatal("actual membership voter", err)
			}
			cert.Accepts = append(cert.Accepts, *result.Accept)
		}
		for _, v := range voters {
			if err := WriteVoterConfig(ctx, v.c, value, cert); err != nil {
				t.Fatal(err)
			}
		}
	}
	choose(VoterConfigValue{Generation: 1, Members: membersOf(a, b, c), Change: VoterChangeGenesis, CreatedBy: "a", CreatedAt: "t"}, []*claimTestVoter{a, b, c})
	for _, v := range []*claimTestVoter{a, b, c} {
		if err := RecordVoterAdoption(ctx, v.c, 1); err != nil {
			t.Fatal(err)
		}
	}
	choose(VoterConfigValue{Generation: 2, Members: membersOf(a, b, c, d), Change: "add:d", CreatedBy: "a", CreatedAt: "t2"}, []*claimTestVoter{a, b})
	pair, err := pki.ServedHostKeyPair(d.pki)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = InsertHost(ctx, d.c, HostRecord{Name: "d", Address: "127.0.0.1", SSHUser: "test", CertSerial: leaf.SerialNumber.Text(16), State: "active"}); err != nil {
		t.Fatal(err)
	}
	r := NewAutomationReceiver(d.c, d.pki)
	intent := AutomationSourceRequest{Generation: 1, Target: "d", Job: "whole-old", Revision: 1, Sources: membersOf(a)}
	active := receiverActive(t, d.c)
	if _, err = r.Begin(ctx, intent, nil); err == nil {
		t.Fatal("reachable one-source majority replaced whole three-voter electorate")
	}
	intent.Sources = membersOf(a, b)
	if _, err = r.Begin(ctx, intent, nil); err != nil {
		t.Fatal("actual two-of-three old roster refused", err)
	}
	if receiverActive(t, d.c) != active {
		t.Fatal("roster validation altered active state")
	}
}
func TestReceiverRenewedSourcePublication(t *testing.T) {
	p, r, q, exportCtx, _ := receiverFixture(t)
	ctx := context.Background()
	if _, _, err := pki.RenewLocal(filepath.Join(p.dir, "ca.crt"), filepath.Join(p.dir, "ca.key"), p.dir, "a"); err != nil {
		t.Fatal(err)
	}
	signer, err := LoadClaimSigner(p.dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	// Normal re-attestation of exact retained votes supplies the required current
	// certified predecessor chain. No historical expiry/pin relaxation is used.
	for g := int64(1); g <= 2; g++ {
		key := ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: g - 1}
		st, found, err := p.client.ClaimState(ctx, key)
		if err != nil || !found || st.Accept == nil {
			t.Fatal(err)
		}
		accept, err := signer.Sign(key, g-1, st.Accepted, st.ValueDigest, st.Accept.VoterIncarnation)
		if err != nil {
			t.Fatal(err)
		}
		cert := ClaimCertificate{Key: key, ConfigGeneration: g - 1, Ballot: st.Accepted, ValueDigest: st.ValueDigest, Accepts: []ClaimAccept{accept}}
		// Fixture installs current re-attested certificate bytes for the identical
		// decided value. WriteVoterConfig deliberately ignores an existing row.
		raw, err := cert.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = r.client.db.Exec(`UPDATE voter_configs SET certificate=? WHERE generation=?`, raw, g); err != nil {
			t.Fatal(err)
		}
	}
	q.Intent.Revision++
	candidate, err := p.Prepare(ctx, q.Intent)
	if err != nil {
		t.Fatal("actual renewed source preparation", err)
	}
	q.Publication, err = p.Publish(ctx, candidate)
	if err != nil {
		t.Fatal("actual renewed source publication", err)
	}
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal("receiver normal renewed membership chain", err)
	}
	active := receiverActive(t, r.client)
	receiverThrough(t, p, r, a, q, exportCtx, 11)
	if receiverActive(t, r.client) != active {
		t.Fatal("renewed source inert ingress changed active state")
	}
	t.Log("fresh renewed source attestation received over original immutable cut; expired anchored history semantics remain the later aggregate audit")
}

func TestReceiverMembershipChangesDuringTrustLearning(t *testing.T) {
	_, r, q, _, _ := receiverFixture(t)
	ctx := context.Background()
	var changedActive string
	r.afterMembershipLearning = func() {
		// Exact valid signature bytes are preserved; add an ordinary duplicate vote
		// so the changed canonical certificate still verifies independently. This
		// exercises the actual DB between learning and capture, not a false flag.
		cfg, err := GetVoterConfig(ctx, r.client, 1)
		if err != nil || cfg == nil {
			t.Fatal(err)
		}
		cert, err := DecodeClaimCertificate(cfg.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		cert.Accepts = append(cert.Accepts, cert.Accepts[0])
		raw, err := cert.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = r.client.db.Exec(`UPDATE voter_configs SET certificate=? WHERE generation=1`, raw); err != nil {
			t.Fatal(err)
		}
		// Both owners are actually obtainable at this seam; no DB-to-PKI lock
		// inversion or owner lock is hidden around the renewal-learning callback.
		if _, err = pki.CaptureHostTrust(ctx, r.dir, r.client.hostName); err != nil {
			t.Fatal(err)
		}
		changedActive = receiverActive(t, r.client)
	}
	if _, err := r.Begin(ctx, q.Intent, nil); err == nil || !strings.Contains(err.Error(), "membership changed during trust learning") {
		t.Fatal("receiver verified certificate bytes it had not learned", err)
	}
	if receiverActive(t, r.client) != changedActive {
		t.Fatal("refused learning race mutated active state")
	}
	rows, err := r.client.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_receiver_jobs`)
	if err != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
		t.Fatal("learning race selected current attempt", err)
	}
	r.afterMembershipLearning = nil
	if _, err = r.Begin(ctx, q.Intent, nil); err != nil {
		t.Fatal("fresh normal reauthorization after race did not progress", err)
	}
}
