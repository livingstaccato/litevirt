package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

func TestReceiverCurrentWholeFiveSemantics(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(fmt.Sprint(conflict), func(t *testing.T) {
			ctx := context.Background()
			key := LeaseTermClaimKey("current_maxima", 7)
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 5, Sources: 3, Heads: []int{3, 1, 1}, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
				for _, i := range []int{0, 2} {
					round := uint64(i + 2)
					if conflict {
						round = 2
					}
					value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: key.OwnerEpoch, Holder: fmt.Sprintf("holder%d", i)}}
					reply, err := voters[i].c.ClaimAccept(ctx, key, testBallot(round, "common"), value, 1, voters[i].signer, unreachable)
					if err != nil || !reply.Accepted {
						t.Fatal("real original acceptance", reply, err)
					}
				}
				reply, err := voters[1].c.ClaimPrepare(ctx, key, testBallot(9, "common"), 1)
				if err != nil || !reply.Promised {
					t.Fatal("real higher independent promise", reply, err)
				}
			}})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
			p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
			if conflict {
				if p != nil {
					p.Discard()
				}
				if err == nil || !strings.Contains(err.Error(), "contradictory exact claim ballot") {
					t.Fatal("current proof accepted exact-ballot contradiction", err)
				}
			} else {
				if err != nil {
					t.Fatal("genuine minority maximum and losing copies refused", err)
				}
				rows, e := f.local.c.Query(ctx, `SELECT head FROM local_automation_aggregates WHERE id=?`, p.evidence.aggregate)
				var head AutomationPrefix
				if e != nil || len(rows) != 1 || json.Unmarshal(rows[0].Bytes("head"), &head) != nil || head.Sequence != 3 {
					t.Fatal("minority maximum lost", rows, e)
				}
				rows, e = f.local.c.Query(ctx, `SELECT (SELECT COUNT(*) FROM local_automation_aggregate_copies WHERE bundle=?) AS copies,(SELECT COUNT(*) FROM local_automation_aggregate_maxima WHERE bundle=?) AS maxima`, p.evidence.aggregate, p.evidence.aggregate)
				if e != nil || len(rows) != 1 || rows[0].Int64("copies") != 3 || rows[0].Int64("maxima") != 1 {
					t.Fatal("current proof lost originals/maxima", rows, e)
				}
				if err = f.receiver.consumeCurrent(ctx, p); err != nil {
					t.Fatal(err)
				}
			}
			if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool {
				t.Fatal("current semantics changed active/original spool")
			}
		})
	}
}

func TestReceiverCurrentRenewedOverExpiredNativeAnchor(t *testing.T) {
	ctx := context.Background()
	setup := time.Now()
	var expires, issued time.Time
	var original ClaimCertificate
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{2, 1}, Initial: func(t *testing.T, v *claimTestVoter, ca claimTestCA) {
		if v.name != "old-0" {
			return
		}
		issued = time.Now()
		expires = issued.Truncate(time.Second).Add(12 * time.Second)
		v.signer = currentShortSigner(t, ca, v, expires)
		if err := os.WriteFile(filepath.Join(v.pki, "host.crt"), []byte(v.signer.certPEM), 0600); err != nil {
			t.Fatal(err)
		}
	}, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
		rows, err := voters[0].c.Query(ctx, `SELECT certificate FROM local_automation_history WHERE sequence=1`)
		if err != nil || len(rows) != 1 {
			t.Fatal(err)
		}
		original, err = sourceCertificate(rows[0].String("certificate"))
		if err != nil {
			t.Fatal(err)
		}
	}, BeforePublish: func(t *testing.T, f *aggregateFixture) {
		v := f.voters[0]
		t.Logf("actual native anchor setupBeforeIssue=%s issueToRenewal=%s remainingNativeBeforeRenewal=%s nativeInterval=12s", issued.Sub(setup), time.Since(issued), time.Until(expires))
		if _, _, err := pki.RenewLocal(f.ca.cert, f.ca.key, v.pki, v.name); err != nil {
			t.Fatal(err)
		}
		signer, err := LoadClaimSigner(v.pki, v.name)
		if err != nil {
			t.Fatal(err)
		}
		all := append(append([]*claimTestVoter(nil), f.voters...), f.local)
		for g := int64(1); g <= 2; g++ {
			cfg, e := GetVoterConfig(ctx, v.c, g)
			if e != nil {
				t.Fatal(e)
			}
			cert, e := sourceCertificate(cfg.Certificate)
			if e != nil {
				t.Fatal(e)
			}
			for i, a := range cert.Accepts {
				if a.Voter == v.name {
					cert.Accepts[i], e = signer.Sign(cert.Key, cert.ConfigGeneration, cert.Ballot, cert.ValueDigest, a.VoterIncarnation)
					if e != nil {
						t.Fatal(e)
					}
				}
			}
			raw, e := cert.Encode()
			if e != nil {
				t.Fatal(e)
			}
			for _, owner := range all {
				if _, e = owner.c.db.Exec(`UPDATE voter_configs SET certificate=? WHERE generation=?`, raw, g); e != nil {
					t.Fatal(e)
				}
			}
		}
		time.Sleep(time.Until(expires) + 25*time.Millisecond)
	}})
	t.Logf("actual native anchor fixtureComplete=%s sinceIssue=%s", time.Since(setup), time.Since(issued))
	verifier, err := LoadClaimVerifier(f.voters[0].pki)
	if err != nil {
		t.Fatal(err)
	}
	one := original
	for _, a := range original.Accepts {
		if a.Voter == "old-0" {
			one.Accepts = []ClaimAccept{a}
			break
		}
	}
	if len(one.Accepts) != 1 {
		t.Fatal("expired original absent")
	}
	if err = verifier.Historical().Verify(one, CertExpectation{Key: one.Key, ConfigGeneration: one.ConfigGeneration, ValueDigest: one.ValueDigest, Electorate: f.attempt.request.Sources, Quorum: 1}); err == nil {
		t.Fatal("standalone expired Historical verification succeeded")
	}
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
	p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	if err != nil {
		t.Fatal("renewed current source over genuine expired native anchors", err)
	}
	if err = f.receiver.consumeCurrent(ctx, p); err != nil {
		t.Fatal(err)
	}
	if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool {
		t.Fatal("current verification rewrote expired originals")
	}
}
