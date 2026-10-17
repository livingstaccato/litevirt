package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"strings"
	"testing"
)

func receiverAuditClaimSeed(t *testing.T, a *claimTestVoter, _ []*claimTestVoter, record AutomationRecord) {
	t.Helper()
	d, err := automationDecision(record.Value)
	if err != nil {
		t.Fatal(err)
	}
	if d.Sequence != 2 {
		return
	}
	ctx := context.Background()
	loser := sharedAutomationRecord(t, 2, d.ParentDigest, "loser-request", "loser-operation", a)
	key, _ := AutomationClaimKey(2)
	accepted, err := a.c.ClaimAccept(ctx, key, testBallot(1, "a"), loser.Value, 1, a.signer, nil)
	if err != nil || !accepted.Accepted {
		t.Fatal("genuine prior losing automation acceptance", accepted, err)
	}
	for _, scoped := range []bool{false, true} {
		k := workloadKey()
		k.TargetName = fmt.Sprintf("retained-%t", scoped)
		if scoped {
			k.Incarnation = "workload-lifetime"
		}
		value := workloadValue(strings.Repeat("full-accepted-payload", 1000), "a", "ghost")
		value.Proof.TargetName = k.TargetName
		accepted, err = a.c.ClaimAccept(ctx, k, testBallot(2, "a"), value, 1, a.signer, unreachable)
		if err != nil || !accepted.Accepted {
			t.Fatal("genuine full legacy acceptance", err)
		}
		if reply, err := a.c.ClaimPrepare(ctx, k, testBallot(9, "a"), 1); err != nil || !reply.Promised {
			t.Fatal("independent retained promise", err)
		}
		for i := 0; i < 80; i++ {
			promise := k
			promise.TargetName = fmt.Sprintf("promise-%t-%03d", scoped, i)
			if reply, err := a.c.ClaimPrepare(ctx, promise, testBallot(11, "a"), 1); err != nil || !reply.Promised {
				t.Fatal("real promise-only", err)
			}
		}
	}
}
func TestReceiverSourceAuditBothClaimsAndLosingAcceptance(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixtureOptions(t, 3, receiverAuditOptions{beforeApply: func(a *claimTestVoter, v []*claimTestVoter, record AutomationRecord) {
		receiverAuditClaimSeed(t, a, v, record)
	}})
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	q.MaxRecords = 7
	receiverThrough(t, p, r, a, q, peer, 11)
	active := receiverActive(t, r.client)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal("genuine losing/full/promise-only source refused", err)
	}
	for _, component := range []int{3, 4} {
		rows, err := r.client.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_receiver_refs WHERE component=?`, component)
		if err != nil || len(rows) != 1 || rows[0].Int64("n") < 81 {
			t.Fatal("complete claims references missing", component, err)
		}
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("retained claims audit activated claims")
	}
}

func TestReceiverSourceAuditDifferentValidCertificateMetadata(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixture(t, 3, nil)
	receiverAuditChangeCut(t, p, &q, 3, func(rows []Row) []Row {
		cert, err := sourceCertificate(rows[0].String("certificate"))
		if err != nil {
			t.Fatal(err)
		}
		cert.Accepts[0], cert.Accepts[2] = cert.Accepts[2], cert.Accepts[0]
		raw, err := cert.Encode()
		if err != nil {
			t.Fatal(err)
		}
		receiverAuditSet(t, &rows[0], "certificate", raw)
		return rows
	})
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	active := receiverActive(t, r.client)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal("same stable value with independently valid original certificate metadata treated as fork", err)
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("certificate metadata audit changed active state")
	}
}

func TestReceiverSourceAuditOlderLegacySignedDomain(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixtureOptions(t, 0, receiverAuditOptions{legacy: true})
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	active := receiverActive(t, r.client)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal("authentic older legacy signed domain refused", err)
	}
	rows, err := r.client.Query(ctx, `SELECT ordinal,record FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=3 ORDER BY ordinal`, a.id)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		fact, err := decodeSourceCutRow(0, row.Int64("ordinal"), row.Bytes("record"))
		if err != nil {
			t.Fatal(err)
		}
		if fact.String("target_kind") == ClaimKindVM {
			state, err := scanClaimRow(workloadKey(), fact)
			if err != nil || state.Accept == nil || state.ConfigGeneration != 2 || state.Accept.ConfigGeneration != 1 {
				t.Fatal("original generation lost", err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("older legacy acceptance absent")
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("legacy audit changed active state")
	}
}

func TestReceiverSourceAuditSignedClaimParentAndCoverage(t *testing.T) {
	for _, mode := range []string{"parent", "uid", "frontier", "unsupported", "secret-coverage"} {
		t.Run(mode, func(t *testing.T) {
			var signer *claimTestVoter
			p, r, q, peer, _ := receiverAuditFixtureOptions(t, 3, receiverAuditOptions{beforeApply: func(a *claimTestVoter, v []*claimTestVoter, record AutomationRecord) {
				signer = a
				receiverAuditClaimSeed(t, a, v, record)
			}})
			receiverAuditChangeCut(t, p, &q, 0, func(rows []Row) []Row {
				for i := range rows {
					row := &rows[i]
					if row.String("target_kind") != ClaimKindAutomation {
						continue
					}
					key, _ := AutomationClaimKey(uint64(row.Int64("owner_epoch")))
					state, err := scanClaimRow(key, *row)
					if err != nil {
						t.Fatal(err)
					}
					decision, err := automationDecision(*state.Value)
					if err != nil {
						t.Fatal(err)
					}
					switch mode {
					case "parent":
						decision.ParentDigest = strings.Repeat("0", 64)
					case "uid":
						decision.Command.ClusterUID = "foreign-cluster"
					case "frontier":
						decision.Sequence = 99
						key, _ = AutomationClaimKey(99)
						receiverAuditSet(t, row, "owner_epoch", int64(99))
					case "unsupported":
						decision.Command.Kind = "rewrap_payload"
					case "secret-coverage":
						decision.Command.Ciphertext = []byte{1, 2, 3}
						decision.Command.SecretIntentTag = []byte{4}
						decision.Command.SecretKeyEpoch = "unsupported-epoch"
					}
					// Preserve structurally valid signed encoding, including a genuinely signed
					// but unsupported command. The semantic owner must make the refusal.
					envelope, err := contract.EncodeDecision(decision)
					if err != nil {
						t.Fatal(err)
					}
					value := ClaimValue{Automation: &AutomationClaimValue{Envelope: envelope}}
					digest, err := value.Digest()
					if err != nil {
						t.Fatal("signed corruption fixture shape", err)
					}
					accept, err := signer.signer.Sign(key, 1, state.Accepted, digest, signer.inc)
					if err != nil {
						t.Fatal(err)
					}
					raw, _ := json.Marshal(value)
					receiverAuditSet(t, row, "value_json", string(raw))
					receiverAuditSet(t, row, "value_digest", digest)
					raw, _ = json.Marshal(accept)
					receiverAuditSet(t, row, "accept_json", string(raw))
					return rows
				}
				t.Fatal("genuine loser missing")
				return nil
			})
			receiverAuditSemanticRefusal(t, p, r, q, peer, "")
		})
	}
}
