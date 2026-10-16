package corrosion

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

func TestReceiverBothFullClaimTables(t *testing.T) {
	p, r, q, exportCtx, _ := receiverFixtureSeed(t, func(a *claimTestVoter) {
		for _, scoped := range []bool{false, true} {
			key := workloadKey()
			key.TargetName = fmt.Sprintf("claim-%t", scoped)
			if scoped {
				key.Incarnation = "workload-lifetime"
			}
			value := workloadValue(strings.Repeat("full-accepted-payload", 1000), "a", "ghost")
			value.Proof.TargetName = key.TargetName
			accepted, err := a.c.ClaimAccept(context.Background(), key, testBallot(2, "a"), value, 1, a.signer, unreachable)
			if err != nil || !accepted.Accepted {
				t.Fatal("actual full acceptance", err)
			}
			if reply, err := a.c.ClaimPrepare(context.Background(), key, testBallot(9, "a"), 1); err != nil || !reply.Promised {
				t.Fatal("independent promise", err)
			}
			for i := 0; i < 80; i++ {
				k := key
				k.TargetName = fmt.Sprintf("promise-%t-%03d", scoped, i)
				reply, err := a.c.ClaimPrepare(context.Background(), k, testBallot(11, "a"), 1)
				if err != nil || !reply.Promised {
					t.Fatal("actual promise-only", err)
				}
			}
		}
	})
	active := receiverActive(t, r.client)
	a, err := r.Begin(context.Background(), q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, exportCtx, 11)
	rows, err := p.client.Query(context.Background(), `SELECT id FROM local_automation_cuts WHERE generation=1`)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	cut := rows[0].String("id")
	for section := 0; section < 2; section++ {
		original, err := p.client.Query(context.Background(), `SELECT ordinal,record FROM local_automation_cut_records WHERE cut_id=? AND section=? ORDER BY ordinal`, cut, section)
		if err != nil || len(original) < 81 {
			t.Fatal("full accepted and promise-only fixture missing", err)
		}
		stored, err := r.client.Query(context.Background(), `SELECT ordinal,record FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=? ORDER BY ordinal`, a.id, section+3)
		if err != nil || len(stored) != len(original) {
			t.Fatal("lost full generation-scoped inventory", err)
		}
		for i := range original {
			if !bytes.Equal(original[i].Bytes("record"), stored[i].Bytes("record")) {
				t.Fatal("accepted/promise-only bytes changed")
			}
		}
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("full payload staging mutated active state")
	}
}
func TestReceiverMultipartPublication(t *testing.T) {
	p, r, q, exportCtx, _ := receiverFixture(t)
	ctx := context.Background()
	serials := make([]string, 50000)
	for i := range serials {
		serials[i] = fmt.Sprintf("f000%08x", i)
	}
	if err := pki.GenerateCRL(filepath.Join(p.dir, "ca.crt"), filepath.Join(p.dir, "ca.key"), filepath.Join(p.dir, "crl.pem"), serials); err != nil {
		t.Fatal(err)
	}
	q.Intent.Revision++
	candidate, err := p.Prepare(ctx, q.Intent)
	if err != nil {
		t.Fatal(err)
	}
	q.Publication, err = p.Publish(ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	active := receiverActive(t, r.client)
	chunks := 0
	for component := uint32(0); component < 3; component++ {
		q.Component = component
		q.Cursor = ""
		for {
			page, err := p.ExportAutomationSource(exportCtx, q)
			if err != nil {
				t.Fatal(err)
			}
			progress, err := r.Stage(ctx, a, "a", q, page)
			if err != nil {
				t.Fatal(err)
			}
			if component == 1 {
				chunks++
				if progress.Authenticated {
					t.Fatal("partial multipart metadata authenticated")
				}
			}
			if component == 2 && page.Terminal && !progress.Authenticated {
				t.Fatal("full multipart signed publication not authenticated")
			}
			if page.Terminal {
				break
			}
			q.Cursor = page.Cursor
		}
	}
	if chunks < 2 {
		t.Fatal("fixture did not exercise multiple bounded chunks")
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("multipart metadata changed active state")
	}
	t.Logf("genuine signed source public trust artifact traversed %d bounded chunks before full publication authentication", chunks)
}

// Adversarial, current-source-signed CURSORS around an invalid multipart
// artifact. This is deliberately NOT a successful fabricated publication. It
// proves two-chunk pending artifact storage remains inert until full auth.
func TestReceiverTwoChunkPendingArtifactRefusesPromotion(t *testing.T) {
	p, r, q, exportCtx, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := bytes.Repeat([]byte{'x'}, AutomationExportChunkBytes+1)
	sum := sha256.Sum256(raw)
	cursor := sourceExportCursor{Binding: sourceExportBinding(q), Position: 1, Bytes: AutomationExportChunkBytes, TotalRecords: 2, TotalBytes: int64(len(raw)), Digest: sum}
	hash := sha256.New()
	hash.Write(raw[:AutomationExportChunkBytes])
	if err = cursor.setHash(hash); err != nil {
		t.Fatal(err)
	}
	pair, err := pki.ServedHostKeyPair(p.dir)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cursor.encode(pair.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	first := AutomationExportPage{Publication: q.Publication, Component: 0, Chunk: raw[:AutomationExportChunkBytes], Cursor: signed, TerminalRecords: 2, TerminalBytes: int64(len(raw)), TerminalDigest: hex.EncodeToString(sum[:])}
	active := receiverActive(t, r.client)
	progress, err := r.Stage(ctx, a, "a", q, first)
	if err != nil || progress.Authenticated || progress.Terminal {
		t.Fatal("first inert artifact chunk", err)
	}
	q.Cursor = signed
	second := first
	second.Chunk = raw[AutomationExportChunkBytes:]
	second.Cursor = ""
	second.Terminal = true
	progress, err = r.Stage(ctx, a, "a", q, second)
	if err != nil || progress.Authenticated || !progress.Terminal {
		t.Fatal("second artifact chunk acquired authentication", err)
	}
	q.Cursor = ""
	for component := uint32(1); component < 3; component++ {
		q.Component = component
		page, err := p.ExportAutomationSource(exportCtx, q)
		if err != nil {
			t.Fatal(err)
		}
		before := receiverStored(t, r.client)
		_, err = r.Stage(ctx, a, "a", q, page)
		if component == 1 {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			if err == nil {
				t.Fatal("invalid two-chunk artifact promoted")
			}
			if before != receiverStored(t, r.client) {
				t.Fatal("failed multipart promotion advanced progress")
			}
		}
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("pending artifact affected active state")
	}
}
func TestReceiverAuthenticatedEmptyInventory(t *testing.T) {
	p, r, q, exportCtx, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, exportCtx, 3)
	before := receiverStored(t, r.client)
	active := receiverActive(t, r.client)
	q.Component = 5
	later, err := p.ExportAutomationSource(exportCtx, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Stage(ctx, a, "a", q, later); err == nil {
		t.Fatal("omitted empty section treated as authenticated inventory")
	}
	q.Component = 4
	empty, err := p.ExportAutomationSource(exportCtx, q)
	if err != nil || !empty.Terminal || empty.TerminalRecords != 0 || empty.TerminalBytes != 0 || len(empty.Records) != 0 {
		t.Fatal("fixture lacks authenticated empty section", err)
	}
	eof := empty
	eof.Terminal = false
	eof.Cursor = "interrupted"
	if _, err = r.Stage(ctx, a, "a", q, eof); err == nil {
		t.Fatal("header plus nonterminal EOF accepted")
	}
	if receiverStored(t, r.client) != before {
		t.Fatal("missing empty inventory made progress")
	}
	progress, err := r.Stage(ctx, a, "a", q, empty)
	if err != nil || !progress.Terminal || progress.Records != 0 || !progress.Authenticated {
		t.Fatal("authenticated empty inventory refused", err)
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("empty inventory affected active state")
	}
}
