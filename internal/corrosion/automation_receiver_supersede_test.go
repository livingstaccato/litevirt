package corrosion

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type receiverTransferPage struct {
	Request AutomationExportRequest
	Page    AutomationExportPage
}

func receiverPinnedAttempt(t *testing.T, c *Client, id string) string {
	t.Helper()
	var all []byte
	for _, table := range []string{"jobs", "validations", "sources", "components", "records", "pages"} {
		column := "attempt"
		if table == "jobs" {
			column = "id"
		}
		rows, err := c.Query(context.Background(), `SELECT * FROM local_automation_receiver_`+table+` WHERE `+column+`=? ORDER BY rowid`, id)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, raw...)
	}
	return sourceDigest(all)
}

func receiverAllStored(t *testing.T, c *Client) string {
	t.Helper()
	var raw []byte
	for _, table := range []string{"current", "jobs", "validations", "sources", "components", "records", "pages"} {
		rows, e := c.Query(context.Background(), `SELECT * FROM local_automation_receiver_`+table+` ORDER BY rowid`)
		if e != nil {
			t.Fatal(e)
		}
		b, e := json.Marshal(rows)
		if e != nil {
			t.Fatal(e)
		}
		raw = append(raw, b...)
	}
	return sourceDigest(raw)
}
func TestReceiverSupersedeAuthorityAndStorageRefusals(t *testing.T) {
	for _, mode := range []string{"no-current", "equal-revision", "lower-revision", "foreign-CA", "missing-genesis", "forced-transition", "wrong-target", "wrong-incarnation", "foreign-roster", "target-tombstone", "target-endpoint", "next-adopted", "adoption-changed", "reseed", "changed-chosen", "current-oversize", "binding-oversize", "binding-identity", "binding-noncanonical", "binding-job", "binding-context"} {
		t.Run(mode, func(t *testing.T) {
			_, r, q, _, _ := receiverFixture(t)
			ctx := context.Background()
			var a *AutomationReceiverAttempt
			var err error
			if mode != "no-current" {
				a, err = r.Begin(ctx, q.Intent, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			next := q.Intent
			next.Revision++
			switch mode {
			case "equal-revision":
				next.Revision = q.Intent.Revision
			case "lower-revision":
				next.Revision = 0
			case "foreign-CA":
				r.dir = newClaimTestCA(t).pkiDir(t, "b")
			case "missing-genesis":
				_, err = r.client.db.Exec(`DELETE FROM voter_configs WHERE generation=1`)
			case "forced-transition":
				_, err = r.client.db.Exec(`UPDATE voter_configs SET change='force:reseed' WHERE generation=2`)
			case "wrong-target":
				next.Target = "a"
			case "wrong-incarnation":
				_, err = r.client.ReplaceVoterIncarnationForTest(ctx)
			case "foreign-roster":
				next.Sources = []VoterMember{{Name: "foreign", Incarnation: "foreign"}}
			case "target-tombstone":
				_, err = r.client.db.Exec(`UPDATE hosts SET deleted_at='gone' WHERE name='b'`)
			case "target-endpoint":
				_, err = r.client.db.Exec(`UPDATE hosts SET address='127.0.0.2' WHERE name='b'`)
			case "next-adopted":
				err = RecordVoterAdoption(ctx, r.client, 2)
			case "adoption-changed":
				err = RecordVoterAdoption(ctx, r.client, 1)
			case "reseed":
				_, err = r.client.db.Exec(`INSERT INTO reseed_generation(id,generation) VALUES(1,99)`)
			case "changed-chosen":
				_, err = r.client.db.Exec(`UPDATE voter_configs SET created_at='changed' WHERE generation=2`)
			case "current-oversize":
				_, err = r.client.db.Exec(`UPDATE local_automation_receiver_current SET attempt=?`, "x\x00"+strings.Repeat("z", 65))
			case "binding-oversize":
				_, err = r.client.db.Exec(`UPDATE local_automation_receiver_jobs SET binding=? WHERE id=?`, "x\x00"+strings.Repeat("z", maxReceiverBindingBytes), a.id)
			case "binding-identity":
				_, err = r.client.db.Exec(`UPDATE local_automation_receiver_jobs SET binding='{}' WHERE id=?`, a.id)
			case "binding-job":
				_, err = r.client.db.Exec(`UPDATE local_automation_receiver_jobs SET job='different' WHERE id=?`, a.id)
			case "binding-noncanonical", "binding-context":
				binding := append([]byte(nil), a.binding...)
				if mode == "binding-noncanonical" {
					binding = append(binding, ' ')
				} else {
					var v receiverAttemptBinding
					if e := json.Unmarshal(binding, &v); e != nil {
						t.Fatal(e)
					}
					v.Facts.Old = nil
					binding, err = json.Marshal(v)
					if err != nil {
						t.Fatal(err)
					}
				}
				id := sourceDigest([]byte("litevirt/receiver-attempt/v1"), binding)
				if _, err = r.client.db.Exec(`UPDATE local_automation_receiver_jobs SET id=?,binding=? WHERE id=?`, id, binding, a.id); err == nil {
					_, err = r.client.db.Exec(`UPDATE local_automation_receiver_current SET attempt=?`, id)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			active, stored := receiverActive(t, r.client), receiverAllStored(t, r.client)
			fresh := NewAutomationReceiver(r.client, r.dir)
			if _, err = fresh.Supersede(ctx, next); err == nil {
				t.Fatal("invalid replacement authority or retained context accepted")
			}
			if receiverActive(t, r.client) != active || receiverAllStored(t, r.client) != stored {
				t.Fatal("refused replacement mutated ACTIVE or receiver progress")
			}
		})
	}
}
func TestReceiverSupersedeObservedPredecessorCAS(t *testing.T) {
	p, r, q, peer, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := p.ExportAutomationSource(peer, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Stage(ctx, a, "a", q, first); err != nil {
		t.Fatal(err)
	}
	pins := receiverPinnedAttempt(t, r.client, a.id)
	active := receiverActive(t, r.client)
	fresh := NewAutomationReceiver(r.client, r.dir)
	intent := q.Intent
	intent.Revision += 2
	var stored string
	var competing *AutomationReceiverAttempt
	fresh.afterCurrentObservation = func() {
		next := q.Intent
		next.Revision++
		competing, err = r.Begin(ctx, next, a)
		if err != nil {
			t.Fatal("actual competing current selection", err)
		}
		stored = receiverAllStored(t, r.client)
	}
	if _, err = fresh.Supersede(ctx, intent); err == nil || !strings.Contains(err.Error(), "observed predecessor changed") {
		t.Fatal("observed predecessor race did not refuse exact CAS", err)
	}
	if competing == nil || stored != receiverAllStored(t, r.client) || pins != receiverPinnedAttempt(t, r.client, a.id) || active != receiverActive(t, r.client) {
		t.Fatal("losing CAS altered current selection, pins or ACTIVE")
	}
	fresh.afterCurrentObservation = nil
	b, err := fresh.Supersede(ctx, intent)
	if err != nil {
		t.Fatal("fresh observation after real CAS race", err)
	}
	if b.id == competing.id {
		t.Fatal("replacement not distinct")
	}
	if _, err = r.Begin(ctx, q.Intent, a); err == nil {
		t.Fatal("old private authority revived after owner replacement")
	}
	if _, err = r.Stage(ctx, a, "a", q, first); err == nil {
		t.Fatal("superseded old private handle accepted an exact retained page")
	}
}
func receiverProcessValue(t *testing.T, dir, name string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func receiverReadProcessValue(t *testing.T, dir, name string, value any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, value); err != nil {
		t.Fatal(err)
	}
}

// The first child owns the only old private attempt, persists a real page and
// exits. A later fresh executable must replace after genuine re-attestation;
// no old process handle is available in either parent or replacement child.
func TestReceiverRestartSupersedeAfterReattestation(t *testing.T) {
	p, r, q, peer, dir := receiverFixtureSeed(t, func(v *claimTestVoter) {
		for _, name := range []string{"restart-splice-one", "restart-splice-two"} {
			key := workloadKey()
			key.TargetName = name
			reply, e := v.c.ClaimPrepare(context.Background(), key, testBallot(11, "a"), 1)
			if e != nil || !reply.Promised {
				t.Fatal("genuine multi-record source promise", e)
			}
		}
	})
	ctx := context.Background()
	page, err := p.ExportAutomationSource(peer, q)
	if err != nil {
		t.Fatal(err)
	}
	receiverProcessValue(t, dir, "supersede-old", receiverTransferPage{q, page})
	oldContentRequest := q
	oldContentRequest.Component = 3
	oldContent, err := p.ExportAutomationSource(peer, oldContentRequest)
	if err != nil {
		t.Fatal(err)
	}
	if len(oldContent.Records) == 0 || oldContent.Cursor == "" {
		t.Fatal("old genuine content must include signed continuation")
	}
	receiverProcessValue(t, dir, "supersede-old-content", receiverTransferPage{oldContentRequest, oldContent})
	child := func(mode string) {
		t.Helper()
		binary := os.Args[0]
		if mode == "initial" && os.Getenv("RECEIVER_PREMERGE_BINARY") != "" {
			binary = os.Getenv("RECEIVER_PREMERGE_BINARY")
		}
		cmd := exec.Command(binary, "-test.run=^TestReceiverRestartSupersedeProcess$", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "RECEIVER_SUPERSEDE_DIR="+dir, "RECEIVER_SUPERSEDE_PKI="+r.dir, "RECEIVER_SUPERSEDE_MODE="+mode)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("actual fresh process %s: %v\n%s", mode, err, out)
		}
		if cmd.ProcessState == nil || !cmd.ProcessState.Success() {
			t.Fatal("child not terminal")
		}
		t.Logf("actual receiver child %d %s binary=%s exited successfully", cmd.ProcessState.Pid(), mode, binary)
	}
	child("initial")
	child("retry-old")
	var oldID string
	receiverReadProcessValue(t, dir, "supersede-old-id", &oldID)
	if len(oldID) != 64 {
		t.Fatal("initial process did not persist an actual attempt")
	}
	receiverProcessValue(t, dir, "supersede-old-pins", receiverPinnedAttempt(t, r.client, oldID))
	receiverRenewMembership(t, p, r)
	q.Intent.Revision++
	candidate, err := p.Prepare(ctx, q.Intent)
	if err != nil {
		t.Fatal(err)
	}
	q.Publication, err = p.Publish(ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	var pages []receiverTransferPage
	for component := uint32(0); component < 12; component++ {
		q.Component = component
		q.Cursor = ""
		for {
			page, err = p.ExportAutomationSource(peer, q)
			if err != nil {
				t.Fatal(err)
			}
			pages = append(pages, receiverTransferPage{q, page})
			if page.Terminal {
				break
			}
			q.Cursor = page.Cursor
		}
	}
	receiverProcessValue(t, dir, "supersede-new-pages", pages)
	receiverProcessValue(t, dir, "supersede-active", receiverActive(t, r.client))
	child("replace")
	child("resume")
	var newID string
	receiverReadProcessValue(t, dir, "supersede-new-id", &newID)
	if newID == oldID || len(newID) != 64 {
		t.Fatal("replacement did not preserve distinct attempt identity")
	}
	t.Log("ordinary renewal and exact chosen-value re-attestation replaced a retained current attempt across actual private-handle process loss; all12 new components retained")
}
func TestReceiverRestartSupersedeProcess(t *testing.T) {
	dir := os.Getenv("RECEIVER_SUPERSEDE_DIR")
	if dir == "" {
		t.Skip("subprocess helper exercised by TestReceiverRestartSupersedeAfterReattestation")
	}
	ctx := context.Background()
	c, err := NewLocalClient(dir, "b")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	r := NewAutomationReceiver(c, os.Getenv("RECEIVER_SUPERSEDE_PKI"))
	var old receiverTransferPage
	receiverReadProcessValue(t, dir, "supersede-old", &old)
	if os.Getenv("RECEIVER_SUPERSEDE_MODE") == "initial" {
		a, e := r.Begin(ctx, old.Request.Intent, nil)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = r.Stage(ctx, a, "a", old.Request, old.Page); e != nil {
			t.Fatal(e)
		}
		receiverProcessValue(t, dir, "supersede-old-id", a.id)
		return
	}
	if os.Getenv("RECEIVER_SUPERSEDE_MODE") == "retry-old" {
		before := receiverAllStored(t, c)
		a, e := r.Begin(ctx, old.Request.Intent, nil)
		if e != nil {
			t.Fatal("premerge persisted binding exact retry", e)
		}
		if _, e = r.Stage(ctx, a, "a", old.Request, old.Page); e != nil {
			t.Fatal("premerge persisted page exact retry", e)
		}
		if before != receiverAllStored(t, c) {
			t.Fatal("exact old retry changed retained evidence")
		}
		return
	}
	var oldID, pins, active string
	var pages []receiverTransferPage
	receiverReadProcessValue(t, dir, "supersede-old-id", &oldID)
	receiverReadProcessValue(t, dir, "supersede-old-pins", &pins)
	receiverReadProcessValue(t, dir, "supersede-active", &active)
	receiverReadProcessValue(t, dir, "supersede-new-pages", &pages)
	if len(pages) < 12 {
		t.Fatal("genuine new transfer omitted components")
	}
	if _, err = r.Begin(ctx, old.Request.Intent, nil); err == nil {
		t.Fatal("old immutable attempt rebound to renewed certificate bytes")
	}
	var a *AutomationReceiverAttempt
	if os.Getenv("RECEIVER_SUPERSEDE_MODE") == "replace" {
		if _, err = r.Begin(ctx, pages[0].Request.Intent, nil); err == nil {
			t.Fatal("plain higher revision selected without explicit owner supersession")
		}
		a, err = r.Supersede(ctx, pages[0].Request.Intent)
		if err != nil {
			t.Fatal("fresh verified replacement stranded after re-attestation", err)
		}
		if a.id == oldID {
			t.Fatal("replacement reused old immutable binding")
		}
		receiverProcessValue(t, dir, "supersede-new-id", a.id)
		if _, err = r.Stage(ctx, a, "a", old.Request, old.Page); err == nil {
			t.Fatal("old revision spliced into new receiver attempt")
		}
		for _, page := range pages {
			if _, err = r.Stage(ctx, a, "a", page.Request, page.Page); err != nil {
				t.Fatal("fresh replacement genuine transfer", err)
			}
		}
		var oldContent receiverTransferPage
		receiverReadProcessValue(t, dir, "supersede-old-content", &oldContent)
		for _, relabel := range []bool{false, true} {
			splice := oldContent.Request
			stale := oldContent.Page
			splice.Intent = pages[0].Request.Intent
			if relabel {
				splice.Publication = pages[0].Request.Publication
				stale.Publication = splice.Publication
			}
			normalized, e := sourceExportRequest(splice)
			if e != nil {
				t.Fatal(e)
			}
			if e = receiverPageBounds(normalized, stale); e != nil {
				t.Fatal("genuine old content splice invalid at wrapper shape", e)
			}
			before := receiverStored(t, c)
			if _, e = r.Stage(ctx, a, "a", splice, stale); e == nil {
				t.Fatal("genuine old content/continuation rebound to new revision", relabel)
			}
			if receiverStored(t, c) != before {
				t.Fatal("content splice changed retained progress")
			}
		}
	} else {
		a, err = r.Begin(ctx, pages[0].Request.Intent, nil)
		if err != nil {
			t.Fatal("unchanged-context fresh process resume", err)
		}
		var id string
		receiverReadProcessValue(t, dir, "supersede-new-id", &id)
		if a.id != id {
			t.Fatal("exact restart changed current identity")
		}
		before := receiverStored(t, c)
		if _, err = r.Stage(ctx, a, "a", pages[0].Request, pages[0].Page); err != nil {
			t.Fatal(err)
		}
		if receiverStored(t, c) != before {
			t.Fatal("exact restart retry changed retained pages")
		}
	}
	if _, err = r.Stage(ctx, &AutomationReceiverAttempt{id: oldID}, "a", old.Request, old.Page); err == nil {
		t.Fatal("stored predecessor identity revived private authority")
	}
	if receiverPinnedAttempt(t, c, oldID) != pins || receiverActive(t, c) != active {
		t.Fatal("replacement/restart changed prior pins or active state")
	}
}

func TestReceiverSupersedeObservedBindingCAS(t *testing.T) {
	_, r, q, _, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	fresh := NewAutomationReceiver(r.client, r.dir)
	next := q.Intent
	next.Revision++
	var stored string
	active := receiverActive(t, r.client)
	fresh.afterCurrentObservation = func() {
		if _, e := r.client.db.Exec(`UPDATE local_automation_receiver_jobs SET binding='{}' WHERE id=?`, a.id); e != nil {
			t.Fatal(e)
		}
		stored = receiverAllStored(t, r.client)
	}
	if _, err = fresh.Supersede(ctx, next); err == nil || !strings.Contains(err.Error(), "observed predecessor changed") {
		t.Fatal("binding changed under same current row escaped CAS", err)
	}
	if stored != receiverAllStored(t, r.client) || active != receiverActive(t, r.client) {
		t.Fatal("binding-race refusal mutated evidence or ACTIVE")
	}
}
