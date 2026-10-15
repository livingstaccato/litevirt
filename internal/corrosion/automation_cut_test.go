package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

// Removing full promise/accept copying or refusing a properly sealed source
// must fail this test, which exercises real storage-owned voter state.
func TestAutomationCutPreservesClaims(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	key, value := automationFixture(t, 1, "")
	installAutomationEvidence(t, a.c, key, "", 1)
	if r, err := a.c.ClaimAccept(ctx, key, testBallot(2, "a"), value, 1, a.signer, nil); err != nil || !r.Accepted {
		t.Fatal(r, err)
	}
	if r, err := a.c.ClaimPrepare(ctx, key, testBallot(8, "a"), 1); err != nil || !r.Promised {
		t.Fatal(r, err)
	}
	promise := workloadKey().WithIncarnation("old-workload")
	if r, err := a.c.ClaimPrepare(ctx, promise, testBallot(11, "a"), 1); err != nil || !r.Promised {
		t.Fatal(r, err)
	}
	if err := a.c.SealVoterGeneration(ctx, 1, "test source freeze"); err != nil {
		t.Fatal(err)
	}
	id, err := a.c.FreezeAutomationCut(ctx, 1, nil)
	if err != nil || id == "" {
		t.Fatalf("sealed source with complete accepted genesis and promise-only key could not freeze: %v", err)
	}

	m, records := cutFixtureRead(t, a.c, id)
	counts := []int64{1, 1, 0, 0, 0, 1, 1, 1, 1}
	for i, inv := range m.Inventory {
		if inv.Records != counts[i] {
			t.Fatalf("section %s count=%d want=%d", inv.Section, inv.Records, counts[i])
		}
	}
	fields := cutFixtureFields(t, records[0][0])
	raw, _ := json.Marshal(value)
	if string(fields[12][1:]) != string(raw) || int64(binary.BigEndian.Uint64(fields[6][1:])) != 8 || int64(binary.BigEndian.Uint64(fields[9][1:])) != 2 {
		t.Fatal("full accepted bytes or independent promise lost")
	}
	fields = cutFixtureFields(t, records[1][0])
	if int64(binary.BigEndian.Uint64(fields[7][1:])) != 11 || len(fields[13]) != 1 {
		t.Fatal("promise-only incarnation key lost")
	}
}

// Each corrupt/incomplete representation must be refused, never silently frozen.
func TestAutomationCutStandingAndIntegrity(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"unsealed", "past-old", "changed-incarnation", "normal", "record-bit", "metadata-bit", "missing-record", "invalid-ordinal", "negative-ordinal"} {
		t.Run(mode, func(t *testing.T) {
			_, a, _, _ := threeVoters(t)
			if r, err := a.c.ClaimPrepare(ctx, workloadKey(), testBallot(9, "a"), 1); err != nil || !r.Promised {
				t.Fatal(r, err)
			}
			if mode == "unsealed" {
				if _, err := a.c.FreezeAutomationCut(ctx, 1, nil); err == nil {
					t.Fatal("unsealed source frozen")
				}
				return
			}
			if err := a.c.SealVoterGeneration(ctx, 1, "test"); err != nil {
				t.Fatal(err)
			}
			if mode == "past-old" {
				adoptHandBuilt(t, 2, []VoterMember{{Name: "a", Incarnation: a.inc}, {Name: "b", Incarnation: "b"}, {Name: "c", Incarnation: "c"}}, a)
				if _, err := a.c.FreezeAutomationCut(ctx, 1, nil); err == nil {
					t.Fatal("current successor relabeled old")
				}
				return
			}
			id, err := a.c.FreezeAutomationCut(ctx, 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "record-bit":
				_, err = a.c.db.Exec(`UPDATE local_automation_cut_records SET record=x'01' WHERE cut_id=? AND section=0`, id)
			case "metadata-bit":
				_, err = a.c.db.Exec(`UPDATE local_automation_cuts SET root='corrupt' WHERE id=?`, id)
			case "missing-record":
				_, err = a.c.db.Exec(`DELETE FROM local_automation_cut_records WHERE cut_id=? AND section=0`, id)
			case "invalid-ordinal":
				_, err = a.c.db.Exec(`INSERT INTO local_automation_cut_records(cut_id,section,ordinal,record) VALUES(?,0,0,x'01')`, id)
			case "negative-ordinal":
				_, err = a.c.db.Exec(`INSERT INTO local_automation_cut_records(cut_id,section,ordinal,record) VALUES(?,0,-1,x'01')`, id)
			case "changed-incarnation":
				_, err = a.c.db.Exec(`UPDATE local_voter_incarnation SET incarnation='reimaged' WHERE id=1`)
			case "normal":
				_, err = a.c.db.Exec(`UPDATE local_recovery_claims SET promised_round=99 WHERE target_kind='vm'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			again, err := a.c.FreezeAutomationCut(ctx, 1, nil)
			if mode == "normal" {
				if err != nil || again != id {
					t.Fatal("immutable repeat changed", again, err)
				}
			} else if err == nil {
				t.Fatal("corrupt or reimaged cut reused")
			}
		})
	}
}

// Independent frame reader: no production encoder computes its own expectation.
func cutFixtureFields(t *testing.T, b []byte) [][]byte {
	t.Helper()
	if len(b) < 6 || string(b[:6]) != "LVCUT\x01" {
		t.Fatal("wrong frame header")
	}
	b = b[6:]
	var fields [][]byte
	for len(b) > 0 {
		if len(b) < 4 {
			t.Fatal("short frame")
		}
		n := int(binary.BigEndian.Uint32(b))
		b = b[4:]
		if n > len(b) {
			t.Fatal("short field")
		}
		fields = append(fields, b[:n])
		b = b[n:]
	}
	return fields
}
func cutFixtureRead(t *testing.T, c *Client, id string) (automationCutMetadata, [][][]byte) {
	t.Helper()
	ctx := context.Background()
	rows, err := c.Query(ctx, `SELECT id,metadata,root FROM local_automation_cuts WHERE id=?`, id)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	var m automationCutMetadata
	raw := rows[0].Bytes("metadata")
	if json.Unmarshal(raw, &m) != nil {
		t.Fatal("invalid metadata")
	}
	var frame bytes.Buffer
	frame.WriteString("LVCUT\x01")
	for _, p := range [][]byte{[]byte("content-inventory/v1"), raw} {
		binary.Write(&frame, binary.BigEndian, uint32(len(p)))
		frame.Write(p)
	}
	root := sha256.Sum256(frame.Bytes())
	if rows[0].String("root") != hex.EncodeToString(root[:]) {
		t.Fatal("terminal root mismatch")
	}
	all := make([][][]byte, len(m.Inventory))
	for i, inv := range m.Inventory {
		rows, err = c.Query(ctx, `SELECT ordinal,record FROM local_automation_cut_records WHERE cut_id=? AND section=? ORDER BY ordinal`, id, i)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		var prefix bytes.Buffer
		prefix.WriteString("LVCUT\x01")
		for _, p := range [][]byte{[]byte("section/v1"), []byte(inv.Section)} {
			binary.Write(&prefix, binary.BigEndian, uint32(len(p)))
			prefix.Write(p)
		}
		hash.Write(prefix.Bytes())
		var total int64
		for j, row := range rows {
			if row.Int64("ordinal") != int64(j+1) {
				t.Fatal("ordinal gap")
			}
			b := row.Bytes("record")
			hash.Write(b)
			total += int64(len(b))
			all[i] = append(all[i], b)
		}
		if inv.Records != int64(len(rows)) || inv.Bytes != total || inv.Digest != hex.EncodeToString(hash.Sum(nil)) {
			t.Fatal("count/bytes/digest mismatch", inv.Section)
		}
	}
	return m, all
}

func TestAutomationCutAtomicAndReopen(t *testing.T) {
	ctx := context.Background()
	ca := newClaimTestCA(t)
	dir := t.TempDir()
	c, err := NewLocalClient(dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	if err = InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.SetVoterConfigGate(func() bool { return true })
	inc, err := c.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := LoadClaimSigner(ca.pkiDir(t, "a"), "a")
	if err != nil {
		t.Fatal(err)
	}
	a := &claimTestVoter{name: "a", c: c, inc: inc, signer: signer}
	members := []VoterMember{{Name: "a", Incarnation: inc}, {Name: "b", Incarnation: "b"}, {Name: "c", Incarnation: "c"}}
	adoptHandBuilt(t, 1, members, a)
	key, value := automationFixture(t, 1, "")
	installAutomationEvidence(t, c, key, "", 1)
	if r, err := c.ClaimAccept(ctx, key, testBallot(2, "a"), value, 1, signer, nil); err != nil || !r.Accepted {
		t.Fatal(r, err)
	}
	if err = c.SealVoterGeneration(ctx, 1, "test"); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"rollback", "record-write", "normal"} {
		c.automationSeams = nil
		if mode == "rollback" {
			c.automationSeams = &localCommitSeams{beforeCommit: func(*sql.Tx) error { return errors.New("injected rollback") }}
		}
		if mode == "record-write" {
			if _, err = c.db.Exec(`CREATE TRIGGER cut_failure BEFORE INSERT ON local_automation_cut_records WHEN NEW.section=6 BEGIN SELECT RAISE(ABORT,'injected disk failure'); END`); err != nil {
				t.Fatal(err)
			}
		}
		id, err := c.FreezeAutomationCut(ctx, 1, nil)
		if mode != "normal" {
			if err == nil || id != "" {
				t.Fatal("failed cut returned success")
			}
			for _, table := range []string{"local_automation_cuts", "local_automation_cut_records"} {
				rows, e := c.Query(ctx, "SELECT count(*) AS n FROM "+table)
				if e != nil || rows[0].Int64("n") != 0 {
					t.Fatal("partial cut survived", table, e)
				}
			}
			if mode == "record-write" {
				if _, err = c.db.Exec(`DROP TRIGGER cut_failure`); err != nil {
					t.Fatal(err)
				}
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		before, records := cutFixtureRead(t, c, id)
		adoptHandBuilt(t, 2, members, a)
		if _, err = c.db.Exec(`UPDATE local_recovery_claims SET promised_round=100,config_generation=2,accept_json='' WHERE target_kind='automation'`); err != nil {
			t.Fatal(err)
		}
		if err = c.Close(); err != nil {
			t.Fatal(err)
		}
		c, err = NewLocalClient(dir, "a")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		again, err := c.FreezeAutomationCut(ctx, 1, nil)
		if err != nil || again != id {
			t.Fatal("archived old cut unavailable", err)
		}
		after, later := cutFixtureRead(t, c, id)
		if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, later) {
			t.Fatal("cut changed after adoption/write/reopen")
		}
	}
}

func TestAutomationCutStorageBounds(t *testing.T) {
	// Exact framing ceiling, not a claim about a future complete protobuf page.
	row := Row{Values: []interface{}{strings.Repeat("x", maxAutomationCutRecordBytes-28)}}
	b, err := encodeAutomationCutRecord("x", 1, row)
	if err != nil || len(b) != maxAutomationCutRecordBytes {
		t.Fatal("maximum framed record", len(b), err)
	}
	row.Values[0] = strings.Repeat("x", maxAutomationCutRecordBytes-27)
	if _, err = encodeAutomationCutRecord("x", 1, row); err == nil {
		t.Fatal("overbound record accepted")
	}
	inv := automationCutInventory{Records: math.MaxInt64}
	if addAutomationCutSize(&inv, 1) == nil {
		t.Fatal("count overflow")
	}
	inv = automationCutInventory{Bytes: math.MaxInt64}
	if addAutomationCutSize(&inv, 1) == nil {
		t.Fatal("byte overflow")
	}
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	if err = a.c.SealVoterGeneration(ctx, 1, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err = a.c.db.Exec(`UPDATE local_voter_seals SET reason=?`, strings.Repeat("x", maxAutomationCutRecordBytes+1)); err != nil {
		t.Fatal(err)
	}
	if _, err = a.c.FreezeAutomationCut(ctx, 1, nil); err == nil {
		t.Fatal("oversized source row published")
	}
}

func TestAutomationCutRequiresActualFull(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	if err := a.c.SealVoterGeneration(ctx, 1, "test"); err != nil {
		t.Fatal(err)
	}
	a.c.db.SetMaxOpenConns(1)
	if _, err := a.c.db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.c.FreezeAutomationCut(ctx, 1, nil); err == nil {
		t.Fatal("non-FULL snapshot accepted")
	}
}
