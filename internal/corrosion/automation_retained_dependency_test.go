package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"strings"
	"testing"
)

func TestRetainedOriginalLocalDependencyOwnedCuts(t *testing.T) {
	ctx := context.Background()
	key := LeaseTermClaimKey("retained_local_native", 9)
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, LocalHead: 3, BeforeFreeze: func(t *testing.T, _ []*claimTestVoter, local *claimTestVoter) {
		bad := LeaseTermClaimKey("retained-local-native", 9)
		refused, err := local.c.ClaimAccept(ctx, bad, testBallot(3, local.name), ClaimValue{LeaseTerm: &LeaseTermValue{Key: bad.TargetName, Term: 9, Holder: local.name}}, 1, local.signer, unreachable)
		if err != nil || refused.Accepted || refused.Refusal != RefusalInvalidValue {
			t.Fatalf("malformed fixture lease key: %+v err=%v", refused, err)
		}
		t.Logf("original malformed-key setup refusal: %s detail=%s", refused.Refusal, refused.Detail)
		value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: 9, Holder: local.name}}
		reply, err := local.c.ClaimAccept(ctx, key, testBallot(3, local.name), value, 1, local.signer, unreachable)
		if err != nil || !reply.Accepted {
			t.Fatalf("actual native local acceptance: %+v err=%v", reply, err)
		}
	}})
	before := receiverActive(t, f.local.c)
	tx0, err := f.local.c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx0.Rollback()
	tx := &LocalTx{tx: tx0}
	expected, err := rehashAggregateLocalTx(ctx, tx, f.attempt, f.local.c)
	if err != nil {
		t.Fatal(err)
	}
	id := sourceDigest([]byte("litevirt/local-audit/v1"), []byte(f.attempt.id), []byte(expected))
	delivery := strings.Repeat("a", 64)
	local, err := retainedAddress(delivery, 1, f.local.name, id, retainedLocalStream)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := retainedAddress(delivery, 0, f.local.name, id, retainedMetadataStream)
	if err != nil {
		t.Fatal(err)
	}
	d := retainedDescriptorInput("local")
	d.Source = f.local.name
	d.Incarnation = f.attempt.facts.Incarnation
	d.OriginalIdentity = id
	hashes := make([]hash.Hash, len(d.ComponentInventories))
	for i, inv := range d.ComponentInventories {
		hashes[i] = sha256.New()
		prefix, _ := automationCutFrame("section/v1", []byte(inv.Section))
		hashes[i].Write(prefix)
	}
	directory := retainedDirectoryReader{address: dir}
	var native retainedFrameAddress
	var originalFrames int64
	captured, err := aggregateLocalSnapshot(ctx, tx, f.attempt, f.local.c, func(section int, n int64, row Row, raw []byte) error {
		if err := local.save(ctx, tx, section, n, raw); err != nil {
			return err
		}
		hashes[section].Write(raw)
		d.ComponentInventories[section].Records++
		d.ComponentInventories[section].Bytes += int64(len(raw))
		if aggregateLocalTables()[section].table != "local_automation_cuts" {
			return nil
		}
		m, err := readAutomationCutMetadata(row)
		if err != nil {
			return err
		}
		directory.objects++
		native, err = retainedAddress(delivery, directory.objects+1, f.local.name, m.ID, retainedNativeStream)
		if err != nil {
			return err
		}
		metadata := row.Bytes("metadata")
		sum := sha256.Sum256(metadata)
		descriptor := retainedObjectDescriptor{1, "native", retainedObjectLayout("native"), m.ID, m.Source, m.Incarnation, append([]automationCutInventory{{"native-cut/v1", 1, 1, int64(len(metadata)), hex.EncodeToString(sum[:])}}, m.Inventory...)}
		// Directory ordinal is its actual object number. Include the local object.
		if directory.objects == 1 {
			entry, _ := json.Marshal(retainedDirectoryEntry{1, d})
			if err = dir.save(ctx, tx, 0, 1, entry); err != nil {
				return err
			}
		}
		entry, _ := json.Marshal(retainedDirectoryEntry{directory.objects + 1, descriptor})
		if err = dir.save(ctx, tx, 0, directory.objects+1, entry); err != nil {
			return err
		}
		if err = native.save(ctx, tx, 0, 1, metadata); err != nil {
			return err
		}
		return walkAggregateStoredFrames(ctx, tx, "local_automation_cut_records", "cut_id", m.ID, func(s int, ordinal int64, body []byte) error {
			originalFrames++
			return native.save(ctx, tx, s+3, ordinal, body)
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if captured != expected || originalFrames == 0 || directory.objects == 0 {
		t.Fatal("actual local snapshot/native originals unavailable")
	}
	directory.objects++
	for i, h := range hashes {
		d.ComponentInventories[i].Digest = hex.EncodeToString(h.Sum(nil))
	}
	// The final local inventory replaces only this test's unfinished directory setup.
	entry, _ := json.Marshal(retainedDirectoryEntry{1, d})
	if _, err = tx.Exec(ctx, `UPDATE local_automation_receiver_records SET record=? WHERE attempt=? AND source=? AND component=0 AND ordinal=1`, entry, dir.namespace, dir.source); err != nil {
		t.Fatal(err)
	}
	h := retainedAggregateHeader{Attempt: f.attempt.id, BindingDigest: sourceDigest(f.attempt.binding), Host: f.local.name, Incarnation: f.attempt.facts.Incarnation, LocalID: id, LocalDependency: expected}
	got, err := retainedOriginalLocalDependency(ctx, tx, h, f.attempt.binding, local, d, directory)
	if err != nil || got != expected {
		t.Fatalf("exact original local dependency including owned bytes refused: got=%s want=%s err=%v", got, expected, err)
	}
	t.Run("shared-semantic-audit", func(t *testing.T) {
		ordinary, err := auditAggregateLocalTx(ctx, tx, f.attempt, f.local.c, "retained-original-comparison")
		if err != nil {
			t.Fatal(err)
		}
		header := h
		header.LocalCoverage = ordinary.coverage
		original := receiverAuditContext{f.attempt.id, f.attempt.request, f.attempt.facts}
		retained, err := auditRetainedLocal(ctx, tx, original, header, local, d, directory, "retained-local-comparison")
		if err != nil {
			t.Fatalf("authentic original local semantic contribution refused: %v", err)
		}
		if retained.head != ordinary.head || retained.coverage != ordinary.coverage || retained.records != ordinary.records || retained.id != ordinary.id {
			t.Fatal("retained local shared audit differs from C")
		}
		t.Run("owned-acceptance-original", func(t *testing.T) {
			keyRaw, _ := json.Marshal(key)
			rows, err := tx.Query(ctx, `SELECT component,ordinal FROM local_automation_receiver_refs WHERE audit=? AND claim_key=?`, retained.store.id, keyRaw)
			if err != nil || len(rows) != 1 {
				t.Fatal("actual retained local claim reference unavailable", err)
			}
			component, ordinal := rows[0].Int("component"), rows[0].Int64("ordinal")
			origin := func(local aggregateLocalAudit) ([]byte, error) {
				var raw []byte
				err := aggregateLocalOriginsTx(ctx, tx, local, func(read func(int, int64) ([]byte, error)) error {
					var err error
					raw, err = read(component, ordinal)
					return err
				})
				return raw, err
			}
			want, err := origin(ordinary)
			if err != nil {
				t.Fatal("genuine original C native acceptance", err)
			}
			got, err := origin(retained)
			if err != nil {
				t.Fatalf("retained owned acceptance original refused: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("retained native acceptance provenance changed")
			}
		})
	})
	for _, mode := range []string{"binding", "host", "attempt", "native-body", "missing-native", "extra-directory", "directory-identity", "empty-table"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := tx0.ExecContext(ctx, `SAVEPOINT retained_dependency`); err != nil {
				t.Fatal(err)
			}
			defer tx0.ExecContext(ctx, `ROLLBACK TO retained_dependency`)
			header, descriptor, reader := h, d, directory
			descriptor.ComponentInventories = append([]automationCutInventory(nil), d.ComponentInventories...)
			var err error
			switch mode {
			case "binding":
				header.BindingDigest = strings.Repeat("b", 64)
			case "host":
				header.Host = "another"
			case "attempt":
				header.Attempt = strings.Repeat("b", 64)
			case "native-body":
				_, err = tx.Exec(ctx, `UPDATE local_automation_receiver_records SET record=x'6162' WHERE attempt=? AND component>=3`, native.namespace)
			case "missing-native":
				_, err = tx.Exec(ctx, `DELETE FROM local_automation_receiver_records WHERE attempt=?`, native.namespace)
			case "extra-directory":
				_, err = tx.Exec(ctx, `INSERT INTO local_automation_receiver_records(attempt,source,component,ordinal,record) VALUES(?,?,0,?,?)`, dir.namespace, dir.source, reader.objects+1, entry)
			case "directory-identity":
				_, err = tx.Exec(ctx, `UPDATE local_automation_receiver_records SET ordinal=ordinal+10 WHERE attempt=?`, dir.namespace)
			case "empty-table":
				descriptor.ComponentInventories = descriptor.ComponentInventories[:len(descriptor.ComponentInventories)-1]
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := retainedOriginalLocalDependency(ctx, tx, header, f.attempt.binding, local, descriptor, reader)
			if err == nil && got == expected {
				t.Fatal("spliced original dependency matched")
			}
		})
	}
	if err = tx0.Rollback(); err != nil {
		t.Fatal(err)
	}
	if receiverActive(t, f.local.c) != before {
		t.Fatal("retained dependency changed ACTIVE")
	}
}
