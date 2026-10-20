package corrosion

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Copy genuinely produced C inputs into isolated retained addresses. This
// helper produces no receipt, adopted donor, current proof or successful import.
func retainedCopyOriginalAggregate(t *testing.T, ctx context.Context, tx *LocalTx, f *aggregateFixture, bundle string) (retainedAggregateHeader, retainedDirectoryReader) {
	t.Helper()
	rows, err := tx.Query(ctx, `SELECT a.local_id,a.head,a.coverage,a.roster,l.dependency,l.coverage AS local_coverage FROM local_automation_aggregates a JOIN local_automation_local_audits l ON l.id=a.local_id WHERE a.id=?`, bundle)
	if err != nil || len(rows) != 1 {
		t.Fatal("actual original C metadata", err)
	}
	row := rows[0]
	h := retainedAggregateHeader{Version: 1, Purpose: "automation-original-aggregate", LayoutDigest: retainedLocalLayoutDigest(), Attempt: f.attempt.id, Job: f.attempt.request.Job, Revision: f.attempt.request.Revision, Host: f.local.name, Incarnation: f.attempt.facts.Incarnation, BindingObject: 1, BindingDigest: sourceDigest(f.attempt.binding), LocalRowsObject: 2, LocalInventoryDigest: strings.Repeat("a", 64), LocalID: row.String("local_id"), LocalDependency: row.String("dependency"), LocalCoverage: row.String("local_coverage"), Coverage: row.String("coverage")}
	if json.Unmarshal(row.Bytes("head"), &h.Head) != nil || json.Unmarshal(row.Bytes("roster"), &h.Roster) != nil {
		t.Fatal("original head/roster")
	}
	delivery := strings.Repeat("c", 64)
	directoryAddress, err := retainedAddress(delivery, 0, h.Host, h.BindingDigest, retainedMetadataStream)
	if err != nil {
		t.Fatal(err)
	}
	directory := retainedDirectoryReader{directoryAddress, 2}
	saveDescriptor := func(n int64, d retainedObjectDescriptor) {
		raw, _ := json.Marshal(retainedDirectoryEntry{n, d})
		if err := directoryAddress.save(ctx, tx, 0, n, raw); err != nil {
			t.Fatal(err)
		}
	}
	bindingAddress, err := retainedAddress(delivery, 1, h.Host, h.BindingDigest, retainedMetadataStream)
	if err != nil {
		t.Fatal(err)
	}
	raw := f.attempt.binding
	sum := sha256.Sum256(raw)
	bindingDescriptor := retainedObjectDescriptor{1, "binding", retainedObjectLayout("binding"), h.BindingDigest, h.Host, h.Incarnation, []automationCutInventory{{"binding/v1", 1, int64((len(raw) + AutomationExportChunkBytes - 1) / AutomationExportChunkBytes), int64(len(raw)), hex.EncodeToString(sum[:])}}}
	for n := int64(1); len(raw) > 0; n++ {
		size := len(raw)
		if size > AutomationExportChunkBytes {
			size = AutomationExportChunkBytes
		}
		if err = bindingAddress.save(ctx, tx, 0, n, raw[:size]); err != nil {
			t.Fatal(err)
		}
		raw = raw[size:]
	}
	saveDescriptor(1, bindingDescriptor)
	localAddress, err := retainedAddress(delivery, 2, h.Host, h.LocalID, retainedLocalStream)
	if err != nil {
		t.Fatal(err)
	}
	localDescriptor := retainedDescriptorInput("local")
	localDescriptor.Source = h.Host
	localDescriptor.Incarnation = h.Incarnation
	localDescriptor.OriginalIdentity = h.LocalID
	hashes := make([]hash.Hash, len(localDescriptor.ComponentInventories))
	for i, inv := range localDescriptor.ComponentInventories {
		hashes[i] = sha256.New()
		prefix, _ := automationCutFrame("section/v1", []byte(inv.Section))
		hashes[i].Write(prefix)
	}
	err = walkAggregateStoredFrames(ctx, tx, "local_automation_local_rows", "local_id", h.LocalID, func(section int, n int64, body []byte) error {
		if err := localAddress.save(ctx, tx, section, n, body); err != nil {
			return err
		}
		hashes[section].Write(body)
		localDescriptor.ComponentInventories[section].Records++
		localDescriptor.ComponentInventories[section].Bytes += int64(len(body))
		if section != 16 {
			return nil
		}
		row, err := decodeAutomationFramedRow(aggregateLocalTables()[section].descriptor(), n, body, maxAggregateLocalRecordBytes)
		if err != nil {
			return err
		}
		metadata, err := readAutomationCutMetadata(row)
		if err != nil {
			return err
		}
		directory.objects++
		address, err := retainedAddress(delivery, directory.objects, metadata.Source, metadata.ID, retainedNativeStream)
		if err != nil {
			return err
		}
		raw := row.Bytes("metadata")
		sum := sha256.Sum256(raw)
		descriptor := retainedObjectDescriptor{1, "native", retainedObjectLayout("native"), metadata.ID, metadata.Source, metadata.Incarnation, append([]automationCutInventory{{"native-cut/v1", 1, 1, int64(len(raw)), hex.EncodeToString(sum[:])}}, metadata.Inventory...)}
		if err = address.save(ctx, tx, 0, 1, raw); err != nil {
			return err
		}
		saveDescriptor(directory.objects, descriptor)
		return walkAggregateStoredFrames(ctx, tx, "local_automation_cut_records", "cut_id", metadata.ID, func(section int, n int64, body []byte) error { return address.save(ctx, tx, section+3, n, body) })
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, h := range hashes {
		localDescriptor.ComponentInventories[i].Digest = hex.EncodeToString(h.Sum(nil))
	}
	saveDescriptor(2, localDescriptor)
	for _, roster := range h.Roster {
		publication := f.attempt.publications[roster.Source]
		metadata := publication.manifest
		directory.objects++
		address, err := retainedAddress(delivery, directory.objects, roster.Source, roster.Publication, retainedSourceStream)
		if err != nil {
			t.Fatal(err)
		}
		descriptor := retainedObjectDescriptor{1, "source", retainedObjectLayout("source"), roster.Publication, roster.Source, roster.Incarnation, nil}
		sections, _, _ := retainedObjectSections("source")
		for i := 0; i < 3; i++ {
			n := publication.metadataBytes[i]
			sum := publication.metadataDigests[i]
			descriptor.ComponentInventories = append(descriptor.ComponentInventories, automationCutInventory{sections[i], 1, (n + AutomationExportChunkBytes - 1) / AutomationExportChunkBytes, n, hex.EncodeToString(sum[:])})
		}
		descriptor.ComponentInventories = append(descriptor.ComponentInventories, metadata.Cut.Inventory...)
		saveDescriptor(directory.objects, descriptor)
		if err = walkAutomationStoredFrames(ctx, tx, "local_automation_receiver_records", "attempt=? AND source=?", []any{f.attempt.id, roster.Source}, "component", maxAutomationCutRecordBytes, func(section int, n int64, body []byte) error { return address.save(ctx, tx, section, n, body) }); err != nil {
			t.Fatal(err)
		}
	}
	inventory := sha256.New()
	sourceHash(inventory, []byte("litevirt/retained-local-inventory/v1"))
	var count, total int64
	for n := int64(1); n <= directory.objects; n++ {
		raw, err := directoryAddress.read(ctx, tx, 0, n)
		if err != nil {
			t.Fatal(err)
		}
		var entry retainedDirectoryEntry
		if json.Unmarshal(raw, &entry) != nil {
			t.Fatal("directory setup")
		}
		if entry.Descriptor.Kind != "local" && entry.Descriptor.Kind != "native" {
			continue
		}
		descriptor, _ := json.Marshal(entry.Descriptor)
		sourceHash(inventory, []byte("object"), automationCutInteger(n), descriptor)
		count++
		for _, inv := range entry.Descriptor.ComponentInventories {
			total += inv.Bytes
		}
	}
	sourceHash(inventory, []byte("end"), automationCutInteger(count), automationCutInteger(total))
	h.LocalInventoryDigest = hex.EncodeToString(inventory.Sum(nil))
	return h, directory
}

func TestRetainedWholeOriginalAggregateRebuild(t *testing.T) {
	ctx := context.Background()
	key := LeaseTermClaimKey("retained_rebuild", 7)
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, LocalHead: 3, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
		for i, v := range voters {
			value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: 7, Holder: v.name}}
			reply, err := v.c.ClaimAccept(ctx, key, testBallot(uint64((i+1)%3+1), "common"), value, 1, v.signer, unreachable)
			if err != nil || !reply.Accepted {
				t.Fatalf("real original acceptance: %+v %v", reply, err)
			}
		}
	}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	bundle, err := f.receiver.auditAggregate(ctx, f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	active := receiverActive(t, f.local.c)
	tx0, err := f.local.c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx0.Rollback()
	tx := &LocalTx{tx: tx0}
	h, directory := retainedCopyOriginalAggregate(t, ctx, tx, f, bundle)
	got, err := rebuildRetainedAggregate(ctx, tx, h, f.attempt.binding, directory, f.attempt.view)
	if err != nil {
		t.Fatalf("complete genuine original C rebuild refused: %v", err)
	}
	rootPEM, err := os.ReadFile(filepath.Join(f.local.pki, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	rootBlock, _ := pem.Decode(rootPEM)
	if rootBlock == nil {
		t.Fatal("actual root missing")
	}
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// These genuine originals are directly root-signed. Only that required
	// live root defines the upper bound; original leaves remain historical.
	if got.notBefore.IsZero() || got.notBefore.After(time.Now()) || !got.notAfter.Equal(root.NotAfter) {
		t.Fatal("complete original C lost required current interval", got.notBefore, got.notAfter, root.NotAfter)
	}
	if got.id != bundle {
		t.Fatal("reconstructed original aggregate ID differs")
	}
	wantClaims, err := retainedClaimsDigest(ctx, tx, bundle, bundle)
	if err != nil || got.claims != wantClaims {
		t.Fatal("rebuilt original claims commitment differs", err)
	}
	// Existing C comparison reads every typed original key/body, including
	// losing copies, conflicting-ballot indexes, and chosen maxima.
	for _, d := range []aggregateTable{aggregateCopiesTable, aggregateMaximaTable, aggregateConflictsTable} {
		if err := aggregateCompareTable(ctx, tx, d, bundle, got.temporary); err != nil {
			t.Fatal("reconstructed C claims differ", err)
		}
	}

	for _, mode := range []string{"counted-source-losing", "local-native-losing"} {
		t.Run(mode, func(t *testing.T) {
			store := got.sources[0].store
			if mode == "local-native-losing" {
				var err error
				store, err = retainedLocalOwnedStoreTx(ctx, tx, got.local)
				if err != nil {
					t.Fatal("actual native candidate setup", err)
				}
			}
			rawKey, _ := json.Marshal(key)
			refs, err := tx.Query(ctx, `SELECT component,ordinal,accepted_round FROM local_automation_receiver_refs WHERE audit=? AND claim_key=?`, store.id, rawKey)
			if err != nil || len(refs) != 1 {
				t.Fatal("actual original candidate index", err)
			}
			component, ordinal := refs[0].Int("component"), refs[0].Int64("ordinal")
			row, err := store.record(ctx, component, ordinal)
			if err != nil {
				t.Fatal(err)
			}
			state, err := scanClaimRow(key, row)
			if err != nil || state.Value == nil {
				t.Fatal("actual full candidate", err)
			}
			full, _ := json.Marshal(state.Value)
			raw, err := encodeAutomationCutRecord(automationCutSections[component-3].name, ordinal, row)
			if err != nil {
				t.Fatal(err)
			}
			cut := store.publication.manifest.Cut
			identity := retainedHolderBody{OriginalSource: cut.Source, OriginalIncarnation: cut.Incarnation, OriginalCut: cut.ID, OriginalRoot: store.publication.manifest.Root, Key: key, Accepted: state.Accepted, ValueDigest: sourceDigest([]byte("litevirt/aggregate-full-value/v1"), full), AcceptanceDigest: sourceDigest([]byte("litevirt/retained-acceptance-record/v1"), raw)}
			if state.Accepted.Round >= 3 {
				t.Fatal("candidate must lose genuine aggregate maximum")
			}
			if mode == "local-native-losing" {
				if err := aggregateCleanScratchTx(ctx, tx, store.id); err != nil {
					t.Fatal(err)
				}
			}
			ref, err := got.candidate(ctx, tx, directory, identity, full)
			if err != nil {
				t.Fatalf("complete original losing candidate refused: %v", err)
			}
			if ref.Component != component || ref.Ordinal != ordinal || ref.ValueDigest != identity.ValueDigest {
				t.Fatal("original candidate reference differs")
			}
			for _, mutation := range []string{"source", "incarnation", "cut", "root", "ballot", "value", "acceptance"} {
				t.Run(mutation, func(t *testing.T) {
					bad := identity
					switch mutation {
					case "source":
						bad.OriginalSource = "absent"
					case "incarnation":
						bad.OriginalIncarnation = "other"
					case "cut":
						bad.OriginalCut = strings.Repeat("a", 32)
					case "root":
						bad.OriginalRoot = strings.Repeat("a", 64)
					case "ballot":
						bad.Accepted.Round++
					case "value":
						bad.ValueDigest = strings.Repeat("a", 64)
					case "acceptance":
						bad.AcceptanceDigest = strings.Repeat("a", 64)
					}
					if _, err := got.candidate(ctx, tx, directory, bad, full); err == nil {
						t.Fatal("spliced candidate accepted")
					}
				})
			}
		})
	}
	t.Run("receipt-graph-crossbinding-only", func(t *testing.T) {
		// Construct consumed metadata ONLY to test graph equality. This is not an
		// actual finalizer receipt, signed holder, adopted donor or completion proof.
		holder := retainedTestGraphMetadata(t, ctx, tx, h, directory, got)
		directory.objects += 2
		rebuilt, err := verifyRetainedGraph(ctx, tx, holder, directory, f.attempt.view)
		if err != nil {
			t.Fatalf("complete original graph crossbinding refused: %v", err)
		}
		if !rebuilt.notBefore.Equal(got.notBefore) || !rebuilt.notAfter.Equal(got.notAfter) {
			t.Fatal("whole retained graph lost original current intervals")
		}
		if rebuilt.id != got.id || rebuilt.claims != got.claims {
			t.Fatal("graph reconstructed commitments differ")
		}
		for _, mode := range []string{"holder", "incarnation", "generation", "config", "members", "receipt", "aggregate", "directory", "count", "bytes"} {
			t.Run(mode, func(t *testing.T) {
				bad := holder
				switch mode {
				case "holder":
					bad.Donor = "other"
				case "incarnation":
					bad.DonorIncarnation = "other"
				case "generation":
					bad.Generation++
				case "config":
					bad.ConfigDigest = strings.Repeat("a", 64)
				case "members":
					bad.MembersDigest = strings.Repeat("a", 64)
				case "receipt":
					bad.ReceiptDigest = strings.Repeat("a", 64)
				case "aggregate":
					bad.AggregateDigest = strings.Repeat("a", 64)
				case "directory":
					bad.DirectoryRoot = strings.Repeat("a", 64)
				case "count":
					bad.DirectoryObjects++
				case "bytes":
					bad.DirectoryBytes++
				}
				if _, err := verifyRetainedGraph(ctx, tx, bad, directory, f.attempt.view); err == nil {
					t.Fatal("spliced receipt graph accepted")
				}
			})
		}
	})
	if err = tx0.Rollback(); err != nil {
		t.Fatal(err)
	}
	if receiverActive(t, f.local.c) != active {
		t.Fatal("inert reconstruction changed ACTIVE")
	}
}

func retainedTestGraphMetadata(t *testing.T, ctx context.Context, tx *LocalTx, h retainedAggregateHeader, directory retainedDirectoryReader, rebuilt retainedAggregateRebuild) retainedHolderBody {
	t.Helper()
	original, _, err := h.originalBinding(func() []byte {
		d, a, e := directory.find(ctx, tx, "binding", h.BindingDigest)
		if e != nil {
			t.Fatal(e)
		}
		b, e := a.metadata(ctx, tx, d)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}())
	if err != nil {
		t.Fatal(err)
	}
	save := func(kind string, raw []byte, domain string) string {
		directory.objects++
		id := sourceDigest([]byte(domain), raw)
		a, e := retainedAddress(strings.Split(directory.address.namespace, ":")[1], directory.objects, h.Host, id, retainedMetadataStream)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(raw)
		d := retainedObjectDescriptor{1, kind, retainedObjectLayout(kind), id, h.Host, h.Incarnation, []automationCutInventory{{kind + "/v1", 1, 1, int64(len(raw)), hex.EncodeToString(sum[:])}}}
		if e = a.save(ctx, tx, 0, 1, raw); e != nil {
			t.Fatal(e)
		}
		entry, _ := json.Marshal(retainedDirectoryEntry{directory.objects, d})
		if e = directory.address.save(ctx, tx, 0, directory.objects, entry); e != nil {
			t.Fatal(e)
		}
		return id
	}
	headerRaw, _ := json.Marshal(h)
	headerID := save("header", headerRaw, retainedHeaderDomain)
	// Independent graph preimage excludes the not-yet-written receipt.
	graph := sha256.New()
	sourceHash(graph, []byte("litevirt/retained-evidence-graph/v1"))
	var size int64
	if err := directory.walk(ctx, tx, func(n int64, d retainedObjectDescriptor) error {
		raw, _ := json.Marshal(d)
		sourceHash(graph, []byte("object"), automationCutInteger(n), raw)
		for _, inv := range d.ComponentInventories {
			size += inv.Bytes
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sourceHash(graph, []byte("end"), automationCutInteger(directory.objects), automationCutInteger(size))
	headRaw, _ := json.Marshal(h.Head)
	next := original.value.Facts.Next
	receipt := retainedImportReceipt{1, "automation-completed-import", h.Host, h.Incarnation, next.Generation, sourceConfigDigest(next), next.MembersHash, h.Attempt, h.BindingDigest, rebuilt.id, headerID, h.LocalInventoryDigest, hex.EncodeToString(graph.Sum(nil)), directory.objects, size, sourceDigest(headRaw), rebuilt.claims}
	receiptRaw, _ := json.Marshal(receipt)
	receiptID := save("receipt", receiptRaw, retainedReceiptDomain)
	digest := sha256.New()
	sourceHash(digest, []byte("litevirt/retained-directory/v1"))
	var descriptors, bodies int64
	if err := directory.walk(ctx, tx, func(n int64, d retainedObjectDescriptor) error {
		raw, _ := json.Marshal(d)
		sourceHash(digest, []byte("object"), automationCutInteger(n), raw)
		entry, _ := json.Marshal(retainedDirectoryEntry{n, d})
		descriptors += int64(len(entry))
		for _, inv := range d.ComponentInventories {
			bodies += inv.Bytes
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sourceHash(digest, []byte("end"), automationCutInteger(directory.objects), automationCutInteger(descriptors), automationCutInteger(bodies))
	return retainedHolderBody{Donor: h.Host, DonorIncarnation: h.Incarnation, Generation: next.Generation, ConfigDigest: sourceConfigDigest(next), MembersDigest: next.MembersHash, ReceiptDigest: receiptID, AggregateDigest: rebuilt.id, DirectoryRoot: hex.EncodeToString(digest.Sum(nil)), DirectoryObjects: directory.objects, DirectoryBytes: descriptors}
}

// An old retained layout has no target sections. Current replay must prove
// those projections empty, not silently omit them from semantic comparison.
func TestRetainedOriginal83ReplayRequiresEmptyTargets(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"local_automation_target_operations", "local_automation_target_reservations"} {
		t.Run(table, func(t *testing.T) {
			err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				store := receiverAuditStore{tx: tx, localProjectionID: "synthetic-empty-original", localLayoutDigest: retainedLocalLayout83Digest()}
				if err := store.compareLocalSemantic(ctx, "old83-replay"); err != nil {
					return fmt.Errorf("SETUP empty old replay: %w", err)
				}
				var err error
				if table == "local_automation_target_operations" {
					_, err = tx.Exec(ctx, `INSERT INTO local_automation_target_operations(stage,cluster_uid,operation_id,kind,project_uid,principal_uid,request_id,resource_uid,target_name,sequence,decision_digest,body_json,assignment_json) VALUES('old83-replay','cluster','operation','admit_legacy_rebuild','','principal','request','','machine',1,'digest','{}','{}')`)
				} else {
					_, err = tx.Exec(ctx, `INSERT INTO local_automation_target_reservations(stage,cluster_uid,target_key,operation_id,sequence) VALUES('old83-replay','cluster','key','operation',1)`)
				}
				if err != nil {
					return err
				}
				if err = store.compareLocalSemantic(ctx, "old83-replay"); err == nil || !strings.Contains(err.Error(), table) {
					return fmt.Errorf("RETAINED83_NONEMPTY_NEW_PROJECTION_ACCEPTED: %s: %v", table, err)
				}
				_, err = tx.Exec(ctx, "DELETE FROM "+table+" WHERE stage='old83-replay'")
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
