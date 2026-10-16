package fleet

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Two independently valid prefixes must remain independent source outputs.
// Real engine decisions, ordinary membership, cut audit, current authorization,
// FULL publication and peer export are exercised. Fleet replicas are in-memory;
// TLS uses the fleet's documented peer-address rewrite. This is no receiver
// reconciliation, adoption or process/power-loss proof.
func TestFleet_AutomationExportDifferingValidHeads(t *testing.T) {
	f := NewAutomationFixture(t, 5)
	c, ctx := f.cluster, f.ctx
	high, low, target, removed := c.Nodes[0], c.Nodes[2], c.Nodes[1], c.Nodes[4]
	old := voterRow(t, high, 1)
	if len(old.Members) != 5 {
		t.Fatal("fixture needs five ordinary voters")
	}
	lowHead := f.Head(t, 2)
	if lowHead.Sequence == 0 {
		t.Fatal("lower source has no certified head")
	}
	f.Isolate(2)
	if _, err := f.Engine(0).Submit(ctx, f.Barrier(0, "differing-source-head")); err != nil {
		t.Fatal(err)
	}
	highHead := f.Head(t, 0)
	if f.Head(t, 2) != lowHead || highHead.Sequence != lowHead.Sequence+1 || highHead.ClusterUID != lowHead.ClusterUID || highHead.Digest == lowHead.Digest {
		t.Fatal("fixture did not form distinct compatible certified heads", lowHead, highHead)
	}
	for seq := uint64(1); seq <= lowHead.Sequence; seq++ {
		a, ok, err := low.DB.AutomationRecord(ctx, seq)
		if err != nil || !ok {
			t.Fatal(err)
		}
		b, ok, err := high.DB.AutomationRecord(ctx, seq)
		if err != nil || !ok || a.Value.MustDigest() != b.Value.MustDigest() {
			t.Fatal("sources are not compatible prefixes", seq, err)
		}
	}
	type sourceCase struct {
		node  *Node
		index int
		head  corrosion.AutomationPrefix
		cut   string
	}
	sources := []sourceCase{{low, 2, lowHead, ""}, {high, 0, highHead, ""}}
	for i := range sources {
		s := &sources[i]
		if err := s.node.DB.SealVoterGeneration(ctx, 1, "differing valid source heads"); err != nil {
			t.Fatal(err)
		}
		cut, err := f.Engine(s.index).FreezeMembershipCut(ctx, 1)
		if err != nil {
			t.Fatal("actual source cut audit", s.node.Name, err)
		}
		s.cut = cut
	}
	f.Heal(2)
	// Three unsealed voters can choose the normal successor. No forced path,
	// invented source row or caller-verified completion is used.
	if _, err := c.SelfClient(target).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: removed.Name}); err != nil {
		t.Fatal(err)
	}
	adoptAll(t, c, 2)
	var ids []string
	for _, s := range sources {
		t.Run(s.node.Name, func(t *testing.T) {
			if err := s.node.Server.InitializeAutomationSource(ctx); err != nil {
				t.Fatal(err)
			}
			intent := corrosion.AutomationSourceRequest{Generation: 1, Target: target.Name, Job: "differing-valid-heads", Revision: 1, Sources: old.Members}
			prepared, err := s.node.Server.PrepareAutomationSource(ctx, intent)
			if err != nil {
				t.Fatal("current authorized preparation", err)
			}
			id, err := s.node.Server.PublishAutomationSource(ctx, prepared)
			if err != nil || id == "" {
				t.Fatal("FULL publication", err)
			}
			ids = append(ids, id)
			rows, err := s.node.DB.Query(ctx, `SELECT artifact,evidence,membership FROM local_automation_publications WHERE id=?`, id)
			if err != nil || len(rows) != 1 {
				t.Fatal(err)
			}
			publication := rows[0]
			var artifact struct {
				Manifest  json.RawMessage
				Signature []byte
				Chain     [][]byte
			}
			if err := json.Unmarshal(publication.Bytes("artifact"), &artifact); err != nil {
				t.Fatal(err)
			}
			var manifest struct {
				Source, Root string
				Cut          json.RawMessage
			}
			if err := json.Unmarshal(artifact.Manifest, &manifest); err != nil {
				t.Fatal(err)
			}
			var cut struct {
				ID, Source string
				Head       corrosion.AutomationPrefix
				Inventory  []struct {
					Section        string
					Codec          int
					Records, Bytes int64
					Digest         string
				}
			}
			if err := json.Unmarshal(manifest.Cut, &cut); err != nil {
				t.Fatal(err)
			}
			if len(artifact.Signature) == 0 || len(artifact.Chain) == 0 || manifest.Source != s.node.Name || cut.Source != s.node.Name || cut.ID != s.cut || cut.Head != s.head || len(cut.Inventory) != 9 {
				t.Fatal("signed publication changed exact source/head/inventory", cut)
			}
			stored, err := s.node.DB.Query(ctx, `SELECT metadata,root FROM local_automation_cuts WHERE id=?`, s.cut)
			if err != nil || len(stored) != 1 || !bytes.Equal(manifest.Cut, stored[0].Bytes("metadata")) || manifest.Root != stored[0].String("root") {
				t.Fatal("signed cut differs from completed materialization", err)
			}
			if cut.Inventory[2].Section != "history" || cut.Inventory[2].Records != int64(s.head.Sequence) {
				t.Fatal("history inventory does not match exact certified head")
			}
			req := &pb.AutomationSourceExportRequest{Version: 1, Purpose: "automation-membership-source", Stream: "automation", Generation: 1, Target: target.Name, Job: intent.Job, Revision: 1, PublicationId: id, MaxRecords: 1}
			for _, m := range old.Members {
				req.Sources = append(req.Sources, &pb.ClaimVoterMember{Name: m.Name, Incarnation: m.Incarnation})
			}
			client := c.PeerClient(target, s.node)
			for component := uint32(0); component < 12; component++ {
				req.Component = component
				req.Cursor = ""
				var expected [][]byte
				if component >= 3 {
					records, err := s.node.DB.Query(ctx, `SELECT record FROM local_automation_cut_records WHERE cut_id=? AND section=? ORDER BY ordinal`, s.cut, component-3)
					if err != nil {
						t.Fatal(err)
					}
					for _, r := range records {
						expected = append(expected, r.Bytes("record"))
					}
				}
				var all []byte
				count := 0
				terminal := false
				for pageNo := 0; pageNo < 100; pageNo++ {
					stream, err := client.ExportAutomationSource(ctx, req)
					if err != nil {
						t.Fatal(err)
					}
					page, err := stream.Recv()
					if err != nil {
						t.Fatal("independent source export", s.node.Name, component, err)
					}
					if _, err = stream.Recv(); err != io.EOF {
						t.Fatal("not one page and EOF", err)
					}
					if page.PublicationId != id || page.Component != component {
						t.Fatal("crossed source/component")
					}
					if component < 3 {
						all = append(all, page.Chunk...)
					} else {
						if !bytes.Equal(page.Metadata, manifest.Cut) {
							t.Fatal("export changed signed metadata")
						}
						for _, raw := range page.Records {
							if count >= len(expected) || !bytes.Equal(raw, expected[count]) {
								t.Fatal("independent source record changed", component, count)
							}
							all = append(all, raw...)
							count++
						}
					}
					if page.Terminal {
						terminal = true
						if page.TerminalBytes != int64(len(all)) {
							t.Fatal("terminal bytes differ")
						}
						if component < 3 {
							column := []string{"artifact", "evidence", "membership"}[component]
							digest := sha256.Sum256(all)
							if !bytes.Equal(all, publication.Bytes(column)) || page.TerminalDigest != hex.EncodeToString(digest[:]) {
								t.Fatal("exact source evidence differs")
							}
						} else {
							inv := cut.Inventory[component-3]
							// Independently frame the documented section digest domain.
							hash := sha256.New()
							hash.Write([]byte("LVCUT\x01"))
							for _, part := range []string{"section/v1", inv.Section} {
								var size [4]byte
								binary.BigEndian.PutUint32(size[:], uint32(len(part)))
								hash.Write(size[:])
								hash.Write([]byte(part))
							}
							hash.Write(all)
							if count != len(expected) || inv.Records != int64(count) || inv.Bytes != int64(len(all)) || inv.Digest != hex.EncodeToString(hash.Sum(nil)) || page.TerminalRecords != inv.Records || page.TerminalDigest != inv.Digest {
								t.Fatal("exact independent signed inventory differs", component)
							}
							t.Logf("source=%s head=%d/%s section=%s records=%d bytes=%d digest=%s", s.node.Name, s.head.Sequence, s.head.Digest, inv.Section, inv.Records, inv.Bytes, inv.Digest)
						}
						break
					}
					if page.Cursor == "" {
						t.Fatal("missing continuation")
					}
					req.Cursor = page.Cursor
				}
				if !terminal {
					t.Fatal("source never completed component", component)
				}
			}
			t.Logf("accepted independent source=%s publication=%s cut=%s root=%s certified head=%+v", s.node.Name, id, s.cut, manifest.Root, s.head)
		})
	}
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatal("missing distinct independent source publications", ids)
	}
}
