package fleet

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/protobuf/proto"
)

// Actual near-limit chosen history and a whole old electorate, real peer TLS
// (fleet's documented address rewrite), exporter pages and receiver owner. The
// target remains normally adopted only at G; no successor adoption is fabricated.
func TestFleet_AutomationReceiverManyLargePages(t *testing.T) {
	f, old, cut := largeAutomationCutFixture(t)
	receiveFleetCut(t, f, old, cut, "receiver-many-pages")
}
func receiveFleetCut(t *testing.T, f *AutomationFixture, old *corrosion.VoterConfig, cut, job string) {
	t.Helper()
	// Near-limit transfer has its own bounded operation context; the fixture
	// construction context expires after two minutes under race instrumentation.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := f.cluster
	source, coordinator, target := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if _, err := c.SelfClient(coordinator).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: coordinator.Name}); err != nil {
		t.Fatal(err)
	}
	// Replicate the real chosen config without invoking successor adoption on the
	// receiver or source. Normal source old sealing already owns the actual cut.
	next := voterRow(t, coordinator, old.Generation+1)
	cert, err := corrosion.DecodeClaimCertificate(next.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []*Node{source, target} {
		if err = corrosion.WriteVoterConfig(ctx, n.DB, next.VoterConfigValue, cert); err != nil {
			t.Fatal(err)
		}
	}
	if adoptedGen(t, target) != old.Generation {
		t.Fatal("fixture receiver already adopted successor")
	}
	if err = source.Server.InitializeAutomationSource(ctx); err != nil {
		t.Fatal(err)
	}
	intent := corrosion.AutomationSourceRequest{Generation: old.Generation, Target: target.Name, Job: job, Revision: 1, Sources: old.Members}
	candidate, err := source.Server.PrepareAutomationSource(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	id, err := source.Server.PublishAutomationSource(ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	receiver := corrosion.NewAutomationReceiver(target.DB, target.PKIDir)
	attempt, err := receiver.Begin(ctx, intent, nil)
	if err != nil {
		t.Fatal("real receiver local authority", err)
	}
	before, err := target.DB.AutomationHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	q := corrosion.AutomationExportRequest{Intent: intent, Publication: id, MaxRecords: 1}
	wire := &pb.AutomationSourceExportRequest{Version: 1, Purpose: "automation-membership-source", Stream: "automation", Generation: intent.Generation, Target: target.Name, Job: job, Revision: 1, PublicationId: id, MaxRecords: 1}
	for _, m := range intent.Sources {
		wire.Sources = append(wire.Sources, &pb.ClaimVoterMember{Name: m.Name, Incarnation: m.Incarnation})
	}
	pages, biggest, total := 0, 0, 0
	for component := uint32(0); component < 12; component++ {
		q.Component = component
		q.Cursor = ""
		wire.Component = component
		wire.Cursor = ""
		var ordinal int64
		for {
			stream, err := c.PeerClient(target, source).ExportAutomationSource(ctx, wire)
			if err != nil {
				t.Fatal(err)
			}
			page, err := stream.Recv()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = stream.Recv(); err != io.EOF {
				t.Fatal("export response not bounded one-page", err)
			}
			raw, err := proto.Marshal(page)
			if err != nil || len(raw) >= 4<<20 {
				t.Fatal("full receiver frame exceeded default gRPC ceiling", len(raw), err)
			}
			p := corrosion.AutomationExportPage{Publication: page.PublicationId, Component: page.Component, Metadata: page.Metadata, Records: page.Records, Chunk: page.Chunk, Cursor: page.Cursor, Terminal: page.Terminal, TerminalRecords: page.TerminalRecords, TerminalBytes: page.TerminalBytes, TerminalDigest: page.TerminalDigest}
			progress, err := receiver.Stage(ctx, attempt, source.Name, q, p)
			if err != nil {
				t.Fatalf("receiver component %d: %v (operation context: %v)", component, err, ctx.Err())
			}
			if progress.Terminal != page.Terminal {
				t.Fatal("receiver inventory terminal differs")
			}
			for _, record := range page.Records {
				ordinal++
				expected, err := source.DB.Query(ctx, `SELECT record FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal=?`, cut, component-3, ordinal)
				stored, storeErr := target.DB.Query(ctx, `SELECT record FROM local_automation_receiver_records WHERE source=? AND component=? AND ordinal=?`, source.Name, component, ordinal)
				if err != nil || storeErr != nil || len(expected) != 1 || len(stored) != 1 || !bytes.Equal(expected[0].Bytes("record"), stored[0].Bytes("record")) {
					t.Fatal("receiver did not retain exact full source payload", err, storeErr)
				}
				total += len(record)
				if len(record) > biggest {
					biggest = len(record)
				}
			}
			pages++
			if page.Terminal {
				break
			}
			q.Cursor = page.Cursor
			wire.Cursor = page.Cursor
		}
	}
	if job == "receiver-many-pages" && (pages < 130 || biggest < 1<<20 || total < 4<<20) {
		t.Fatal("near-limit many-page fixture insufficient", pages, biggest, total)
	}
	after, err := target.DB.AutomationHead(ctx)
	if err != nil || after != before || adoptedGen(t, target) != old.Generation {
		t.Fatal("inert receiver advanced baseline or adopted", err)
	}
	t.Log(fmt.Sprintf("receiver retained %d genuine pages, maximum raw record %d bytes, total %d bytes; complete wire frames <4MiB; no active adoption/head change", pages, biggest, total))
}

func TestFleet_AutomationReceiverLosingAcceptance(t *testing.T) {
	f, old, cut := automationLosingCutFixture(t)
	f.Heal(0)
	receiveFleetCut(t, f, old, cut, "receiver-losing-acceptance")
}
