// Fleet scenario for a subset rolling upgrade (lab eqts-26, A2): `lv host
// upgrade <hosts>` must pre-stage the schema of every member, not only its
// targets, because a member left on the old schema refuses every push from an
// upgraded host.
//
// The binary's CurrentSchemaVersion cannot vary inside one test binary, so
// every node starts modelled one schema behind (SetEffectiveDBSchemaForTest)
// and a pre-stage brings it to the real one: the PreStageUpgrade RPC runs the
// staged "binary" (a script) and then RefreshDBSchemaVersion, which reads the
// database's real ledger.
package fleet

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// swapRecordingClient is the operator's client with the binary swap (phase 2
// of `lv host upgrade`) replaced: the fleet cannot re-exec a daemon, and the
// scenario is about what phase 1 left behind. It records the swapped hosts.
type swapRecordingClient struct {
	pb.LiteVirtClient
	swapped []string
}

func (c *swapRecordingClient) UpgradeHost(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UpgradeHostRequest, pb.UpgradeHostResponse], error) {
	return &swapRecordingStream{client: c}, nil
}

type swapRecordingStream struct {
	grpc.ClientStreamingClient[pb.UpgradeHostRequest, pb.UpgradeHostResponse]
	client *swapRecordingClient
	target string
}

func (s *swapRecordingStream) Send(m *pb.UpgradeHostRequest) error {
	if s.target == "" {
		s.target = m.GetTargetHost()
	}
	return nil
}

func (s *swapRecordingStream) CloseAndRecv() (*pb.UpgradeHostResponse, error) {
	s.client.swapped = append(s.client.swapped, s.target)
	return &pb.UpgradeHostResponse{HostName: s.target, Status: "ok", NewVersion: "fleet-new"}, nil
}

// stagedBinary writes the "new build": a script that reports a version and
// answers schema-migrate as the real binary does.
func stagedBinary(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "litevirt-new")
	script := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\n--version) echo \"litevirt version=fleet-new\" ;;\n"+
		"schema-migrate) echo \"schema initialized version=%d\" ;;\nesac\n", corrosion.CurrentSchemaVersion)
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// oldSchemaFleet is a three-node fleet, every node modelled on the previous
// schema, each staging binaries under its own temp directory.
func oldSchemaFleet(t *testing.T) *Cluster {
	t.Helper()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		n.DB.SetEffectiveDBSchemaForTest(corrosion.CurrentSchemaVersion - 1)
		n.Server.SetBinaryPath(filepath.Join(t.TempDir(), "litevirt"))
	}
	return c
}

// TestFleet_SubsetUpgradePreStagesEveryMember: upgrading node-1 alone, run
// from node-0, pre-stages node-0 and node-2 too, and swaps only node-1. A
// write on the upgraded node-1 then reaches node-2, which before the fix
// stayed on the old schema and refused it ("receiver is missing migrations").
func TestFleet_SubsetUpgradePreStagesEveryMember(t *testing.T) {
	ctx := context.Background()
	c := oldSchemaFleet(t)
	a, b, cc := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	client := &swapRecordingClient{LiteVirtClient: c.SelfClient(a)}
	if err := cli.HostUpgrade(ctx, client, cli.UpgradeOpts{
		BinaryPath: stagedBinary(t), HostNames: []string{b.Name}, Yes: true,
	}); err != nil {
		t.Fatalf("lv host upgrade %s: %v", b.Name, err)
	}
	if !slices.Equal(client.swapped, []string{b.Name}) {
		t.Fatalf("swapped %v, want only %s", client.swapped, b.Name)
	}
	for _, n := range c.Nodes {
		if got := n.DB.EffectiveDBSchema(); got != corrosion.CurrentSchemaVersion {
			t.Errorf("%s: effective DB schema %d after the upgrade, want %d (not pre-staged)",
				n.Name, got, corrosion.CurrentSchemaVersion)
		}
	}

	insertVM(t, b, "vm-after-subset-upgrade", b.Name)
	eventually(t, convergeTimeout, cc.Name+" to take the upgraded node's write", func() bool {
		return vmOn(t, cc, "vm-after-subset-upgrade") != nil
	})
	eventually(t, convergeTimeout, a.Name+" to take the upgraded node's write", func() bool {
		return vmOn(t, a, "vm-after-subset-upgrade") != nil
	})
}

// TestFleet_SubsetUpgradeRefusedChangesNothing: a member the upgrade cannot
// reach refuses it before ANY host is pre-staged. A pre-staged host advertises
// the new schema at once, and the unreachable member, back on the old one,
// would refuse its pushes. --skip-prestage names the member as down: the rest
// is pre-staged and the target swapped, and the member alone stays behind.
func TestFleet_SubsetUpgradeRefusedChangesNothing(t *testing.T) {
	ctx := context.Background()
	c := oldSchemaFleet(t)
	a, b, down := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	old := corrosion.CurrentSchemaVersion - 1
	// down is off: every RPC to or from it fails.
	c.SetLinkFaultBoth(a, down, LinkFault{BlockAll: true})
	c.SetLinkFaultBoth(b, down, LinkFault{BlockAll: true})

	client := &swapRecordingClient{LiteVirtClient: c.SelfClient(a)}
	err := cli.HostUpgrade(ctx, client, cli.UpgradeOpts{
		BinaryPath: stagedBinary(t), HostNames: []string{b.Name}, Yes: true,
	})
	if err == nil {
		t.Fatalf("lv host upgrade %s succeeded with %s unreachable", b.Name, down.Name)
	}
	if !strings.Contains(err.Error(), "--skip-prestage "+down.Name) {
		t.Errorf("refusal %q does not name --skip-prestage %s", err, down.Name)
	}
	if len(client.swapped) != 0 {
		t.Fatalf("swapped %v after the refusal", client.swapped)
	}
	for _, n := range c.Nodes {
		if got := n.DB.EffectiveDBSchema(); got != old {
			t.Errorf("%s: effective DB schema %d after a refused upgrade, want %d (unchanged)", n.Name, got, old)
		}
	}

	if err := cli.HostUpgrade(ctx, client, cli.UpgradeOpts{
		BinaryPath: stagedBinary(t), HostNames: []string{b.Name}, Yes: true, SkipPreStage: []string{down.Name},
	}); err != nil {
		t.Fatalf("lv host upgrade %s --skip-prestage %s: %v", b.Name, down.Name, err)
	}
	if !slices.Equal(client.swapped, []string{b.Name}) {
		t.Fatalf("swapped %v, want only %s", client.swapped, b.Name)
	}
	for _, n := range []*Node{a, b} {
		if got := n.DB.EffectiveDBSchema(); got != corrosion.CurrentSchemaVersion {
			t.Errorf("%s: effective DB schema %d, want %d (pre-staged)", n.Name, got, corrosion.CurrentSchemaVersion)
		}
	}
	if got := down.DB.EffectiveDBSchema(); got != old {
		t.Errorf("%s (skipped): effective DB schema %d, want %d", down.Name, got, old)
	}
}
