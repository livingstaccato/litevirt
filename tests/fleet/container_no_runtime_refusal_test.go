package fleet

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// `lv ct create` with no host runs on the node that took the request, and
// `lv ct migrate` names its target. Placement is strict about
// litevirt.lxc=true (corrosion.HostRunsContainers), but neither of these
// placed anything, so on a host with no container runtime both went ahead and
// failed late with "lxc-create not found" — a migrate after it had already
// stopped the source. Both refuse up front now, naming the label.
//
// Mutations: dropping the check from CreateContainer lets the "false" and the
// unlabelled create land on node-1; dropping it from MigrateContainer stops
// and archives the source before the target fails.

// setLXCLabel sets node's litevirt.lxc label to v, or removes it for "" (the
// harness labels every node "true"); either reads as no runtime to placement.
func setLXCLabel(t *testing.T, via, node *Node, v string) {
	t.Helper()
	ctx := context.Background()
	if v == "" {
		if err := via.DB.Execute(ctx, `UPDATE hosts SET labels = json_remove(labels, '$."`+
			corrosion.LabelLXCCapable+`"') WHERE name = ?`, node.Name); err != nil {
			t.Fatalf("unlabel %s: %v", node.Name, err)
		}
	} else if err := corrosion.SetHostLabel(ctx, via.DB, node.Name, corrosion.LabelLXCCapable, v); err != nil {
		t.Fatalf("label %s: %v", node.Name, err)
	}
	if h, err := corrosion.GetHost(ctx, via.DB, node.Name); err != nil || h == nil {
		t.Fatalf("read %s back: %v", node.Name, err)
	} else if corrosion.HostRunsContainers(*h) {
		t.Fatalf("fixture: %s still runs containers: %v", node.Name, h.Labels)
	}
}

func wantNoRuntimeRefusal(t *testing.T, what string, err error, host string) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("%s: got %v, want FailedPrecondition", what, err)
	}
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, corrosion.LabelLXCCapable) || !strings.Contains(msg, host) {
		t.Errorf("%s: refusal %q does not name the host %s and the %s label", what, msg, host, corrosion.LabelLXCCapable)
	}
}

func TestContainerCreate_RefusedOnAHostWithNoContainerRuntime(t *testing.T) {
	for _, label := range []string{"false", ""} {
		t.Run("label="+label, func(t *testing.T) {
			c := ctMigrateCluster(t)
			entry, bare := c.Nodes[0], c.Nodes[1]
			setLXCLabel(t, entry, bare, label)
			const name = "ct-nowhere"

			// No host: it runs on the node that received it.
			_, err := c.SelfClient(bare).CreateContainer(context.Background(), &pb.CreateContainerRequest{
				Name: name, Template: "download", Distro: "debian", Release: "bookworm", Arch: "amd64",
				Cpu: 1, MemoryMib: 256,
			})
			wantNoRuntimeRefusal(t, "create with no host on a host with no runtime", err, bare.Name)
			// Named explicitly from another node: forwarded, refused the same.
			_, err = c.SelfClient(entry).CreateContainer(context.Background(), &pb.CreateContainerRequest{
				HostName: bare.Name, Name: name, Template: "download", Distro: "debian", Release: "bookworm",
				Arch: "amd64", Cpu: 1, MemoryMib: 256,
			})
			wantNoRuntimeRefusal(t, "create forwarded to a host with no runtime", err, bare.Name)
			if bare.CT.Exists(name) {
				t.Error("the runtime was asked to create the container anyway")
			}
			if rec, err := corrosion.GetContainer(context.Background(), entry.DB, bare.Name, name); err != nil || rec != nil {
				t.Errorf("a container row was written for the refused create: %+v %v", rec, err)
			}

			// The capable node still creates: the check refuses only the host
			// that has no runtime.
			createContainer(t, c, entry, name)
		})
	}
}

func TestContainerMigrate_RefusedOntoAHostWithNoContainerRuntime(t *testing.T) {
	for _, label := range []string{"false", ""} {
		t.Run("label="+label, func(t *testing.T) {
			c := ctMigrateCluster(t)
			src, dst := c.Nodes[0], c.Nodes[1]
			ctx := context.Background()
			const name = "ct-stay"

			createContainer(t, c, src, name)
			if _, err := c.SelfClient(src).StartContainer(ctx, &pb.StartContainerRequest{
				HostName: src.Name, Name: name,
			}); err != nil {
				t.Fatalf("start container: %v", err)
			}
			setLXCLabel(t, src, dst, label)

			err := runMigrate(t, c, src, dst, name, stagingRepo(t))
			wantNoRuntimeRefusal(t, "migrate onto a host with no runtime", err, dst.Name)
			if calls := src.CT.StopCalls(); len(calls) != 0 {
				t.Errorf("the source was stopped %d times before the refusal; want 0", len(calls))
			}
			if calls := src.CT.ExportCalls(); len(calls) != 0 {
				t.Errorf("the source was archived %d times before the refusal; want 0", len(calls))
			}
			if rec, err := corrosion.GetContainer(ctx, src.DB, src.Name, name); err != nil || rec == nil ||
				rec.State != "running" || rec.StateDetail != "" {
				t.Errorf("the source row changed: %+v %v", rec, err)
			}
		})
	}
}
