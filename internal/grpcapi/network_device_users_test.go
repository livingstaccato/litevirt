package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// listFailCT is a container runtime whose list fails with listErr; it links
// NICs, so the holder check asks it.
type listFailCT struct{ fakeCT }

func (listFailCT) ContainerNICLinks(context.Context, string) (map[int]string, error) { return nil, nil }
func (listFailCT) SetContainerNICLink(context.Context, string, int, string) error    { return nil }

// Lab 1 netprov proof, finding 1: on a host without the lxc-* tooling the
// container list fails at the binary lookup. That host runs no containers, so
// the holder check reads it as none, and names the VMs on the device. Any
// other list failure still fails closed, and the VMs are still named beside
// it, so a refusal says who holds the device.
//
// Mutations: treat every list failure as no runtime — the "other" cases
// return no error; treat none as no runtime — the not-found cases error;
// return nothing on a list failure — the VM is not named.
func TestDeviceUsersAll_HostWithoutContainerRuntime(t *testing.T) {
	notFound := &exec.Error{Name: "lxc-ls", Err: exec.ErrNotFound}
	for _, tc := range []struct {
		name    string
		err     error
		wantErr bool
	}{
		{"lxc-ls not installed", fmt.Errorf("lxc-ls: %w", notFound), false},
		{"lxc-ls not installed, unwrapped", notFound, false},
		{"lxc-ls failed", errors.New("lxc-ls: exit status 1: permission denied"), true},
		{"lxc-ls not runnable", fmt.Errorf("lxc-ls: %w", &exec.Error{Name: "lxc-ls", Err: errors.New("permission denied")}), true},
		{"not-found text without the lookup error", errors.New(`exec: "lxc-ls": executable file not found in $PATH`), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			ctx := context.Background()
			virt := libvirtfake.New()
			s.virt = virt
			x := `<domain type="kvm"><name>r5</name><devices><interface type="bridge">` +
				`<mac address="52:54:00:00:00:05"/><source bridge="mvaa"/></interface></devices></domain>`
			virt.SetInactiveXML("r5", x)
			virt.SetActiveXML("r5", x)
			virt.SetState("r5", "running")
			s.SetContainerRuntime(&listFailCT{fakeCT: fakeCT{listErr: tc.err}})

			all, err := s.deviceUsersAll(ctx)
			if (err != nil) != tc.wantErr {
				t.Fatalf("deviceUsersAll: err=%v, want error %v", err, tc.wantErr)
			}
			if got := strings.Join(all["mvaa"].running, ","); got != "VM r5" {
				t.Errorf("running on mvaa = %q, want VM r5 named whatever the container list said", got)
			}
		})
	}
}

// Lab 1 netprov proof, finding 2: a target that refused a network's move
// serves it on the device it was last provisioned on, and announces the
// gateway there, where the guest landed, not on the network's current device.
//
// Mutation: announce on network.BridgeName of the row — "lanbb 172.46.0.1".
func TestAnnounceMigratedGuest_OnTheDeviceThisHostServes(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	cur := compose.NetworkDef{Type: "bridge", Interface: "lanbb", Subnet: "172.46.0.0/24"}
	cfg, _ := json.Marshal(cur)
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "ic_lan", Type: "bridge", Config: string(cfg)}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "g", HostName: s.hostName, State: "running", Spec: "{}"},
		[]corrosion.InterfaceRecord{{VMName: "g", NetworkName: "ic_lan", Ordinal: 0, MAC: "52:54:00:00:00:01"}}, nil); err != nil {
		t.Fatal(err)
	}
	old := cur
	old.Interface = "lanaa"
	s.netDevs.setDef("ic_lan", old, true) // the move was refused here
	var got []string
	s.SetGatewayAnnouncer(func(bridge string, gw netip.Addr) (bool, error) {
		got = append(got, bridge+" "+gw.String())
		return true, nil
	})
	virt := libvirtfake.New()
	s.virt = virt
	virt.SetState("g", "running")
	if _, err := s.AnnounceMigratedGuest(peerCtxFor(t, s, "node-src"), &pb.AnnounceMigratedGuestRequest{VmName: "g"}); err != nil {
		t.Fatalf("AnnounceMigratedGuest: %v", err)
	}
	if want := "lanaa 172.46.0.1"; strings.Join(got, ",") != want {
		t.Errorf("announced %q, want %q", strings.Join(got, ","), want)
	}
}
