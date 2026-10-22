package cli

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// listHostsClient answers ListHosts with hosts, in that order.
type listHostsClient struct {
	pb.LiteVirtClient
	hosts []string
}

func (c *listHostsClient) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	resp := &pb.ListHostsResponse{}
	for i, h := range c.hosts {
		resp.Hosts = append(resp.Hosts, &pb.Host{Name: h, Address: "10.78.0." + string(rune('1'+i))})
	}
	return resp, nil
}

type nopFenceSSHHost struct{ name, addr string }

func (h *nopFenceSSHHost) Name() string    { return h.name }
func (h *nopFenceSSHHost) Address() string { return h.addr }
func (h *nopFenceSSHHost) RunScript(context.Context, []string, string) ([]byte, error) {
	return nil, errors.New("not run in this test")
}

// recordDials swaps the SSH dial for one that records which hosts were
// dialed, for the rest of the test.
func recordDials(t *testing.T) *[]string {
	t.Helper()
	var dialed []string
	prev := dialFenceSSHHost
	dialFenceSSHHost = func(_ string, name, addr string) (FenceSSHHost, func(), error) {
		dialed = append(dialed, name)
		return &nopFenceSSHHost{name: name, addr: addr}, func() {}, nil
	}
	t.Cleanup(func() { dialFenceSSHHost = prev })
	return &dialed
}

// TestSSHFenceSSHHosts_HostFilterSelectsExactlyTheNamedHosts: `--host X`
// dials and returns exactly the named hosts, wherever they fall in ListHosts
// order (B5: a host named first or in the middle also selected every host
// listed after it, so `--remove --host X` stripped the drop-in from hosts
// nobody named), and still returns every host's address for the peer list.
func TestSSHFenceSSHHosts_HostFilterSelectsExactlyTheNamedHosts(t *testing.T) {
	order := []string{"node-1", "node-2", "node-4", "node-5", "node-3"}
	for _, tc := range []struct {
		name string
		only []string
		want []string
	}{
		{"first", []string{"node-1"}, []string{"node-1"}},
		{"middle", []string{"node-4"}, []string{"node-4"}},
		{"last", []string{"node-3"}, []string{"node-3"}},
		{"two apart", []string{"node-5", "node-1"}, []string{"node-1", "node-5"}},
		{"named twice", []string{"node-2", "node-2"}, []string{"node-2"}},
		{"no flag: every host", nil, order},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialed := recordDials(t)
			hosts, all, closeAll, err := SSHFenceSSHHosts(context.Background(), &listHostsClient{hosts: order}, "root", tc.only)
			if err != nil {
				t.Fatalf("SSHFenceSSHHosts(%v): %v", tc.only, err)
			}
			defer closeAll()
			var got []string
			for _, h := range hosts {
				got = append(got, h.Name())
			}
			if !reflect.DeepEqual(got, tc.want) || !reflect.DeepEqual(*dialed, tc.want) {
				t.Fatalf("--host %v selected %v and dialed %v, want exactly %v", tc.only, got, *dialed, tc.want)
			}
			if len(all) != len(order) {
				t.Fatalf("peer addresses %v, want every listed host", all)
			}
		})
	}
}

// TestSSHFenceSSHHosts_UnknownHostRefusesBeforeTouchingAny: a name the
// cluster does not list refuses the whole run before any host is dialed,
// alone or beside names it does list, wherever those fall.
func TestSSHFenceSSHHosts_UnknownHostRefusesBeforeTouchingAny(t *testing.T) {
	order := []string{"node-1", "node-2", "node-4", "node-5", "node-3"}
	for _, only := range [][]string{{"node-9"}, {"node-1", "node-9"}, {"node-9", "node-3"}, {"node-4", "node-9", "node-5"}, {""}} {
		dialed := recordDials(t)
		hosts, _, _, err := SSHFenceSSHHosts(context.Background(), &listHostsClient{hosts: order}, "root", only)
		if err == nil || hosts != nil {
			t.Fatalf("--host %q: hosts %v, err %v; want a refusal", only, hosts, err)
		}
		if len(*dialed) != 0 {
			t.Fatalf("--host %q dialed %v before refusing", only, *dialed)
		}
		if !strings.Contains(err.Error(), "no host") {
			t.Fatalf("--host %q: %v", only, err)
		}
	}
}
