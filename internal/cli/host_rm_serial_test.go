package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
)

// serialRemoveClient is hostRemoveTestClient listing hosts of its own:
// hosts the first time, then later when it is set (the row changed).
type serialRemoveClient struct {
	*hostRemoveTestClient
	hosts, later []*pb.Host
	listed       int
}

func (c *serialRemoveClient) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	c.listed++
	if c.later != nil && c.listed > 1 {
		return &pb.ListHostsResponse{Hosts: c.later}, nil
	}
	return &pb.ListHostsResponse{Hosts: c.hosts}, nil
}

func serialInCRL(t *testing.T, pkiDir, serial string) bool {
	t.Helper()
	serials, err := pki.LoadCRL(filepath.Join(pkiDir, "crl.pem"))
	if err != nil {
		return false
	}
	for _, s := range serials {
		if strings.EqualFold(s, serial) {
			return true
		}
	}
	return false
}

// Codex hostadd-foreign (d): `lv host rm <name>` selects the row the name has
// now. An admission whose row is gone could not be revoked or cleaned up,
// and with another admission under the same name the command removed that
// one. `lv host rm <name> --serial <serial> --address <ip>` selects the
// admission by its certificate: the row of the name when it holds that
// serial, and otherwise no row at all: the serial is revoked and its staged
// files and record removed from the machine, and every row is left as it is.
//
// Mutations: remove the named row whatever its serial — "the name is
// another admission's" is refused; revoke the row's serial without checking
// it is still the one asked for — "the name's row changes" revokes b0b0;
// skip the machine check — "a finished install no row lists" revokes it.
func TestHostRemoveSerial_SelectsTheAdmissionByItsCertificate(t *testing.T) {
	type call struct{ addr, serial string }
	for _, tc := range []struct {
		name    string
		hosts   []*pb.Host
		later   []*pb.Host
		addr    string
		probe   error
		wantErr string
		removed bool // RemoveHost asked, with the serial
		revoked bool
		cleaned bool
	}{
		{name: "the name is another admission's",
			hosts: []*pb.Host{{Name: "node-9", CertSerial: "b0b0", State: pb.HostState_HOST_ACTIVE, Address: "10.0.0.9"}},
			addr:  "10.0.0.9", revoked: true, cleaned: true},
		{name: "no row",
			addr: "10.0.0.9", revoked: true, cleaned: true},
		{name: "the name's row holds it",
			hosts: []*pb.Host{{Name: "node-9", CertSerial: "A1A1", State: pb.HostState_HOST_JOINING, Address: "10.0.0.9"}},
			addr:  "10.0.0.9", removed: true, revoked: true, cleaned: true},
		{name: "the name's row changes to another admission before the revocation",
			hosts: []*pb.Host{{Name: "node-9", CertSerial: "a1a1", State: pb.HostState_HOST_JOINING, Address: "10.0.0.9"}},
			later: []*pb.Host{{Name: "node-9", CertSerial: "b0b0", State: pb.HostState_HOST_ACTIVE, Address: "10.0.0.9"}},
			addr:  "10.0.0.9", wantErr: "nothing was revoked"},
		{name: "another name's row holds it",
			hosts: []*pb.Host{{Name: "node-3", CertSerial: "a1a1", State: pb.HostState_HOST_ACTIVE, Address: "10.0.0.3"}},
			addr:  "10.0.0.9", wantErr: "node-3"},
		{name: "a finished install no row lists",
			addr: "10.0.0.9", probe: errFinishedInstall, wantErr: "completed add"},
		{name: "no address for a serial no row holds",
			wantErr: "--address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkiDir := rmTestPKI(t)
			var cleaned []call
			oldClean, oldProbe := removeStagedAdmission, probeStagedAdmission
			removeStagedAdmission = func(addr, serial string) error {
				cleaned = append(cleaned, call{addr, serial})
				return nil
			}
			probeStagedAdmission = func(addr, serial string) error { return tc.probe }
			t.Cleanup(func() { removeStagedAdmission, probeStagedAdmission = oldClean, oldProbe })
			c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}, hosts: tc.hosts, later: tc.later}
			err := HostRemoveAdmission(context.Background(), c, "node-9", "a1a1", tc.addr, false)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("removal = %v, want a refusal naming %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("removal: %v", err)
			}
			if got := countCalls(c.calls, "remove") > 0; got != tc.removed {
				t.Errorf("RemoveHost asked: %v, want %v (calls %v)", got, tc.removed, c.calls)
			}
			if tc.removed && !strings.EqualFold(c.removeReq.GetExpectedCertSerial(), "a1a1") {
				t.Errorf("RemoveHost for serial %q, want a1a1", c.removeReq.GetExpectedCertSerial())
			}
			if got := serialInCRL(t, pkiDir, "a1a1"); got != tc.revoked {
				t.Errorf("a1a1 revoked: %v, want %v", got, tc.revoked)
			}
			if serialInCRL(t, pkiDir, "b0b0") {
				t.Error("the other admission's certificate b0b0 was revoked")
			}
			if got := len(cleaned) == 1 && cleaned[0].addr == "10.0.0.9" && strings.EqualFold(cleaned[0].serial, "a1a1"); got != tc.cleaned {
				t.Errorf("cleanup %v, want called for 10.0.0.9 and a1a1: %v", cleaned, tc.cleaned)
			}
		})
	}
}

// The machine check reads what the machine records: a serial it serves is
// a completed add, which the command does not undo, unless the record is a
// claim for it that never finished; one it does not serve is not.
//
// Mutation: accept a finished record — "finished" passes.
func TestProbeAdmission_AFinishedInstallIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, marker string
		serves       bool
		want         error
	}{
		{"finished", "node-9 %s 1 aaaa installed", true, errFinishedInstall},
		{"an earlier release's record", "node-9 %s 1", true, errFinishedInstall},
		{"no record", "", true, errFinishedInstall},
		{"never finished", "node-9 %s 1 aaaa installing", true, nil},
		{"not served", "node-9 %s 1 aaaa installed", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAddFixture(t)
			serial := installedSerial(f.before["host.crt"])
			if !tc.serves {
				serial = "a1a1"
			}
			if tc.marker != "" {
				writeMarker(t, f.target, strings.ReplaceAll(tc.marker, "%s", serial)+"\n")
			}
			if err := probeAdmission(f.target, serial); !errors.Is(err, tc.want) {
				t.Errorf("probe = %v, want %v", err, tc.want)
			}
		})
	}
}
