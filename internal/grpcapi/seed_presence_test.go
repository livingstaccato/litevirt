package grpcapi

import (
	"context"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestEnsureCloudInit_OwnedSeedVendorDataPresence(t *testing.T) {
	useSeedISOWriter(t)
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "present-empty"}[present], func(t *testing.T) {
			s := testServer(t)
			s.dataDir, s.pkiDir = t.TempDir(), t.TempDir()
			insertTestVMWithSpec(t, adminCtx(), s.db, "presence", "elsewhere", "running", `{"name":"presence","uuid":"presence-1","image":"ubuntu"}`)
			iso := lv.CloudInitISOPath(s.dataDir, "presence")
			cfg := cloudinit.Config{InstanceID: "original-instance", LocalHostname: "presence", UserData: "#cloud-config\nhostname: preserved\n", NetworkConfig: "old-network", VendorData: "old-vendor"}
			if err := cloudinit.GenerateISO(cfg, iso); err != nil {
				t.Fatal(err)
			}
			if err := cloudinit.StampSeed(iso, "presence-1"); err != nil {
				t.Fatal(err)
			}
			before := mustReadSeed(t, iso)
			req := &pb.EnsureCloudInitRequest{VmName: "presence", Userdata: "caller cannot replace user-data", Networkconfig: "version: 2\nethernets: {}\n"}
			if present {
				empty := ""
				req.Vendordata = &empty
			}
			fd := req.ProtoReflect().Descriptor().Fields().ByName("vendordata")
			if fd == nil || fd.Number() != 4 || !fd.HasPresence() {
				t.Fatal("vendordata optional tag4 lost")
			}
			raw, err := proto.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			var round pb.EnsureCloudInitRequest
			if err = proto.Unmarshal(raw, &round); err != nil {
				t.Fatal(err)
			}
			if (round.Vendordata != nil) != present {
				t.Fatal("protobuf lost vendor-data presence")
			}
			peer := diskPeerCtx(t, s)
			limited := context.WithValue(context.WithValue(peer, ctxKeyUsername, "limited"), ctxKeyRole, "viewer")
			if _, e := s.EnsureCloudInit(limited, &round); status.Code(e) != codes.PermissionDenied {
				t.Fatal("peer bypassed forwarded migration authorization", e)
			}
			if mustReadSeed(t, iso) != before {
				t.Fatal("denied forwarded user changed seed")
			}
			if _, err = s.EnsureCloudInit(peer, &round); err != nil {
				t.Fatal(err)
			}
			after := mustReadSeed(t, iso)
			if present {
				if after.NetworkConfig != req.Networkconfig || after.VendorData != "" {
					t.Fatal("present empty did not refresh owned seed and clear vendor-data")
				}
			} else if after != before {
				t.Fatal("absent vendor-data changed owned seed")
			}
			if after.MetaData != before.MetaData || after.UserData != before.UserData || !cloudinit.SeedIsFor(iso, "presence-1") {
				t.Fatal("owned seed identity or user-data changed")
			}
		})
	}
}
