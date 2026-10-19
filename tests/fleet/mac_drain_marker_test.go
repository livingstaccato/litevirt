package fleet

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/pki"
)

// A real cold drain whose target has not seen the drain
// journal yet (hidden from the target's StartVM for the length of the call,
// which is what replication lag looks like there), with a holder of the
// guest's MAC appearing after the preflight. The marker is all that keeps the
// guest from being left stopped.
//
// mtls: the drain is driven over the host certificate (as the existing fleet
// tests do): the control, and it passes.
// bearer: the drain is driven by a logged-in operator, with
// auth.forwarded_identity on and latched. The source's StartVM to the target
// relays the operator's bearer (PeerDial), the target promotes the call to the
// operator, and the marker is judged on an auth method that is no longer mtls.
func TestFleet_MAC_DrainResumeMarkerUnderForwardedIdentity(t *testing.T) {
	for _, mode := range []string{"mtls", "bearer"} {
		t.Run(mode, func(t *testing.T) {
			const dup = "52:54:00:7a:0f:01"
			sc := newColdStoppedScenario(t)
			sc.makeRunning(t)
			ctx := context.Background()
			gates := enforceGate(t, sc.c)
			for _, n := range sc.c.Nodes {
				n.Server.SetForwardedIdentity(true)
			}
			for _, n := range sc.c.Nodes {
				g := gates[n.Name]
				eventually(t, 10*time.Second, n.Name+" to latch forwarded_identity_v1", func() bool {
					return g.Enforced(ctx, capabilities.ForwardedIdentityV1)
				})
			}
			if err := corrosion.InsertInterface(ctx, sc.src.DB, corrosion.InterfaceRecord{VMName: "os1", NetworkName: "lan", MAC: dup}); err != nil {
				t.Fatal(err)
			}
			sc.dst.Server.SetBridgeEnsure(func(string) error { return nil })
			var marker, fwd []string
			sc.dst.HookUnary("StartVM", func(hctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
				if md, ok := metadata.FromIncomingContext(hctx); ok {
					marker = md.Get(grpcapi.DrainResumeFromMDKey)
					fwd = md.Get(pki.FwdBearerMDKey)
				}
				if err := corrosion.InsertVM(ctx, sc.dst.DB, corrosion.VMRecord{Name: "late", HostName: sc.dst.Name, State: "running"},
					[]corrosion.InterfaceRecord{{VMName: "late", NetworkName: "lan", MAC: dup}}, nil); err != nil {
					t.Error(err)
				}
				// The journal has not reached the target.
				hide := `UPDATE operations SET desired_ref = desired_ref || '#lag' WHERE operation_kind = ? AND resource_id = 'os1'`
				show := `UPDATE operations SET desired_ref = replace(desired_ref, '#lag', '') WHERE operation_kind = ? AND resource_id = 'os1'`
				if err := sc.dst.DB.Execute(ctx, hide, string(corrosion.OpDrainColdMove)); err != nil {
					t.Error(err)
				}
				defer func() {
					if err := sc.dst.DB.Execute(ctx, show, string(corrosion.OpDrainColdMove)); err != nil {
						t.Error(err)
					}
				}()
				return handler(hctx, req)
			})

			var client pb.LiteVirtClient = sc.c.SelfClient(sc.src)
			if mode == "bearer" {
				if _, err := sc.c.SelfClient(sc.src).CreateUser(ctx, &pb.CreateUserRequest{
					Username: "op", Password: "op-password-0123456789", Role: "admin",
				}); err != nil {
					t.Fatalf("CreateUser: %v", err)
				}
				login, err := sc.c.SelfClient(sc.src).Login(ctx, &pb.LoginRequest{Username: "op", Password: "op-password-0123456789"})
				if err != nil || !strings.HasPrefix(login.GetToken(), grpcapi.SessionTokenPrefix) {
					t.Fatalf("Login: %v", err)
				}
				client = sc.c.bearerClient(sc.src, login.GetToken())
			}
			st, err := client.DrainHost(ctx, &pb.DrainHostRequest{Name: sc.src.Name})
			if err != nil {
				t.Fatalf("DrainHost: %v", err)
			}
			progress := map[string]*pb.DrainProgress{}
			for {
				p, rerr := st.Recv()
				if rerr == io.EOF {
					break
				}
				if rerr != nil {
					t.Fatalf("drain stream: %v", rerr)
				}
				progress[p.VmName] = p
			}
			if len(marker) != 1 || marker[0] != sc.src.Name {
				t.Fatalf("premise: the target's StartVM got marker %v, want [%s]", marker, sc.src.Name)
			}
			if mode == "bearer" && len(fwd) != 1 {
				t.Fatalf("premise: the target's StartVM carried no forwarded bearer (%v)", fwd)
			}
			if p := progress["os1"]; p == nil || p.Status != "done" || p.Error != "" {
				t.Errorf("drain progress for os1 = %+v, want done with no error", p)
			}
			if active, _ := sc.dst.Virt.DomainIsActive("os1"); !active {
				t.Errorf("os1, running before the drain, is not running on %s (nor anywhere): left stopped", sc.dst.Name)
			}
		})
	}
}
