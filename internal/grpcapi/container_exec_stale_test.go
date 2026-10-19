package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// Exec judges the container's mode where it attaches, under the container's
// lock: an Admin's stop, convert to legacy confinement and start, completed
// after the request's first look at the container, is seen, and a ct.exec-
// only caller does not enter the container's new root mode.
func TestExecContainer_AModeChangedAfterTheFirstLookIsJudged(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		convert bool
		want    codes.Code
	}{
		{"operator, converted meanwhile", ctOperatorCtx(), true, codes.PermissionDenied},
		{"admin, converted meanwhile", adminCtx(), true, codes.OK},
		{"operator, unchanged", ctOperatorCtx(), false, codes.OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			rt := &fakeCTRuntime{}
			s.containerRuntime = rt
			seedExecCT(t, s, "web", unprivDefault)
			prev := execAfterJudge
			t.Cleanup(func() { execAfterJudge = prev })
			execAfterJudge = func() {
				if !tc.convert {
					return
				}
				// lv ct stop; lv ct convert web --confinement legacy; lv ct start
				spec := *unprivDefault
				spec.Confinement = lxc.ConfinementLegacy
				if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
					Name: "web", HostName: s.hostName, State: "running", Project: "acme", CreateSpec: corrosion.EncodeCreateSpec(spec),
				}); err != nil {
					t.Error(err)
				}
			}
			_, err := s.ExecContainer(tc.ctx, &pb.ExecContainerRequest{Name: "web", Argv: []string{"id"}})
			if status.Code(err) != tc.want {
				t.Fatalf("exec: %v, want %v", err, tc.want)
			}
			if tc.want != codes.OK && len(rt.execCalls) != 0 {
				t.Fatalf("the refused exec attached: %+v", rt.execCalls)
			}
		})
	}
}
