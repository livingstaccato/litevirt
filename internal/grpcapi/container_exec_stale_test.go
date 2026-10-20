package grpcapi

import (
	"context"
	"testing"
	"time"

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

// longExecRT is a runtime whose exec attaches, reports it, and then runs
// until release is closed (lv ct exec web -- sleep infinity).
type longExecRT struct {
	*fakeCTRuntime
	attached chan struct{}
	release  chan struct{}
}

func (l *longExecRT) ExecContainerStarted(ctx context.Context, name string, argv []string, started func()) (ContainerExecResult, error) {
	started()
	close(l.attached)
	<-l.release
	return l.fakeCTRuntime.ExecContainer(ctx, name, argv)
}

// Review F2: a long exec holds the container's lock only until it is
// attached, so an Admin's stop (and delete, migrate, backup) goes ahead
// while it runs.
func TestExecContainer_ALongExecDoesNotHoldOffAStop(t *testing.T) {
	s := testServer(t)
	rt := &longExecRT{fakeCTRuntime: &fakeCTRuntime{}, attached: make(chan struct{}), release: make(chan struct{})}
	s.containerRuntime = rt
	seedExecCT(t, s, "web", unprivDefault)
	execDone := make(chan error, 1)
	go func() {
		_, err := s.ExecContainer(ctOperatorCtx(), &pb.ExecContainerRequest{Name: "web", Argv: []string{"sleep", "infinity"}})
		execDone <- err
	}()
	select {
	case <-rt.attached:
	case err := <-execDone:
		t.Fatalf("the exec ended (%v) without attaching through the runtime's attach report", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the exec never attached")
	}
	defer func() { close(rt.release); <-execDone }()
	stopDone := make(chan error, 1)
	go func() {
		_, err := s.StopContainer(adminCtx(), &pb.StopContainerRequest{Name: "web"})
		stopDone <- err
	}()
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("stop during a long exec: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an Admin's stop is held off for as long as an exec runs")
	}
}
