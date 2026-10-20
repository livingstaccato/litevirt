package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// D2-18 verification of fd57b1fa (APPROVE with folds m-A, m-B, m-D; m-C is
// in internal/libvirt): the reconciler undefines a leftover before it
// finishes the quarantine (m-A); its start path never finishes the VM's own
// stage away (m-B); the adopt texts give the sequence that works (m-D).
func TestDoctorFirmwareMove_Residuals(t *testing.T) {
	ctx := context.Background()
	returnedReleased := func(t *testing.T) *fwlRig {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
		r.fenceTarget()
		if _, err := r.doctor(actAcceptSource, withAck); err != nil {
			t.Fatalf("accept-source: %v", err)
		}
		r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
		r.dstFake.SetStateReason(fwlVM, "destroyed")
		return r
	}
	exec := func(t *testing.T, r *fwlRig, q string, args ...any) {
		t.Helper()
		if err := r.src.db.Execute(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	reconcileDst := func(r *fwlRig) {
		rc := health.NewReconciler(r.dst.hostName, r.dst.dataDir, r.dst.db, r.dstFake)
		rc.SetFirmwareStore(r.dstStore)
		rc.ReconcileOnce(ctx)
	}
	qdir := func(s *Server) string { return filepath.Join(s.dataDir, fwmig.QuarantineDir) }
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }
	reconciled := func(s *Server) []string {
		ents, _ := os.ReadDir(qdir(s))
		var out []string
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), fwlVM+"-reconciled-") {
				out = append(out, e.Name())
			}
		}
		return out
	}

	// m-A: the leftover's undefine fails after its state was staged, and the
	// row then comes back here: the start is refused naming the stage, and
	// --restore puts the state back.
	// Mutation: finish the quarantine before the undefine — red.
	t.Run("leftover_undefine_fails_then_row_returns", func(t *testing.T) {
		r := returnedReleased(t)
		nv := read(r.dstStore.NvramPath(fwlVM))
		r.dstFake.FailUndefinePreserv = func(string) error { return errors.New("libvirt: undefine failed") }
		reconcileDst(r)
		r.dstFake.FailUndefinePreserv = nil
		stage := filepath.Join(qdir(r.dst), fwmig.StageName(fwlVM, fwmig.StageReconciling, fwLiveUUID))
		if !exists(stage) || len(reconciled(r.dst)) != 0 {
			t.Fatalf("after a failed undefine: stage %v, finished %v; want the state still staged", exists(stage), reconciled(r.dst))
		}
		exec(t, r, `UPDATE vms SET host_name = ?, state = 'stopped' WHERE name = ?`, "dst-host", fwlVM)
		if err := r.dstFake.StartDomain(fwlVM); err == nil || !strings.Contains(err.Error(), stage) {
			t.Fatalf("start with the state staged: %v", err)
		}
		if _, err := r.dst.SupersededDisks(adminCtx(), &pb.SupersededDisksRequest{RestorePath: stage}); err != nil {
			t.Fatalf("restore: %v", err)
		}
		if read(r.dstStore.NvramPath(fwlVM)) != nv {
			t.Error("the NVRAM did not come back")
		}
		if err := r.dstFake.StartDomain(fwlVM); err != nil {
			t.Fatalf("start after the restore: %v", err)
		}
	})

	// m-B: the row asks for a start on this host (pending: a start after
	// failover, onboot) and the VM's own state is in a stage: the
	// reconciler's start path leaves the domain and the stage.
	// Mutation: drop the staged skip in startPendingVM — red.
	t.Run("own_stage_row_pending/start_path_holds", func(t *testing.T) {
		r := returnedReleased(t)
		stage := filepath.Join(qdir(r.dst), fwmig.StageName(fwlVM, fwmig.StageReconciling, fwLiveUUID))
		if err := os.MkdirAll(stage, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(r.dstStore.NvramPath(fwlVM), filepath.Join(stage, "nvram")); err != nil {
			t.Fatal(err)
		}
		exec(t, r, `UPDATE vms SET host_name = ?, state = 'pending' WHERE name = ?`, "dst-host", fwlVM)
		reconcileDst(r)
		if _, ok := r.dstFake.RawState(fwlVM); !ok {
			t.Error("the VM's own domain was undefined")
		}
		if !exists(stage) || len(reconciled(r.dst)) != 0 {
			t.Errorf("stage %v, finished %v: the VM's own stage was finished away", exists(stage), reconciled(r.dst))
		}
	})

	// m-D: with another copy listed, the refusal gives adopt → cold migrate →
	// restore → start, and the outcome never says the VM can just be started.
	// Mutation: the round-5 outcome ("`lv start` starts it") — red.
	t.Run("adopt_texts_give_the_sequence", func(t *testing.T) {
		r := returnedReleased(t)
		r.src.RetryOwedFirmwareDiscardsOnce(ctx)
		owed, _ := r.src.fwRecords().ListOwedDiscards()
		for _, o := range owed {
			_ = r.src.fwRecords().RemoveOwedDiscard(o.VM, o.Attempt)
		}
		exec(t, r, `UPDATE vms SET host_name = ?, state = 'stopped' WHERE name = ?`, "dst-host", fwlVM)
		newer := filepath.Join(qdir(r.src), fwlVM+"-reconciled-1700000000")
		if err := os.MkdirAll(newer, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := r.doctor(actAdopt)
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("adopt without the acknowledgement: %v", err)
		}
		for _, want := range []string{"--adopt-target-copy --acknowledge-rollback", "do not start the VM", "lv migrate " + fwlVM + " H --cold",
			"lv host superseded-disks H --restore", "check their dates"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal lacks %q: %v", want, err)
			}
		}
		resp, err := r.doctor(actAdopt, withAck)
		if err != nil {
			t.Fatal(err)
		}
		out := resp.GetOutcome()
		if strings.Contains(out, "starts it") || !strings.Contains(out, "do not start the VM until") || !strings.Contains(out, "--cold") {
			t.Errorf("outcome %q", out)
		}
	})
}
