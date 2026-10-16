package grpcapi

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// resOp seeds one reservation-bearing operation: its header at headerEpoch with
// the given created_at, and the given steps at their epochs. Test fixture data.
func resOp(t *testing.T, s *Server, id string, kind corrosion.OperationKind, resourceKind, resourceID, method string,
	headerEpoch int64, rv corrosion.ReservationVector, createdAt string, steps map[int64][]string) {
	t.Helper()
	ctx := context.Background()
	enc, err := rv.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := corrosion.InsertOperation(ctx, s.db, corrosion.OperationRecord{
		ID: id, Method: method, ResourceKind: resourceKind, ResourceID: resourceID,
		OperationKind: string(kind), RequestHash: "h", ReservationJSON: enc, VMOwnerEpoch: headerEpoch,
	}); err != nil {
		t.Fatalf("InsertOperation %s: %v", id, err)
	}
	if err := s.db.Execute(ctx, `UPDATE operations SET created_at = ? WHERE id = ?`, createdAt, id); err != nil {
		t.Fatalf("set created_at: %v", err)
	}
	for epoch, names := range steps {
		for _, n := range names {
			if err := corrosion.AppendOperationStep(ctx, s.db, corrosion.OperationStepRecord{
				OperationID: id, OwnerEpoch: epoch, StepName: n,
			}); err != nil {
				t.Fatalf("append %s@%d: %v", n, epoch, err)
			}
		}
	}
}

// resVM seeds a live VM row with an explicit project, owner epoch, incarnation
// stamp and barrier.
func resVM(t *testing.T, s *Server, name, project string, epoch int64, createdAt, activeOp string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: name, HostName: s.hostName, State: "running", Spec: "{}", Project: project,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
	if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = ?, created_at = ?, active_operation_id = ? WHERE name = ?`,
		epoch, createdAt, activeOp, name); err != nil {
		t.Fatalf("set vm fields: %v", err)
	}
}

func resAgo(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339) }

// seedHostReservations seeds one counted reservation of every state on
// test-host, plus one on another host, and returns the VM names they name.
func seedHostReservations(t *testing.T, s *Server) []string {
	t.Helper()
	ctx := context.Background()
	insertTestHost(t, ctx, s.db, s.hostName, "active")
	long := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano)
	leak := map[int64][]string{
		0: {corrosion.OpStepReserved, corrosion.OpStepAdmitted},
		1: {corrosion.OpStepPlanned, corrosion.OpStepDesiredPersisted, corrosion.OpStepConfigApplied,
			corrosion.OpStepLiveApplied, corrosion.OpStepObserved, corrosion.OpStepCompleted},
	}
	on := func(cpu, mem int) corrosion.ReservationVector {
		return corrosion.ReservationVector{TargetHost: s.hostName, TargetCPU: cpu, TargetMemMiB: mem, Provisional: true}
	}
	resize := corrosion.OpResourceUpdateRunning

	resVM(t, s, "vm-leak", "acme", 1, long, "")
	resOp(t, s, "op-leak", resize, "vm", "vm-leak", "ResizeVMLive", 0, on(0, 512), resAgo(time.Hour), leak)

	resVM(t, s, "vm-busy", "acme", 1, long, "op-busy")
	resOp(t, s, "op-busy", resize, "vm", "vm-busy", "ResizeVMLive", 1, on(2, 0), resAgo(time.Hour),
		map[int64][]string{1: {corrosion.OpStepReserved, corrosion.OpStepAdmitted, corrosion.OpStepPlanned}})

	resVM(t, s, "vm-stale", "acme", 1, long, "")
	resOp(t, s, "op-stale", resize, "vm", "vm-stale", "ResizeVMLive", 1, on(0, 256), resAgo(time.Hour),
		map[int64][]string{1: {corrosion.OpStepReserved, corrosion.OpStepAdmitted}})

	resVM(t, s, "vm-fresh", "acme", 1, long, "")
	resOp(t, s, "op-fresh", resize, "vm", "vm-fresh", "ResizeVMLive", 1, on(1, 0), resAgo(time.Minute),
		map[int64][]string{1: {corrosion.OpStepReserved}})

	resOp(t, s, "op-gone", resize, "vm", "vm-gone", "ResizeVMLive", 1, on(0, 1024), resAgo(time.Hour),
		map[int64][]string{1: {corrosion.OpStepReserved, corrosion.OpStepAdmitted}})

	resVM(t, s, "vm-blk", "acme", 1, long, "")
	resOp(t, s, "op-blk", resize, "vm", "vm-blk", "ResizeVMLive", 0, on(0, 128), resAgo(time.Hour), leak)
	if err := corrosion.AppendOperationStep(ctx, s.db, corrosion.OperationStepRecord{
		OperationID: "op-blk", StepName: corrosion.OpStepCancelled, Facts: corrosion.ReservationReleasedFacts,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE operation_steps SET deleted_at = ?
		WHERE operation_id = 'op-blk' AND owner_epoch = 0 AND step_name = 'cancelled'`, resAgo(time.Minute)); err != nil {
		t.Fatal(err)
	}

	resOp(t, s, "op-lease", resize, corrosion.CapacityResourceKind, "", "CreateVM", 0,
		corrosion.ReservationVector{TargetHost: s.hostName, TargetCPU: 1, TargetMemMiB: 64}, resAgo(time.Minute),
		map[int64][]string{0: {corrosion.OpStepReserved}})
	resOp(t, s, "op-xfer", resize, corrosion.CapacityResourceKind, "", "MigrateVM", 0,
		corrosion.ReservationVector{TargetHost: s.hostName, TargetCPU: 2, TargetMemMiB: 32}, resAgo(time.Minute),
		map[int64][]string{0: {corrosion.OpStepReserved}})
	resOp(t, s, "op-named-lease", resize, corrosion.CapacityResourceKind, "", "CreateVM", 0,
		corrosion.ReservationVector{TargetHost: s.hostName, TargetCPU: 1, TargetMemMiB: 8, Workload: "vm-new"}, resAgo(time.Minute),
		map[int64][]string{0: {corrosion.OpStepReserved}})
	resOp(t, s, "op-ct", corrosion.OpWorkloadCreate, "container", "ct-web", "CreateContainer", 0,
		corrosion.ReservationVector{TargetHost: s.hostName, TargetCPU: 1, TargetMemMiB: 4, Workload: "ct-web"}, resAgo(time.Hour),
		map[int64][]string{0: {corrosion.OpStepReserved}})
	resOp(t, s, "op-journal", corrosion.OpVMReplace, "vm", "vm-leak", "CutoverVM", 0,
		corrosion.ReservationVector{TargetHost: s.hostName, TargetMemMiB: 16}, resAgo(time.Hour),
		map[int64][]string{0: {corrosion.OpStepPlanned}})

	resOp(t, s, "op-elsewhere", resize, "vm", "vm-leak", "ResizeVMLive", 1,
		corrosion.ReservationVector{TargetHost: "other-host", TargetMemMiB: 8}, resAgo(time.Hour),
		map[int64][]string{1: {corrosion.OpStepReserved}})
	return []string{"vm-leak", "vm-busy", "vm-stale", "vm-fresh", "vm-gone", "vm-blk", "vm-new", "ct-web"}
}

func reservationsByOp(h *pb.Host) map[string]*pb.HostReservation {
	out := map[string]*pb.HostReservation{}
	for _, r := range h.GetReservations() {
		out[r.GetOperationId()] = r
	}
	return out
}

func TestInspectHost_ListsReservations(t *testing.T) {
	s := testServer(t)
	seedHostReservations(t, s)

	h, err := s.InspectHost(adminCtx(), &pb.InspectHostRequest{Name: s.hostName})
	if err != nil {
		t.Fatalf("InspectHost: %v", err)
	}
	cpu, mem, err := corrosion.HostReserved(context.Background(), s.db, s.hostName)
	if err != nil {
		t.Fatal(err)
	}
	if cpu == 0 || mem == 0 {
		t.Fatalf("seed: HostReserved = %d/%d, want both nonzero", cpu, mem)
	}
	if int(h.GetReservedCpu()) != cpu || int(h.GetReservedMemMib()) != mem {
		t.Fatalf("reserved_cpu/reserved_mem_mib = %d/%d, HostReserved says %d/%d",
			h.GetReservedCpu(), h.GetReservedMemMib(), cpu, mem)
	}
	var sumCPU, sumMem int32
	for _, r := range h.GetReservations() {
		sumCPU += r.GetVcpu()
		sumMem += r.GetMemoryMib()
	}
	if int(sumCPU) != cpu || int(sumMem) != mem {
		t.Fatalf("rows sum to %d/%d, HostReserved says %d/%d", sumCPU, sumMem, cpu, mem)
	}

	want := []struct {
		op, state, kind, vm, project string
		blocked                      bool
	}{
		{"op-leak", "releasable", "resize", "vm-leak", "acme", false},
		{"op-busy", "in-flight", "resize", "vm-busy", "acme", false},
		{"op-stale", "stale", "resize", "vm-stale", "acme", false},
		{"op-fresh", "admitting", "resize", "vm-fresh", "acme", false},
		{"op-gone", "releasable", "resize", "vm-gone", "", false},
		{"op-blk", "release-blocked", "resize", "vm-blk", "acme", true},
		{"op-lease", "auto-expires", "admission-lease", "", "", false},
		{"op-xfer", "auto-expires", "transfer-lease", "", "", false},
		{"op-journal", "journal", "vm_replace", "vm-leak", "acme", false},
		{"op-named-lease", "auto-expires", "admission-lease", "vm-new", "", false},
		{"op-ct", "stale", "create", "ct-web", "", false},
	}
	got := reservationsByOp(h)
	if len(got) != len(want) {
		t.Fatalf("listed %d reservations %v, want %d (op-elsewhere targets another host)", len(got), got, len(want))
	}
	for _, w := range want {
		r := got[w.op]
		if r == nil {
			t.Errorf("%s not listed", w.op)
			continue
		}
		if r.GetState() != w.state || r.GetKind() != w.kind || r.GetVm() != w.vm || r.GetProject() != w.project ||
			r.GetReleaseBlocked() != w.blocked {
			t.Errorf("%s: state %q kind %q vm %q project %q blocked %v; want %q %q %q %q %v (detail %q)",
				w.op, r.GetState(), r.GetKind(), r.GetVm(), r.GetProject(), r.GetReleaseBlocked(),
				w.state, w.kind, w.vm, w.project, w.blocked, r.GetDetail())
		}
		if r.GetDetail() == "" || r.GetCreatedAt() == nil {
			t.Errorf("%s: detail %q created_at %v, want both set", w.op, r.GetDetail(), r.GetCreatedAt())
		}
	}

	leak := got["op-leak"]
	if leak.GetMethod() != "ResizeVMLive" || leak.GetHeaderOwnerEpoch() != 0 || !leak.GetAdmitted() ||
		!leak.GetProvisional() || leak.GetMemoryMib() != 512 {
		t.Errorf("op-leak fields: %+v", leak)
	}
	if !strings.Contains(leak.GetDetail(), "owner epoch 1") {
		t.Errorf("op-leak detail %q, want the classifier's sentence", leak.GetDetail())
	}
	if a := leak.GetAgeSeconds(); a < 3500 || a > 3700 {
		t.Errorf("op-leak age_seconds = %d, want about 3600", a)
	}
	if got["op-busy"].GetHeaderOwnerEpoch() != 1 || got["op-fresh"].GetAdmitted() {
		t.Errorf("op-busy header epoch %d, op-fresh admitted %v; want 1, false",
			got["op-busy"].GetHeaderOwnerEpoch(), got["op-fresh"].GetAdmitted())
	}
	if d := got["op-blk"].GetDetail(); !strings.HasPrefix(d, "still counted; release blocked: ") {
		t.Errorf("op-blk detail %q, want the still-counted release-blocked prefix", d)
	}

	// ListHosts leaves the reservation fields empty.
	lh, err := s.ListHosts(adminCtx(), &pb.ListHostsRequest{})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	for _, x := range lh.GetHosts() {
		if len(x.GetReservations()) != 0 || x.GetReservedCpu() != 0 || x.GetReservedMemMib() != 0 {
			t.Errorf("ListHosts carries reservations for %s", x.GetName())
		}
	}
}

func TestInspectHost_RedactsUnreadableVM(t *testing.T) {
	s := testServer(t)
	names := seedHostReservations(t, s)

	full, err := s.InspectHost(adminCtx(), &pb.InspectHostRequest{Name: s.hostName})
	if err != nil {
		t.Fatalf("InspectHost (admin): %v", err)
	}
	other := boundAtCtx(t, s, "vic", "viewer", "Viewer", "/projects/other")
	acme := boundAtCtx(t, s, "ana", "viewer", "Viewer", "/projects/acme")

	h, err := s.InspectHost(other, &pb.InspectHostRequest{Name: s.hostName})
	if err != nil {
		t.Fatalf("InspectHost (viewer at /projects/other): %v", err)
	}
	if h.GetReservedCpu() != full.GetReservedCpu() || h.GetReservedMemMib() != full.GetReservedMemMib() {
		t.Fatalf("redacted totals %d/%d, admin sees %d/%d",
			h.GetReservedCpu(), h.GetReservedMemMib(), full.GetReservedCpu(), full.GetReservedMemMib())
	}
	fullBy := reservationsByOp(full)
	if len(h.GetReservations()) != len(fullBy) {
		t.Fatalf("viewer sees %d rows, admin %d", len(h.GetReservations()), len(fullBy))
	}
	for _, r := range h.GetReservations() {
		f := fullBy[r.GetOperationId()]
		if r.GetVm() != "" || r.GetProject() != "" {
			t.Errorf("%s: viewer at /projects/other sees vm %q project %q", r.GetOperationId(), r.GetVm(), r.GetProject())
		}
		for _, n := range append(names, "acme") {
			if strings.Contains(r.GetDetail(), n) {
				t.Errorf("%s: redacted detail %q names %s", r.GetOperationId(), r.GetDetail(), n)
			}
		}
		if f == nil || r.GetVcpu() != f.GetVcpu() || r.GetMemoryMib() != f.GetMemoryMib() ||
			r.GetState() != f.GetState() || r.GetAgeSeconds() == 0 {
			t.Errorf("%s: redacted row %+v lost what the admin row %+v carries", r.GetOperationId(), r, f)
		}
	}

	// A viewer of the VM's project sees it; a VM that no longer exists resolves
	// to no project, so only a cluster-root grant reads its name.
	h, err = s.InspectHost(acme, &pb.InspectHostRequest{Name: s.hostName})
	if err != nil {
		t.Fatalf("InspectHost (viewer at /projects/acme): %v", err)
	}
	by := reservationsByOp(h)
	if r := by["op-busy"]; r.GetVm() != "vm-busy" || r.GetProject() != "acme" || !strings.Contains(r.GetDetail(), "vm-busy") {
		t.Errorf("acme viewer: op-busy vm %q project %q detail %q, want vm-busy/acme named", r.GetVm(), r.GetProject(), r.GetDetail())
	}
	for _, op := range []string{"op-gone", "op-named-lease", "op-ct"} {
		r := by[op]
		if r == nil || r.GetVm() != "" || r.GetProject() != "" {
			t.Errorf("acme viewer: %s = %+v, want vm and project redacted", op, r)
		}
	}
	if d := by["op-gone"].GetDetail(); strings.Contains(d, "vm-gone") {
		t.Errorf("acme viewer: op-gone detail %q names the VM", d)
	}
}

// seedUnreadableReservations adds two reservations that cannot be read: op-bad,
// whose vector does not decode (so its target is unknown), and op-mismatch, a
// test-host reservation whose vector names project "beta" under an operation
// of project "alpha"; and op-mismatch-far, the same shape targeting another
// host.
func seedUnreadableReservations(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	steps := map[int64][]string{1: {corrosion.OpStepReserved}}
	resOp(t, s, "op-bad", corrosion.OpResourceUpdateRunning, "vm", "vm-leak", "ResizeVMLive", 1,
		corrosion.ReservationVector{TargetHost: s.hostName, TargetMemMiB: 8}, resAgo(time.Hour), steps)
	resOp(t, s, "op-mismatch", corrosion.OpResourceUpdateRunning, "vm", "vm-leak", "ResizeVMLive", 1,
		corrosion.ReservationVector{TargetHost: s.hostName, TargetMemMiB: 8, Project: "beta"}, resAgo(time.Hour), steps)
	resOp(t, s, "op-mismatch-far", corrosion.OpResourceUpdateRunning, "vm", "vm-leak", "ResizeVMLive", 1,
		corrosion.ReservationVector{TargetHost: "other-host", TargetMemMiB: 8, Project: "beta"}, resAgo(time.Hour), steps)
	for _, q := range []string{
		`UPDATE operations SET reservation_json = '{not json' WHERE id = 'op-bad'`,
		`UPDATE operations SET project = 'alpha' WHERE id IN ('op-mismatch', 'op-mismatch-far')`,
	} {
		if err := s.db.Execute(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
}

// A reservation that cannot be read does not take the rest of the host, or the
// other reservations, with it: InspectHost lists every readable reservation,
// names the unreadable ones in reservations_error, and marks the totals
// partial.
func TestInspectHost_UnreadableReservationReturnsTheHost(t *testing.T) {
	s := testServer(t)
	seedHostReservations(t, s)
	seedUnreadableReservations(t, s)
	if err := s.db.Execute(context.Background(),
		`UPDATE hosts SET fence_strategy = 'ipmi' WHERE name = ?`, s.hostName); err != nil {
		t.Fatal(err)
	}
	if _, _, err := corrosion.HostReserved(context.Background(), s.db, s.hostName); err == nil {
		t.Fatal("seed: HostReserved accepted the unreadable reservations; admission must still refuse them")
	}

	h, err := s.InspectHost(adminCtx(), &pb.InspectHostRequest{Name: s.hostName})
	if err != nil {
		t.Fatalf("InspectHost with unreadable reservations: %v, want the host", err)
	}
	if h.GetName() != s.hostName || h.GetFenceStrategy() != "ipmi" || h.GetCpuTotal() != 8 {
		t.Fatalf("host facts missing: name %q fence %q cpu_total %d", h.GetName(), h.GetFenceStrategy(), h.GetCpuTotal())
	}
	e := h.GetReservationsError()
	for _, want := range []string{"op-bad", "invalid character", "op-mismatch", "does not match"} {
		if !strings.Contains(e, want) {
			t.Fatalf("reservations_error = %q, want %q (a cluster-wide reader sees the detail)", e, want)
		}
	}
	if strings.Contains(e, "op-mismatch-far") {
		t.Fatalf("reservations_error = %q names a reservation targeting another host", e)
	}
	if !h.GetReservationsPartial() {
		t.Fatal("reservations_partial = false with reservations_error set")
	}
	got := reservationsByOp(h)
	if len(got) != 11 || got["op-bad"] != nil || got["op-mismatch"] != nil {
		t.Fatalf("listed %d rows %v, want the 11 readable ones and no unreadable one", len(got), got)
	}
	var cpu, mem int32
	for _, r := range h.GetReservations() {
		cpu += r.GetVcpu()
		mem += r.GetMemoryMib()
	}
	if cpu == 0 || cpu != h.GetReservedCpu() || mem != h.GetReservedMemMib() {
		t.Fatalf("partial totals %d/%d, readable rows sum to %d/%d", h.GetReservedCpu(), h.GetReservedMemMib(), cpu, mem)
	}
}

// reservations_error never names a project to a caller who may not read it:
// such a caller sees each unreadable operation's id and a fixed reason.
func TestInspectHost_UnreadableReservationNamesNoProject(t *testing.T) {
	s := testServer(t)
	seedHostReservations(t, s)
	seedUnreadableReservations(t, s)
	other := boundAtCtx(t, s, "vic", "viewer", "Viewer", "/projects/other")

	h, err := s.InspectHost(other, &pb.InspectHostRequest{Name: s.hostName})
	if err != nil {
		t.Fatalf("InspectHost: %v", err)
	}
	b, err := protojson.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"alpha", "beta", "acme", "invalid character"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("viewer at /projects/other: response names %q: %s", leak, h.GetReservationsError())
		}
	}
	e := h.GetReservationsError()
	for _, want := range []string{"op-bad", "op-mismatch", "reservation data unreadable"} {
		if !strings.Contains(e, want) {
			t.Errorf("reservations_error = %q, want %q", e, want)
		}
	}
	if !h.GetReservationsPartial() {
		t.Error("reservations_partial = false with reservations_error set")
	}
}

// The totals are summed from the listed rows, not from a second scan, so they
// agree even while reservations are being added between the reads.
func TestInspectHost_TotalsMatchRowsUnderConcurrentWrites(t *testing.T) {
	s := testServer(t)
	seedHostReservations(t, s)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 150; i++ {
			select {
			case <-stop:
				return
			default:
			}
			id := "op-churn-" + strconv.Itoa(i)
			enc, _ := corrosion.ReservationVector{TargetHost: s.hostName, TargetMemMiB: 1}.Encode()
			if err := corrosion.InsertOperation(context.Background(), s.db, corrosion.OperationRecord{
				ID: id, Method: "ResizeVMLive", ResourceKind: "vm", ResourceID: "vm-churn",
				OperationKind: string(corrosion.OpResourceUpdateRunning), RequestHash: "h", ReservationJSON: enc,
			}); err != nil {
				return
			}
		}
	}()
	defer func() { close(stop); <-done }()
	for i := 0; ; i++ {
		select {
		case <-done:
			return
		default:
		}
		h, err := s.InspectHost(adminCtx(), &pb.InspectHostRequest{Name: s.hostName})
		if err != nil {
			t.Fatalf("InspectHost: %v", err)
		}
		var cpu, mem int32
		for _, r := range h.GetReservations() {
			cpu += r.GetVcpu()
			mem += r.GetMemoryMib()
		}
		if cpu != h.GetReservedCpu() || mem != h.GetReservedMemMib() {
			t.Fatalf("pass %d: rows sum to %d/%d, totals say %d/%d", i, cpu, mem, h.GetReservedCpu(), h.GetReservedMemMib())
		}
	}
}
