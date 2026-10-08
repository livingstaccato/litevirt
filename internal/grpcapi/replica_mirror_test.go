package grpcapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// While a host that cannot answer ListReplicas (main's build) is in the
// cluster, every run that writes a replica into the area also writes main's
// top-level replica of the same data (replica_mirror.go); once every host
// answers, it does not.

// setEveryHostListsReplicas fixes everyHostListsReplicas' answer for s.
func setEveryHostListsReplicas(t *testing.T, s *Server, all bool) {
	t.Helper()
	m := replicaPeersMemoOf(s)
	m.mu.Lock()
	m.at, m.all = time.Now(), all
	m.mu.Unlock()
	t.Cleanup(func() { replicaPeersMemos.Delete(s) })
}

// areaReceiver is a host on this build: it answers ListReplicas, takes
// PushReplica into its area, and records every top-level upload and every
// incremental push with its data.
type areaReceiver struct {
	legacyReceiver
	areaPushes int
	increments []*capturedIncrement
	records    []*pb.ReplicaRecord // the area's, from recorded pushes
}

type capturedIncrement struct {
	hdr  *pb.PushReplicaIncrementRequest
	data map[int64][]byte
}

func (a *areaReceiver) ListReplicas(context.Context, *pb.ListReplicasRequest, ...grpc.CallOption) (*pb.ListReplicasResponse, error) {
	return &pb.ListReplicasResponse{Replicas: a.records}, nil
}

func (a *areaReceiver) PushReplica(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushReplicaRequest, pb.PushReplicaResponse], error) {
	a.areaPushes++
	return &recvStream[pb.PushReplicaRequest, pb.PushReplicaResponse]{on: func(*pb.PushReplicaRequest) {}}, nil
}

func (a *areaReceiver) PushReplicaIncrement(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushReplicaIncrementRequest, pb.PushReplicaIncrementResponse], error) {
	c := &capturedIncrement{data: map[int64][]byte{}}
	a.increments = append(a.increments, c)
	return &recordedIncrementStream{on: func(m *pb.PushReplicaIncrementRequest) {
		if c.hdr == nil {
			c.hdr = m
			if m.GetReplica() == nil {
				a.files = append(a.files, m.GetFilename())
			} else {
				a.records = append(a.records, m.GetReplica())
			}
			return
		}
		c.data[m.GetOffset()] = append([]byte(nil), m.GetData()...)
	}}, nil
}

// recordedIncrementStream answers as this build's receiver does: recorded.
type recordedIncrementStream struct {
	grpc.ClientStream
	on func(*pb.PushReplicaIncrementRequest)
}

func (c *recordedIncrementStream) Send(m *pb.PushReplicaIncrementRequest) error { c.on(m); return nil }
func (c *recordedIncrementStream) CloseAndRecv() (*pb.PushReplicaIncrementResponse, error) {
	return &pb.PushReplicaIncrementResponse{ReplicaRecorded: true}, nil
}

func TestReplicateCrossHost_AlsoWritesMainsReplicaWhileAHostCannotSeeTheArea(t *testing.T) {
	for _, all := range []bool{false, true} {
		f := newPoolFixture(t)
		rcv := &areaReceiver{}
		f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return rcv, func() {}, nil }
		setEveryHostListsReplicas(t, f.s, all)
		ctx := context.Background()
		vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
		disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
		if err := f.s.replicateCrossHost(ctx, corrosion.BackupScheduleRecord{
			VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", KeepReplicas: 3,
		}, vm, &disks[0], "new-host", "20261005-000000"); err != nil {
			t.Fatalf("replicate (every host lists replicas: %v): %v", all, err)
		}
		if rcv.areaPushes != 1 {
			t.Errorf("every host lists replicas: %v: %d replica(s) pushed into the area, want 1", all, rcv.areaPushes)
		}
		switch {
		case !all && (rcv.uploaded == nil || rcv.uploaded.GetFilename() != "web-1-20261005-000000.qcow2" || rcv.uploadData == 0):
			t.Errorf("with a main-build host in the cluster, top-level upload = %+v (%d bytes), want main's web-1-20261005-000000.qcow2 with its data",
				rcv.uploaded, rcv.uploadData)
		case all && rcv.uploaded != nil:
			t.Errorf("every host sees the area, yet main's top-level replica %s was written", rcv.uploaded.GetFilename())
		}
	}
}

func TestReplicateLocal_AlsoWritesMainsReplicaWhileAHostCannotSeeTheArea(t *testing.T) {
	for _, all := range []bool{false, true} {
		f := newPoolFixture(t)
		setEveryHostListsReplicas(t, f.s, all)
		ctx := context.Background()
		vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
		disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
		content := []byte("the run's replica")
		if err := f.s.replicateLocalWith(ctx, corrosion.BackupScheduleRecord{
			VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", KeepReplicas: 3,
		}, vm, &disks[0], "20261005-000000", func(_ context.Context, _, dst string, _ func(*pb.MoveVolumeProgress) error) error {
			return os.WriteFile(dst, content, 0o600)
		}); err != nil {
			t.Fatalf("replicate (every host lists replicas: %v): %v", all, err)
		}
		top := filepath.Join(f.dr, "web-1-20261005-000000.qcow2")
		got, err := os.ReadFile(top)
		switch {
		case !all && (err != nil || !bytes.Equal(got, content)):
			t.Errorf("with a main-build host in the cluster, main's %s holds %q (%v), want the run's replica", filepath.Base(top), got, err)
		case all && err == nil:
			t.Errorf("every host sees the area, yet main's top-level replica %s was written", filepath.Base(top))
		}
		if !all {
			if names := f.s.localReplicaNames(ctx, f.dr, replicaKeyOf(vm, "1"), "", false); len(names) != 1 || names[0] != filepath.Base(top) {
				t.Errorf("web's top-level replicas = %v, want main's copy matched as web's", names)
			}
		}
	}
}

// An incremental run's top-level copy is forked from main's copy of the same
// base run when there is one, and is otherwise the whole disk; either way it
// holds the run's data.
func TestReplicateIncremental_MainsReplicaHoldsTheRunsData(t *testing.T) {
	const size = 4 << 20
	img := func(fill byte, at ...int) []byte {
		b := make([]byte, size)
		for _, mib := range at {
			for i := mib << 20; i < (mib+1)<<20; i++ {
				b[i] = fill
			}
		}
		return b
	}
	run1 := img(0xAA, 0, 2) // full
	run2 := append([]byte(nil), run1...)
	copy(run2[2<<20:3<<20], img(0xBB, 2)[2<<20:3<<20]) // MiB 2 changed
	run3 := append([]byte(nil), run2...)
	copy(run3[0:1<<20], img(0xCC, 0)[0:1<<20]) // MiB 0 changed
	clear(run3[2<<20 : 3<<20])                 // MiB 2 zeroed: a fork must write the zeros

	sched := corrosion.BackupScheduleRecord{
		VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", KeepReplicas: 5, Incremental: true,
	}
	runs := []struct {
		ts      string
		data    []byte
		extents [][2]int64
		all     bool // every host lists replicas: no top-level copy
	}{
		{"20261005-000000", run1, [][2]int64{{0, 1 << 20}, {2 << 20, 1 << 20}}, true},
		{"20261005-010000", run2, [][2]int64{{2 << 20, 1 << 20}}, false},               // no main copy of the base: the whole disk
		{"20261005-020000", run3, [][2]int64{{0, 1 << 20}, {2 << 20, 1 << 20}}, false}, // forked from main's copy of run 2
	}

	t.Run("local", func(t *testing.T) {
		f := newPoolFixture(t)
		ctx := context.Background()
		vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
		disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
		for _, r := range runs {
			replicaPeersMemos.Delete(f.s)
			setEveryHostListsReplicas(t, f.s, r.all)
			rd := &fakeBackupReader{data: r.data, extents: r.extents, incr: true}
			f.s.SetBackupSource(&fakeBackupSource{full: rd, incr: rd})
			if err := f.s.replicateIncremental(ctx, sched, vm, &disks[0], f.s.hostName, r.ts); err != nil {
				t.Fatalf("run %s: %v", r.ts, err)
			}
			got, err := os.ReadFile(filepath.Join(f.dr, "web-1-"+r.ts+".raw"))
			switch {
			case r.all && err == nil:
				t.Errorf("run %s: every host sees the area, yet main's top-level replica was written", r.ts)
			case !r.all && (err != nil || !bytes.Equal(got, r.data)):
				t.Errorf("run %s: main's top-level replica does not hold the run's data (%v)", r.ts, err)
			}
		}
	})

	t.Run("cross-host", func(t *testing.T) {
		f := newPoolFixture(t)
		ctx := context.Background()
		vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
		disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
		rcv := &areaReceiver{}
		f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return rcv, func() {}, nil }
		tops := map[string][]byte{} // main's top-level replicas on the receiver
		for i, r := range runs {
			replicaPeersMemos.Delete(f.s)
			setEveryHostListsReplicas(t, f.s, r.all)
			rcv.increments = nil
			rd := &fakeBackupReader{data: r.data, extents: r.extents, incr: true}
			f.s.SetBackupSource(&fakeBackupSource{full: rd, incr: rd})
			if err := f.s.replicateIncremental(ctx, sched, vm, &disks[0], "new-host", r.ts); err != nil {
				t.Fatalf("run %s: %v", r.ts, err)
			}
			var top *capturedIncrement
			for _, c := range rcv.increments {
				if c.hdr.GetReplica() == nil {
					top = c
				}
			}
			if r.all {
				if top != nil {
					t.Errorf("run %s: every host sees the area, yet main's %s was pushed", r.ts, top.hdr.GetFilename())
				}
				continue
			}
			if top == nil || top.hdr.GetFilename() != "web-1-"+r.ts+".raw" {
				t.Fatalf("run %s: no top-level push of main's web-1-%s.raw (%d pushes)", r.ts, r.ts, len(rcv.increments))
			}
			wantBase := ""
			if i == 2 {
				wantBase = "web-1-" + runs[1].ts + ".raw"
			}
			if top.hdr.GetBase() != wantBase {
				t.Errorf("run %s: top-level push forked from %q, want %q", r.ts, top.hdr.GetBase(), wantBase)
			}
			got := make([]byte, size)
			if b := top.hdr.GetBase(); b != "" {
				copy(got, tops[b])
			}
			for off, d := range top.data {
				copy(got[off:], d)
			}
			tops[top.hdr.GetFilename()] = got
			if !bytes.Equal(got, r.data) {
				t.Errorf("run %s: main's top-level replica would not hold the run's data", r.ts)
			}
		}
	})
}

// The top-level base for an area base is main's name for the same run, and
// only that.
func TestLegacyNameOfAreaReplica(t *testing.T) {
	for _, c := range []struct {
		file, want string
		ok         bool
	}{
		{"1-20261005-000000.raw", "web-1-20261005-000000.raw", true},
		{"1-20261005-000000.qcow2", "", false},
		{"2-20261005-000000.raw", "", false},
		{"1-latest.raw", "", false},
	} {
		got, ok := legacyNameOfAreaReplica("web", "1", c.file)
		if got != c.want || ok != c.ok {
			t.Errorf("legacyNameOfAreaReplica(web, 1, %s) = %q, %v; want %q, %v", c.file, got, ok, c.want, c.ok)
		}
	}
}
