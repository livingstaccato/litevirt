package grpcapi

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// A live restore is a recovery path main allowed: invalid disk/NIC tuning in
// the spec it restores is dropped, with a warning naming each dropped key,
// and the restore goes ahead after the latch as before it. The valid tuning
// is kept under the feature's grant.
//
// Mutation: refuse an invalid value in restrictRestoredTuning (as before) —
// the restore never starts and writes no row.
func TestRestoreLive_InvalidTuningIsDroppedNotRefused(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.virt = libvirtfake.New()
	s.SetReleaseFeatureGate(ioGate{t: t, on: true})
	logs := captureSlog(t)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Cpu: 2, MemoryMib: 2048, Machine: "q35", Firmware: "uefi",
		Disks:   []*pb.DiskSpec{{Name: "root", Bus: "virtio", Io: &pb.DiskIOLimits{ReadIopsSec: 321}}},
		Network: []*pb.NetworkAttachment{{Name: "lo", Model: "virtio", Queues: 4096}}})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-a", State: "stopped", Spec: string(spec)}, nil, nil); err != nil {
		t.Fatal(err)
	}
	repoDir, ts := seedLiveRepo(t, make([]byte, pbsstore.ChunkSize), "")
	_, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts, FromExisting: true, NewName: "vm2",
		TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
	}, pb.RestoreLiveProgress_STARTED)
	row, _ := corrosion.GetVM(context.Background(), s.db, "vm2")
	cancel()
	err := <-done
	if row == nil {
		t.Fatalf("the restore with invalid tuning wrote no row (restore: %v)", err)
	}
	var got pb.VMSpec
	_ = json.Unmarshal([]byte(row.Spec), &got)
	if len(got.Network) != 1 || got.Network[0].Queues != 0 {
		t.Errorf("restored NICs %+v; want the invalid queues dropped", got.Network)
	}
	if len(got.Disks) != 1 || got.Disks[0].Io.GetReadIopsSec() != 321 {
		t.Errorf("restored disks %+v; want the valid disk tuning kept", got.Disks)
	}
	if out := logs.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "network 0 queues") {
		t.Errorf("no warning naming the dropped key:\n%s", out)
	}
}
