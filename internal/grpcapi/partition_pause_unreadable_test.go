package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// corruptPauseRecord leaves a partition-pause record for vm that cannot be
// read, as a torn write or a failing disk does.
func corruptPauseRecord(t *testing.T, dataDir, vm string) {
	t.Helper()
	dir := filepath.Join(dataDir, "partition-pause")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vm-"+vm+".json"), []byte(`{"kind":"vm","na`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A partition-pause state this host cannot read is held: the source's resume
// fallback leaves the guest paused rather than reading the unreadable record
// as "not paused for a partition".
//
// Mutation: ignore ReadPauseRecord's error in ArmNICFirewall — the guest is
// resumed and this goes red.
func TestArmNICFirewall_ResumeFallbackHoldsOnAnUnreadablePauseRecord(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	s.dataDir = t.TempDir()
	virt := libvirtfake.New()
	s.virt = virt
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1", HostName: s.hostName, State: "running",
		Spec: `{"name":"vm1","uuid":"u-vm1"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	virt.SetState("vm1", libvirtfake.StatePaused)
	corruptPauseRecord(t, s.dataDir, "vm1")
	_, err := s.ArmNICFirewall(peerCtxFor(t, s, "src"), &pb.ArmNICFirewallRequest{VmName: "vm1", Resume: true})
	if st, _ := virt.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Errorf("a guest whose partition-pause state is unreadable was resumed: %s (err %v)", st, err)
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err = %v, want FailedPrecondition", err)
	}
}

// The same for a guest this host holds for its NIC guards: an unreadable
// partition-pause record keeps it paused.
//
// Mutation: ignore ReadPauseRecord's error in resumeHeld — the guest runs and
// this goes red.
func TestResumeHeldGuests_HoldsOnAnUnreadablePauseRecord(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	s.dataDir = t.TempDir()
	virt := libvirtfake.New()
	s.virt = virt
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "split", HostName: s.hostName, State: "running",
		Spec: `{"name":"split","uuid":"u-split"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	virt.SetInactiveXML("split", `<domain type='kvm'><name>split</name></domain>`)
	virt.SetState("split", libvirtfake.StatePaused)
	if err := s.putHeld(heldGuest{VM: "split", UUID: "u-split", Since: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	corruptPauseRecord(t, s.dataDir, "split")
	s.ResumeHeldGuestsOnce(ctx)
	if st, _ := virt.RawState("split"); st != libvirtfake.StatePaused {
		t.Errorf("a held guest whose partition-pause state is unreadable was resumed: %s", st)
	}
}
