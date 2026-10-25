package grpcapi

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// NB-R13: a start record whose domain libvirt no longer knows (not found), or
// whose VM row is gone or names another host, is dropped by the sweep: that
// start can never be finished here, and the record would otherwise outlive it
// for good.
func TestResumeStrandedStarts_DropsARecordWithNothingToFinish(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, s *Server, fake *libvirtfake.Fake){
		"domain not found": func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			// Its row still names this host; libvirt has no such domain.
			if err := s.markStartPaused("vm1"); err != nil {
				t.Fatal(err)
			}
			if err := fake.UndefineDomain("vm1", false); err != nil {
				t.Fatal(err)
			}
			// libvirt's answer for a domain it does not know (the fake's own
			// answer for one is "unknown", which other tests rely on).
			fake.FailDomainStateReason = func(name string) error {
				return fmt.Errorf("lookup domain %s: Domain not found: no domain with matching name '%s'", name, name)
			}
		},
		"row gone": func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			fake.SetState("vm1", libvirtfake.StatePaused)
			if err := s.markStartPaused("vm1"); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.DeleteVM(adminCtx(), s.db, "vm1"); err != nil {
				t.Fatal(err)
			}
		},
		"row names another host": func(t *testing.T, s *Server, fake *libvirtfake.Fake) {
			fake.SetState("vm1", libvirtfake.StatePaused)
			if err := s.markStartPaused("vm1"); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.UpdateVMHost(adminCtx(), s.db, "vm1", "elsewhere", "running"); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, fake := vlanStartServer(t)
			setup(t, s, fake)
			s.ResumeStrandedStarts(context.Background())
			for _, vm := range []string{"vm1"} {
				if marked, _ := s.startPausedMarked(vm); marked {
					t.Fatalf("the record of %s outlived a start that can never be finished here", vm)
				}
			}
			if st, _ := fake.RawState("vm1"); st == libvirtfake.StateRunning {
				t.Fatal("the sweep resumed vm1")
			}
		})
	}
}

// NB-R14: the record names the incarnation it paused (the domain's uuid); a
// same-name domain with another uuid — the VM was deleted and created again,
// or its record is older than this domain — is not that start, and is never
// resumed by it.
func TestResumeStrandedStarts_RefusesAnotherIncarnation(t *testing.T) {
	s, fake := vlanStartServer(t)
	if err := corrosion.UpdateVMState(adminCtx(), s.db, "vm1", "running", ""); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(`<domain type='kvm'><name>vm1</name><uuid>11111111-1111-1111-1111-111111111111</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	fake.SetState("vm1", libvirtfake.StatePaused)
	if err := s.markStartPaused("vm1"); err != nil {
		t.Fatal(err)
	}
	// The VM deleted and created again under its name: a new incarnation.
	fake.SetState("vm1", libvirtfake.StateShutdown)
	if err := fake.UndefineDomain("vm1", false); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(`<domain type='kvm'><name>vm1</name><uuid>22222222-2222-2222-2222-222222222222</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	fake.SetState("vm1", libvirtfake.StatePaused)
	s.ResumeStrandedStarts(context.Background())
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Fatalf("the sweep resumed a domain of another uuid than its record's: %v", st)
	}
}

// NB-R15: a record that cannot be written is an error in the log, not a
// warning: a guest of that start, should the daemon die before its resume,
// is left paused with nothing to find it.
func TestNICStartGuard_ARecordThatCannotBeWrittenLogsAnError(t *testing.T) {
	s, fake := vlanStartServer(t)
	if err := os.WriteFile(filepath.Join(s.dataDir, startPausedDir), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)
	_, _ = s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "vm1"})
	_ = fake
	var line string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, "could not record a paused start") {
			line = l
		}
	}
	if !strings.Contains(line, "level=ERROR") {
		t.Fatalf("the failed record write was logged as %q, want level=ERROR", line)
	}
}

// NB-R17: a half-written record (.tmp-*, a write the daemon died in) is
// removed by the sweep, not kept for ever beside the records.
func TestResumeStrandedStarts_RemovesHalfWrittenRecords(t *testing.T) {
	s, _ := vlanStartServer(t)
	dir := filepath.Join(s.dataDir, startPausedDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, ".tmp-12345")
	if err := os.WriteFile(tmp, []byte("vm1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.ResumeStrandedStarts(context.Background())
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("the half-written record is still there: %v", err)
	}
}
