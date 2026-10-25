package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// NB-R13: a start record whose domain libvirt no longer knows (not found) is
// dropped by the sweep: that start has ended, and the record would otherwise
// outlive it for good. (A row naming another host, or a row that is gone,
// keeps the record and names the paused domain: review m2, F7 m2.)
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
				// As libvirt.Client wraps it (domain.go): VIR_ERR_NO_DOMAIN.
				return fmt.Errorf("lookup domain %s: %w", name,
					golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: "Domain not found: no domain with matching name '" + name + "'"})
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
// removed by the sweep, not kept for ever beside the records; a real record
// beside it is left alone (review M4).
//
// Mutations: no removal — red; removing every file — red.
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
	if err := s.markStartPaused("vm1"); err != nil {
		t.Fatal(err)
	}
	s.removeHalfWrittenStartRecords()
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("the half-written record is still there: %v", err)
	}
	if marked, err := s.startPausedMarked("vm1"); !marked || err != nil {
		t.Fatalf("a real record went with the temp files: %v, %v", marked, err)
	}
	if err := os.WriteFile(tmp, []byte("vm1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.ResumeStrandedStarts(context.Background())
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("the sweep left the half-written record: %v", err)
	}
}

// Only libvirt's own VIR_ERR_NO_DOMAIN drops a record (review I1): any other
// failure to read the domain's state — a dropped connection, a driver error
// that happens to say "not found" — keeps it, since the domain may still be
// paused and need its start finished.
//
// Mutation: drop records on lv.IsNotFound (its text fallback) — red.
func TestResumeStrandedStarts_KeepsTheRecordOnAnyOtherStateError(t *testing.T) {
	s, fake := vlanStartServer(t)
	fake.SetState("vm1", libvirtfake.StatePaused)
	if err := s.markStartPaused("vm1"); err != nil {
		t.Fatal(err)
	}
	fake.FailDomainStateReason = func(string) error {
		return errors.New("internal error: storage driver not found for the connection")
	}
	s.ResumeStrandedStarts(context.Background())
	if marked, _ := s.startPausedMarked("vm1"); !marked {
		t.Fatal("a state error that only says \"not found\" dropped the record of a domain that may still be paused")
	}
}

// A record that holds no uuid (its domain's definition could not be read when
// the start was recorded) is never resumed by, whatever the domain here
// reports — even a domain whose own uuid cannot be read either — and the
// condition says the record holds no readable uuid (review M1, M2).
//
// Mutations: drop the want == "" guard — red; the old "another incarnation"
// text for it — red.
func TestResumeStrandedStarts_ARecordWithNoUUIDIsNeverResumed(t *testing.T) {
	s, fake := vlanStartServer(t)
	ctx := adminCtx()
	if err := corrosion.UpdateVMState(ctx, s.db, "vm1", "running", ""); err != nil {
		t.Fatal(err)
	}
	fake.SetState("vm1", libvirtfake.StatePaused) // no definition: no uuid either side
	if err := s.markStartPaused("vm1"); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.startPausedUUID("vm1"); u != "" {
		t.Fatalf("the record holds uuid %q, want none for this test", u)
	}
	s.ResumeStrandedStarts(context.Background())
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Fatalf("a record with no uuid was resumed: %v", st)
	}
	c, ok, err := corrosion.GetHealthCondition(ctx, s.db, StrandedStartEvaluator, CondStrandedStartPaused, "vm", "vm1@"+s.hostName)
	if err != nil || !ok || !strings.Contains(c.Evidence, "no readable") {
		t.Fatalf("condition %+v (found %v, %v): want it raised, saying the record holds no readable uuid", c, ok, err)
	}
}

// A domain something else holds (partition pause) is not reported as a
// stranded start even when its record names another incarnation: the hold
// checks come first (review M3). It is never resumed either way.
//
// Mutation: the uuid refusal before the hold checks — red (a condition).
func TestResumeStrandedStarts_AHeldDomainIsNotReportedForAUUIDMismatch(t *testing.T) {
	s, fake := vlanStartServer(t)
	ctx := adminCtx()
	if err := corrosion.UpdateVMState(ctx, s.db, "vm1", "running", ""); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(`<domain type='kvm'><name>vm1</name><uuid>11111111-1111-1111-1111-111111111111</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := s.markStartPaused("vm1"); err != nil {
		t.Fatal(err)
	}
	fake.SetState("vm1", libvirtfake.StateShutdown)
	if err := fake.UndefineDomain("vm1", false); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(`<domain type='kvm'><name>vm1</name><uuid>22222222-2222-2222-2222-222222222222</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	fake.SetState("vm1", libvirtfake.StatePaused)
	if err := fake.MarkPartitionPaused("vm1", "tok-1"); err != nil {
		t.Fatal(err)
	}
	s.ResumeStrandedStarts(context.Background())
	if st, _ := fake.RawState("vm1"); st != libvirtfake.StatePaused {
		t.Fatalf("resumed: %v", st)
	}
	if c, ok, _ := corrosion.GetHealthCondition(ctx, s.db, StrandedStartEvaluator, CondStrandedStartPaused, "vm", "vm1@"+s.hostName); ok {
		t.Fatalf("a partition-paused domain was reported as a stranded start: %+v", c)
	}
}
