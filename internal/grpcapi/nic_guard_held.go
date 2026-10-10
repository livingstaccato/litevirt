package grpcapi

// Guests held paused for their NIC guards (re-review R3-I2).
//
// A guarded NIC whose domain an older release defined has a tap libvirt names
// only at start (vnetN), so a live move hands such a guest over paused and the
// target lets it run once its guards are in force under the taps it got there
// (ArmNICFirewall{resume}). The target owns that resume: the arming before the
// move tells it the guest will arrive paused, and it records so on its own
// disk. Whether or not the source's resume arrives — a dropped connection, a
// target daemon restart, an arm that ran out of time — the target lets the
// guest run as soon as its guards are in force, raises a critical condition
// while it holds it, and `lv firewall nic-guard resume` does the same on an
// operator's word.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/safename"
)

// CondFirewallHeld: a guest this host holds paused because its NIC guards are
// not in force here yet (critical: the workload is down).
const CondFirewallHeld = "firewall.nic.held"

// heldGuestDir is the record directory under the daemon's data dir.
const heldGuestDir = "nic-guard-held"

// heldStaleAfter is how long a record for a guest that never arrived here (a
// move that failed, or still runs) is kept. Longer than any live migration
// may run (adoptedMigrationCeiling).
var heldStaleAfter = 2 * time.Hour

// heldGuest is one guest this host holds, or will hold, paused for its NIC
// guards. A file, not a table: it is a statement about what this host does
// to its own runtime, which must survive a restart and is no other host's.
type heldGuest struct {
	VM     string `json:"vm"`
	UUID   string `json:"uuid,omitempty"` // the VM's incarnation (spec uuid)
	Source string `json:"source,omitempty"`
	Since  string `json:"since"` // RFC3339, when the move announced it
}

func heldPath(dataDir, vm string) (string, error) {
	if err := safename.ValidateVMName(vm); err != nil {
		return "", err
	}
	return filepath.Join(dataDir, heldGuestDir, vm+".json"), nil
}

// putHeld records g durably (temp file, fsync, rename, directory fsync).
func (s *Server) putHeld(g heldGuest) error {
	if s.dataDir == "" {
		return errors.New("no data directory to record a held guest in")
	}
	p, err := heldPath(s.dataDir, g.VM)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(g)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(p)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return err
	}
	return syncDirPath(dir)
}

// removeHeld drops vm's record; absent is success.
func (s *Server) removeHeld(vm string) error {
	if s.dataDir == "" {
		return nil
	}
	p, err := heldPath(s.dataDir, vm)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return syncDirPath(filepath.Dir(p))
}

// getHeld reads vm's record; ok is false when there is none.
func (s *Server) getHeld(vm string) (heldGuest, bool, error) {
	if s.dataDir == "" {
		return heldGuest{}, false, nil
	}
	p, err := heldPath(s.dataDir, vm)
	if err != nil {
		return heldGuest{}, false, err
	}
	return readHeld(p)
}

// listHeld is every record, sorted by VM. One that does not parse is an
// error, not a skip: a skipped record is a guest nothing will let run.
func (s *Server) listHeld() ([]heldGuest, error) {
	if s.dataDir == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(filepath.Join(s.dataDir, heldGuestDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []heldGuest
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		g, ok, err := readHeld(filepath.Join(s.dataDir, heldGuestDir, e.Name()))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VM < out[j].VM })
	return out, nil
}

func readHeld(path string) (heldGuest, bool, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return heldGuest{}, false, nil
	}
	if err != nil {
		return heldGuest{}, false, err
	}
	var g heldGuest
	if err := json.Unmarshal(b, &g); err != nil || g.VM == "" {
		return heldGuest{}, false, fmt.Errorf("corrupt held-guest record %s: %v", path, err)
	}
	return g, true, nil
}

func syncDirPath(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// HeldGuestsForTests lists the VMs this host holds a record for.
func (s *Server) HeldGuestsForTests() []string {
	gs, _ := s.listHeld()
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.VM)
	}
	return out
}

// heldMu serializes resuming held guests: the source's resume, the resumer
// loop and the operator's command may all reach one guest at once.
var heldMu sync.Mutex

// holdForHandOver records that vm will arrive here paused for its guards
// (ArmNICFirewall{paused_handover}).
func (s *Server) holdForHandOver(ctx context.Context, vm, source string) error {
	g := heldGuest{VM: vm, Source: source, Since: time.Now().UTC().Format(time.RFC3339)}
	if rec, err := corrosion.GetVM(ctx, s.db, vm); err == nil && rec != nil {
		g.UUID = specUUID(rec.Spec)
	}
	return s.putHeld(g)
}

// errNotHeld: the guest is not one this host holds paused for its guards.
var errNotHeld = errors.New("not held")

// resumeHeld lets vm, held paused here for its guards, run: it puts its NIC
// firewall in force (ArmNICsFor, which refuses while a guard is not), then
// resumes the domain, then drops the record. A guest already running is
// done. It returns errNotHeld when this host holds no record for vm, or the
// domain is not paused here.
func (s *Server) resumeHeld(ctx context.Context, vm string) error {
	heldMu.Lock()
	defer heldMu.Unlock()
	g, ok, err := s.getHeld(vm)
	if err != nil {
		return err
	}
	if !ok {
		return errNotHeld
	}
	st, err := s.virt.DomainStateReason(vm)
	if err != nil || st.Reason != "paused" {
		if err == nil && st.State == "running" {
			_ = s.removeHeld(vm) // it runs: nothing is held
			return nil
		}
		return errNotHeld
	}
	if _, paused, _ := health.ReadPauseRecord(s.dataDir, health.PauseKindVM, vm); paused {
		// Partition pause holds it too: that is its pauser's to resume.
		return fmt.Errorf("%s is also paused for a partition (partition pause); it resumes when the partition does", vm)
	}
	actx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = s.ArmNICsFor(actx, vm)
	cancel()
	if err != nil {
		return err
	}
	r, ok := s.virt.(interface{ ResumeDomain(string) error })
	if !ok {
		return errors.New("this host cannot resume a domain")
	}
	if err := r.ResumeDomain(vm); err != nil {
		return fmt.Errorf("resume %s: %w", vm, err)
	}
	if err := s.removeHeld(vm); err != nil {
		slog.Warn("NIC guard: resumed a held guest but could not drop its record", "vm", vm, "error", err)
	}
	slog.Info("NIC guard: a guest held paused for its guards runs, its guards in force", "vm", vm, "from", g.Source)
	return nil
}

// ResumeHeldGuestsOnce goes over the guests this host holds: each one owned
// here and paused is let run once its guards are in force; a record whose
// guest runs, or was stopped, is dropped; one for a guest that never arrived
// is dropped after heldStaleAfter. While any guest stays held,
// firewall.nic.held names it.
func (s *Server) ResumeHeldGuestsOnce(ctx context.Context) {
	gs, err := s.listHeld()
	if err != nil {
		s.setFirewallCondition(ctx, CondFirewallHeld, true, corrosion.SeverityCritical,
			"the records of guests held paused for their NIC guards cannot be read: "+err.Error())
		return
	}
	var held []string
	for _, g := range gs {
		if why := s.resumeHeldGuest(ctx, g); why != "" {
			held = append(held, why)
		}
	}
	text := ""
	if len(held) > 0 {
		text = "guests held paused because their NIC guards are not in force here: " + strings.Join(held, "; ") +
			". Each resumes by itself once its guards are in force here"
	}
	s.setFirewallCondition(ctx, CondFirewallHeld, len(held) > 0, corrosion.SeverityCritical, text)
}

// resumeHeldGuest handles one record, returning why its guest stays held
// ("" when it does not).
func (s *Server) resumeHeldGuest(ctx context.Context, g heldGuest) string {
	stale := func() bool {
		t, err := time.Parse(time.RFC3339, g.Since)
		return err != nil || time.Since(t) > heldStaleAfter
	}
	vm, err := corrosion.GetVM(ctx, s.db, g.VM)
	switch {
	case err != nil:
		return ""
	case vm == nil || (g.UUID != "" && specUUID(vm.Spec) != "" && specUUID(vm.Spec) != g.UUID):
		_ = s.removeHeld(g.VM) // deleted, or another incarnation
		return ""
	case vm.HostName != s.hostName:
		// The move has not committed (or failed): nothing here to resume.
		if stale() {
			_ = s.removeHeld(g.VM)
		}
		return ""
	}
	if !s.virt.DomainExists(g.VM) {
		if stale() {
			_ = s.removeHeld(g.VM)
		}
		return ""
	}
	st, err := s.virt.DomainStateReason(g.VM)
	if err != nil {
		return ""
	}
	if st.Reason != "paused" {
		_ = s.removeHeld(g.VM) // running, or stopped: nothing is held
		return ""
	}
	if err := s.resumeHeld(ctx, g.VM); err != nil && !errors.Is(err, errNotHeld) {
		return fmt.Sprintf("%s (since %s: %v; once its guards are in force, `lv firewall nic-guard resume %s`; "+
			"or stop and start it, which reboots the guest)", g.VM, g.Since, err, g.VM)
	}
	return ""
}

// RunHeldGuestResumer runs ResumeHeldGuestsOnce every interval until ctx ends.
func (s *Server) RunHeldGuestResumer(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 10 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		s.ResumeHeldGuestsOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ResumeHeldVM lets a guest its host holds paused for its NIC guards run,
// its guards in force first (`lv firewall nic-guard resume`). It refuses a
// guest that is not held, and one whose guards still cannot be put in force.
func (s *Server) ResumeHeldVM(ctx context.Context, req *pb.ResumeHeldVMRequest) (*emptypb.Empty, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.GetVmName())
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.GetVmName())
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.start", "operator"); err != nil {
		return nil, err
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.ResumeHeldVM(ctx, req)
	}
	err = s.resumeHeld(ctx, vm.Name)
	switch {
	case errors.Is(err, errNotHeld):
		return nil, status.Errorf(codes.FailedPrecondition, "%s is not held paused for its NIC guards on %s", vm.Name, s.hostName)
	case err != nil:
		s.audit(ctx, "vm.resume-held", vm.Name, "error: "+err.Error(), "error")
		return nil, status.Errorf(codes.FailedPrecondition, "%s stays paused: %v", vm.Name, err)
	}
	s.audit(ctx, "vm.resume-held", vm.Name, "guards in force; resumed", "ok")
	s.ResumeHeldGuestsOnce(ctx) // the condition follows
	return &emptypb.Empty{}, nil
}
