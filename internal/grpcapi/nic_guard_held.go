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
	"regexp"
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
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/safename"
)

// CondFirewallHeld: a guest this host holds paused because its NIC guards are
// not in force here yet (critical: the workload is down).
const CondFirewallHeld = "firewall.nic.held"

// heldGuestDir is the record directory under the daemon's data dir.
const heldGuestDir = "nic-guard-held"

// heldStaleAfter is how long a record for a guest that never arrived here is
// kept while its move may still be running: the record is written before the
// row says `migrating`. Longer than any live migration may run
// (adoptedMigrationCeiling). It only ever drops a record that can resume
// nothing; it never lets one resume anything (re-review m3).
var heldStaleAfter = 2 * time.Hour

// heldGuest is one guest this host holds, or will hold, paused for its NIC
// guards. A file, not a table: it is a statement about what this host does
// to its own runtime, which must survive a restart and is no other host's.
//
// A record is the move's, not the name's (re-review m3): it is bound to the
// incarnation the move carried (its spec uuid, which is the domain's uuid,
// and its row's created_at), and it ends when the move does — when the
// guest it held runs, and when anything else brings the VM's domain here: a
// start of it here (the start guard), or another move's arming.
type heldGuest struct {
	VM        string `json:"vm"`
	UUID      string `json:"uuid,omitempty"`       // the VM's incarnation (spec uuid = domain uuid)
	CreatedAt string `json:"created_at,omitempty"` // the incarnation's row created_at
	Source    string `json:"source,omitempty"`
	Since     string `json:"since"` // RFC3339, when the move announced it
	// Uncommitted: the source told this host the guest arrived but the
	// move's ownership commit failed (re-review m4).
	Uncommitted bool `json:"uncommitted,omitempty"`
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
		g.CreatedAt = rec.CreatedAt
	}
	heldMu.Lock()
	defer heldMu.Unlock()
	return s.putHeld(g)
}

// endHeld drops vm's held record, if any: its domain comes here by another
// way than the move that wrote it (a start here, another move), so the
// record has nothing left to resume (re-review m3).
func (s *Server) endHeld(vm, why string) {
	heldMu.Lock()
	defer heldMu.Unlock()
	if _, ok, err := s.getHeld(vm); err != nil || !ok {
		return
	}
	if err := s.removeHeld(vm); err != nil {
		slog.Warn("NIC guard: could not drop a held-guest record", "vm", vm, "why", why, "error", err)
		return
	}
	slog.Info("NIC guard: dropped the record of an earlier hand-over", "vm", vm, "why", why)
}

// markHeldUncommitted records that the guest held for vm's hand-over
// arrived while its move's ownership commit failed
// (ArmNICFirewall{handover_uncommitted}, re-review m4).
func (s *Server) markHeldUncommitted(vm string) error {
	heldMu.Lock()
	defer heldMu.Unlock()
	g, ok, err := s.getHeld(vm)
	if err != nil || !ok {
		return err
	}
	g.Uncommitted = true
	return s.putHeld(g)
}

// domainOfIncarnation reports whether vm's domain here is the incarnation g
// was written for: its domain uuid is g's spec uuid, when both are known.
func (s *Server) domainOfIncarnation(vm string, g heldGuest) bool {
	if !isUUID(g.UUID) {
		return true
	}
	x, err := s.virt.DumpXML(vm)
	if err != nil {
		return true // the state check that follows decides
	}
	got := lv.UUIDFromXML(x)
	return got == "" || got == strings.ToLower(g.UUID)
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func isUUID(s string) bool { return uuidPattern.MatchString(s) }

// errNotHeld: the guest is not one this host holds paused for its guards.
var errNotHeld = errors.New("not held")

// errFirmwareMoveHeld: a live firmware move holds the guest here until its
// state verifies; only that move's release resumes it (spec §6.9, I5).
var errFirmwareMoveHeld = errors.New("held for firmware verification")

// firmwareMoveHeld is nil when no live firmware move holds vm on this host,
// else an errFirmwareMoveHeld naming the attempt and its source. A hold that
// cannot be read holds too.
func (s *Server) firmwareMoveHeld(vm string) error {
	h, ok, err := s.fwRecords().GetHold(vm)
	switch {
	case err != nil:
		return fmt.Errorf("%w: its live firmware move hold on %s cannot be read, so it is not resumed: %v", errFirmwareMoveHeld, s.hostName, err)
	case !ok:
		return nil
	}
	return fmt.Errorf("%w of attempt %s from %s (hold %s); only that move's release resumes it",
		errFirmwareMoveHeld, h.Attempt, h.Source, h.State)
}

// resumeHeld lets vm, held paused here for its guards or its tap VLANs, run:
// it puts its NIC firewall in force and its NICs' VLANs on its taps
// (readyGuestHere, which refuses while either is not), then resumes the
// domain, then drops the record. A guest already running is
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
	if err := s.firmwareMoveHeld(vm); err != nil {
		return err
	}
	if !s.domainOfIncarnation(vm, g) {
		// Not the domain the move carried: never resumed by its record. Kept
		// and reported, not dropped: a guest nothing resumes must be seen.
		return fmt.Errorf("its domain here is not the incarnation its move carried (domain uuid is not %s), "+
			"so its hand-over record does not resume it", g.UUID)
	}
	st, err := s.virt.DomainStateReason(vm)
	if err != nil || st.Reason != "paused" {
		if err == nil && st.State == "running" {
			_ = s.removeHeld(vm) // it runs: nothing is held
			return nil
		}
		return errNotHeld
	}
	if _, paused, perr := health.ReadPauseRecord(s.dataDir, health.PauseKindVM, vm); paused || perr != nil {
		// Partition pause holds it too: that is its pauser's to resume. A
		// pause state this host cannot read is held the same way.
		if perr != nil {
			return fmt.Errorf("%s: its partition-pause state is unreadable (%v), so it is held paused", vm, perr)
		}
		return fmt.Errorf("%s is also paused for a partition (partition pause); it resumes when the partition does", vm)
	}
	if err := s.readyGuestHere(ctx, vm); err != nil {
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
	var held, fwHeld []string
	for _, g := range gs {
		why, firmware := s.resumeHeldGuest(ctx, g)
		switch {
		case why == "":
		case firmware:
			fwHeld = append(fwHeld, why)
		default:
			held = append(held, why)
		}
	}
	var parts []string
	if len(held) > 0 {
		parts = append(parts, "guests held paused because their NIC guards are not in force here: "+strings.Join(held, "; ")+
			". Each resumes by itself once its guards are in force here")
	}
	if len(fwHeld) > 0 {
		parts = append(parts, "guests a live firmware move holds paused here: "+strings.Join(fwHeld, "; ")+
			". Each resumes only when its move releases it")
	}
	s.setFirewallCondition(ctx, CondFirewallHeld, len(parts) > 0, corrosion.SeverityCritical, strings.Join(parts, ". "))
}

// resumeHeldGuest handles one record, returning why its guest stays held
// ("" when it does not), and whether a live firmware move is what holds it.
// A record whose guest is paused here is reported for as long as it is
// (re-review m4), whatever stops this host resuming it.
func (s *Server) resumeHeldGuest(ctx context.Context, g heldGuest) (why string, firmware bool) {
	why = s.resumeHeldGuestWhy(ctx, g, &firmware)
	return why, firmware
}

func (s *Server) resumeHeldGuestWhy(ctx context.Context, g heldGuest, firmware *bool) string {
	stale := func() bool {
		t, err := time.Parse(time.RFC3339, g.Since)
		return err != nil || time.Since(t) > heldStaleAfter
	}
	exists := s.virt.DomainExists(g.VM)
	pausedHere := func() (bool, string) {
		st, err := s.virt.DomainStateReason(g.VM)
		if err != nil {
			return true, "its state here cannot be read: " + err.Error()
		}
		return st.Reason == "paused", ""
	}
	held := func(why string) string {
		return fmt.Sprintf("%s (since %s: %s; once its guards are in force, `lv firewall nic-guard resume %s`; "+
			"or stop and start it, which reboots the guest)", g.VM, g.Since, why, g.VM)
	}
	vm, err := corrosion.GetVM(ctx, s.db, g.VM)
	switch {
	case err != nil:
		if !exists {
			return ""
		}
		if p, why := pausedHere(); p {
			if why == "" {
				why = "its VM row cannot be read: " + err.Error()
			}
			return held(why)
		}
		return ""
	case vm == nil || (g.UUID != "" && specUUID(vm.Spec) != "" && specUUID(vm.Spec) != g.UUID) ||
		(g.CreatedAt != "" && vm.CreatedAt != "" && vm.CreatedAt != g.CreatedAt):
		_ = s.removeHeld(g.VM) // deleted, or another incarnation
		return ""
	case vm.HostName != s.hostName:
		if !exists {
			// Not arrived (the move still runs, or failed): nothing here to
			// resume, and the record is dropped once no move can be running.
			if stale() && vm.State != "migrating" {
				_ = s.removeHeld(g.VM)
			}
			return ""
		}
		p, why := pausedHere()
		if !p {
			_ = s.removeHeld(g.VM) // it runs here: nothing is held
			return ""
		}
		if why == "" && !g.Uncommitted && vm.State == "migrating" && !stale() {
			return "" // the move is still under way
		}
		if ferr := s.firmwareMoveHeld(g.VM); ferr != nil {
			// A live firmware move holds it: its source decides from Verify
			// whether it commits here. Writing its owner here first is
			// never the way out.
			*firmware = true
			return fmt.Sprintf("%s (since %s: %v)", g.VM, g.Since, ferr)
		}
		if why == "" {
			why = fmt.Sprintf("it arrived here paused, but its move's ownership commit is not recorded (the VM's row names %s), "+
				"so this host does not resume it: `lv doctor repair-owner %s %s` records it here", vm.HostName, g.VM, s.hostName)
		}
		return fmt.Sprintf("%s (since %s: %s; it then resumes here once its guards are in force)", g.VM, g.Since, why)
	}
	if !exists {
		if stale() {
			_ = s.removeHeld(g.VM)
		}
		return ""
	}
	p, why := pausedHere()
	if why != "" {
		return held(why)
	}
	if !p {
		_ = s.removeHeld(g.VM) // running, or stopped: nothing is held
		return ""
	}
	if err := s.resumeHeld(ctx, g.VM); err != nil && !errors.Is(err, errNotHeld) {
		if errors.Is(err, errFirmwareMoveHeld) {
			// Its guards are not what holds it: the record stays for the
			// move's release to drop.
			*firmware = true
			return fmt.Sprintf("%s (since %s: %v)", g.VM, g.Since, err)
		}
		return held(err.Error())
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
	if err := s.firmwareMoveHeld(vm.Name); err != nil {
		s.audit(ctx, "vm.resume-held", vm.Name, "error: "+err.Error(), "error")
		return nil, status.Errorf(codes.FailedPrecondition, "%s stays paused: %v", vm.Name, err)
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
