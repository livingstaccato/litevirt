package daemon

import (
	"errors"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/litevirt/litevirt/internal/libvirt"
)

type vtpmReport struct {
	open     bool
	evidence map[string]any
}

type vtpmHarness struct {
	mu      sync.Mutex
	calls   []bool
	reports []vtpmReport
}

func (h *vtpmHarness) snapshot() ([]bool, []vtpmReport) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]bool(nil), h.calls...), append([]vtpmReport(nil), h.reports...)
}

func newTestVTPMSync(on bool, states ...libvirt.SwtpmSyncReport) (*vtpmStateSync, *vtpmHarness) {
	h := &vtpmHarness{}
	i := 0
	v := &vtpmStateSync{
		on:   on,
		base: "/var/lib/libvirt/swtpm",
		wait: 5 * time.Second,
		sync: func(on bool) libvirt.SwtpmSyncReport {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.calls = append(h.calls, on)
			r := states[i]
			if i < len(states)-1 {
				i++
			}
			return r
		},
		report: func(open bool, evidence map[string]any) bool {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.reports = append(h.reports, vtpmReport{open, evidence})
			return true
		},
	}
	return v, h
}

func TestVTPMStateSync_UnsupportedRaisesTheConditionOnce(t *testing.T) {
	unsup := libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncUnsupported, Base: "/var/lib/libvirt/swtpm", FS: "tmpfs",
		Err: errors.New("operation not supported")}
	v, h := newTestVTPMSync(true, unsup)
	if !v.probe(true) || !v.probe(true) {
		t.Fatal("a pass that completed did not make the host vTPM-capable")
	}
	calls, reports := h.snapshot()
	if len(calls) != 2 || !calls[0] {
		t.Fatalf("sync calls %v, want two passes with on=true", calls)
	}
	if len(reports) != 1 {
		t.Fatalf("reports %+v, want the condition written once", reports)
	}
	r := reports[0]
	if !r.open || r.evidence["state"] != libvirt.SwtpmSyncUnsupported || r.evidence["fs"] != "tmpfs" ||
		r.evidence["path"] != "/var/lib/libvirt/swtpm" || r.evidence["error"] != "operation not supported" ||
		r.evidence["remedy"] == nil {
		t.Fatalf("report %+v, want it open with the state, fs, path, error and remedy", r)
	}
}

func TestVTPMStateSync_OnResolvesAndARecoveryClearsIt(t *testing.T) {
	v, h := newTestVTPMSync(true,
		libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncRenameNotSynchronous, FS: "xfs", Err: errors.New("x")},
		libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncOn})
	v.probe(true)
	v.probe(true)
	v.probe(true)
	_, reports := h.snapshot()
	if len(reports) != 2 || !reports[0].open || reports[1].open {
		t.Fatalf("reports %+v, want open then resolved, once each", reports)
	}
}

// Off is the operator's choice: litevirt's attribute is cleared and nothing
// is raised.
func TestVTPMStateSync_OffClearsAndRaisesNothing(t *testing.T) {
	v, h := newTestVTPMSync(false, libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncOff})
	if !v.probe(true) {
		t.Fatal("off: not vTPM-capable")
	}
	calls, reports := h.snapshot()
	if len(calls) != 1 || calls[0] {
		t.Fatalf("sync calls %v, want one pass with on=false", calls)
	}
	if len(reports) != 1 || reports[0].open {
		t.Fatalf("reports %+v, want the condition resolved", reports)
	}
}

func TestVTPMStateSync_AFailedWriteIsRetried(t *testing.T) {
	v, _ := newTestVTPMSync(true, libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncFailed, Err: errors.New("EIO")})
	n := 0
	v.report = func(bool, map[string]any) bool { n++; return n > 1 }
	v.probe(true)
	v.probe(true)
	v.probe(true)
	if n != 2 {
		t.Fatalf("condition written %d times, want a retry after the failed write and then none", n)
	}
}

// M1: swtpm uninstalled (or the host turned container-only) after the
// condition was raised: it is resolved, once, and the host is not capable.
func TestVTPMStateSync_SwtpmGoneResolvesTheCondition(t *testing.T) {
	v, h := newTestVTPMSync(true,
		libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncNotInherited, FS: "btrfs", Err: errors.New("x")},
		libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncOn})
	v.probe(true)
	if v.probe(false) || v.probe(false) {
		t.Fatal("no swtpm: capable")
	}
	calls, reports := h.snapshot()
	if len(reports) != 2 || !reports[0].open || reports[1].open {
		t.Fatalf("reports %+v, want open, then resolved once swtpm is gone", reports)
	}
	if len(calls) != 1 {
		t.Fatalf("a pass ran without swtpm: %v", calls)
	}
	// Reinstalled: a fresh pass runs before it is capable again.
	if !v.probe(true) {
		t.Fatal("swtpm back and a pass done: not capable")
	}
	if calls, _ := h.snapshot(); len(calls) != 2 {
		t.Fatalf("sync calls %v, want a new pass once swtpm is back", calls)
	}
}

// M2: a pass that hangs (a hard NFS mount whose server stopped answering)
// never blocks the probe past its wait, the host is not offered for vTPM
// until a pass completes, the overrun is raised once, and no second pass is
// stacked on the hung one.
func TestVTPMStateSync_AHungPassNeitherBlocksNorOffersVTPM(t *testing.T) {
	release := make(chan struct{})
	v, h := newTestVTPMSync(true, libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncOn})
	inner := v.sync
	v.sync = func(on bool) libvirt.SwtpmSyncReport { <-release; return inner(on) }
	v.wait = 20 * time.Millisecond

	start := time.Now()
	if v.probe(true) {
		t.Fatal("capable before any pass completed")
	}
	if v.probe(true) {
		t.Fatal("capable while the only pass hangs")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("probes blocked %v on a hung pass", el)
	}
	_, reports := h.snapshot()
	if len(reports) != 1 || !reports[0].open || reports[0].evidence["state"] != "timed_out" {
		t.Fatalf("reports %+v, want one open timed_out", reports)
	}

	close(release)
	v.wait = 5 * time.Second
	if !v.probe(true) {
		t.Fatal("the pass completed: not capable")
	}
	calls, reports := h.snapshot()
	if len(calls) > 2 {
		t.Fatalf("passes stacked on a hung one: %v", calls)
	}
	if last := reports[len(reports)-1]; last.open {
		t.Fatalf("reports %+v, want the overrun resolved once a pass made the tree synchronous", reports)
	}
}

func TestVTPMStateSync_RemedyFitsTheFilesystem(t *testing.T) {
	for fs, want := range map[string]string{
		"zfs":   "zfs set sync=always",
		"nfs":   "sync",
		"xfs":   "dirsync",
		"btrfs": "ext4",
		"tmpfs": "ext4",
	} {
		state := libvirt.SwtpmSyncUnsupported
		switch fs {
		case "xfs":
			state = libvirt.SwtpmSyncRenameNotSynchronous
		case "btrfs":
			state = libvirt.SwtpmSyncNotInherited
		}
		v, h := newTestVTPMSync(true, libvirt.SwtpmSyncReport{State: state, FS: fs, Base: "/b", Err: errors.New("x")})
		v.probe(true)
		_, reports := h.snapshot()
		if r, _ := reports[0].evidence["remedy"].(string); !strings.Contains(r, want) {
			t.Errorf("%s: remedy %q, want it to name %q", fs, r, want)
		}
	}
}

func TestTPMCapableProbe_PassesWhetherSwtpmIsInstalled(t *testing.T) {
	look := func(missing string) func(string) (string, error) {
		return func(f string) (string, error) {
			if f == missing {
				return "", exec.ErrNotFound
			}
			return "/usr/bin/" + f, nil
		}
	}
	var got []bool
	probe := func(present bool) bool { got = append(got, present); return present }
	if !tpmCapableProbe(look(""), probe)() {
		t.Fatal("swtpm and swtpm_setup present: not capable")
	}
	for _, missing := range []string{"swtpm", "swtpm_setup"} {
		if tpmCapableProbe(look(missing), probe)() {
			t.Errorf("%s missing: capable", missing)
		}
	}
	if len(got) != 3 || !got[0] || got[1] || got[2] {
		t.Fatalf("probe saw %v, want [true false false]: it must run even without swtpm, to resolve", got)
	}
}

func TestConfig_VTPMStateSyncDefaultsOn(t *testing.T) {
	var c Config
	if !c.VTPMStateSyncEnabled() {
		t.Fatal("unset vtpm_state_sync is off, want on")
	}
	if err := yaml.Unmarshal([]byte("vtpm_state_sync: false\n"), &c); err != nil {
		t.Fatal(err)
	}
	if c.VTPMStateSyncEnabled() {
		t.Fatal("vtpm_state_sync: false is on")
	}
}
