package daemon

import (
	"errors"
	"os/exec"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/litevirt/litevirt/internal/libvirt"
)

type vtpmReport struct {
	open     bool
	evidence map[string]any
}

func newTestVTPMSync(on bool, states ...libvirt.SwtpmSyncReport) (*vtpmStateSync, *[]bool, *[]vtpmReport) {
	var calls []bool
	var reports []vtpmReport
	i := 0
	v := &vtpmStateSync{
		on: on,
		sync: func(on bool) libvirt.SwtpmSyncReport {
			calls = append(calls, on)
			r := states[i]
			if i < len(states)-1 {
				i++
			}
			return r
		},
		report: func(open bool, evidence map[string]any) bool {
			reports = append(reports, vtpmReport{open, evidence})
			return true
		},
	}
	return v, &calls, &reports
}

func TestVTPMStateSync_UnsupportedRaisesTheConditionOnce(t *testing.T) {
	unsup := libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncUnsupported, Base: "/var/lib/libvirt/swtpm",
		Err: errors.New("operation not supported")}
	v, calls, reports := newTestVTPMSync(true, unsup)
	v.ensure()
	v.ensure()
	if len(*calls) != 2 || !(*calls)[0] {
		t.Fatalf("sync calls %v, want two passes with on=true", *calls)
	}
	if len(*reports) != 1 {
		t.Fatalf("reports %+v, want the condition written once", *reports)
	}
	r := (*reports)[0]
	if !r.open || r.evidence["state"] != libvirt.SwtpmSyncUnsupported ||
		r.evidence["path"] != "/var/lib/libvirt/swtpm" || r.evidence["error"] != "operation not supported" ||
		r.evidence["remedy"] == nil {
		t.Fatalf("report %+v, want it open with the state, path, error and remedy", r)
	}
}

func TestVTPMStateSync_OnResolvesAndARecoveryClearsIt(t *testing.T) {
	v, _, reports := newTestVTPMSync(true,
		libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncNotInherited, Err: errors.New("x")},
		libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncOn})
	v.ensure()
	v.ensure()
	v.ensure()
	if len(*reports) != 2 || !(*reports)[0].open || (*reports)[1].open {
		t.Fatalf("reports %+v, want open then resolved, once each", *reports)
	}
}

// Off is the operator's choice: the tree is cleared and nothing is raised.
func TestVTPMStateSync_OffClearsAndRaisesNothing(t *testing.T) {
	v, calls, reports := newTestVTPMSync(false, libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncOff})
	v.ensure()
	if len(*calls) != 1 || (*calls)[0] {
		t.Fatalf("sync calls %v, want one pass with on=false", *calls)
	}
	if len(*reports) != 1 || (*reports)[0].open {
		t.Fatalf("reports %+v, want the condition resolved", *reports)
	}
}

func TestVTPMStateSync_AFailedWriteIsRetried(t *testing.T) {
	v, _, _ := newTestVTPMSync(true, libvirt.SwtpmSyncReport{State: libvirt.SwtpmSyncFailed, Err: errors.New("EIO")})
	n := 0
	v.report = func(bool, map[string]any) bool { n++; return n > 1 }
	v.ensure()
	v.ensure()
	v.ensure()
	if n != 2 {
		t.Fatalf("condition written %d times, want a retry after the failed write and then none", n)
	}
}

// The vTPM label is what lets placement put a vTPM VM on the host, so the tree
// must carry the attribute before the probe says the host is capable.
func TestTPMCapableProbe_SyncsBeforeItSaysCapable(t *testing.T) {
	var order []string
	look := func(missing string) func(string) (string, error) {
		return func(f string) (string, error) {
			if f == missing {
				return "", exec.ErrNotFound
			}
			return "/usr/bin/" + f, nil
		}
	}
	ensure := func() { order = append(order, "ensure") }

	if !tpmCapableProbe(look(""), ensure)() {
		t.Fatal("swtpm and swtpm_setup present: not capable")
	}
	if len(order) != 1 {
		t.Fatalf("ensure ran %d times on a capable host, want 1", len(order))
	}
	order = nil
	for _, missing := range []string{"swtpm", "swtpm_setup"} {
		if tpmCapableProbe(look(missing), ensure)() {
			t.Errorf("%s missing: capable", missing)
		}
	}
	if len(order) != 0 {
		t.Fatalf("ensure ran on a host without swtpm")
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
