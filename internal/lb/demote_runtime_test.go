package lb

import (
	"context"
	"errors"
	"github.com/litevirt/litevirt/internal/lbtestproc"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type observedDemoteRuntime struct {
	*lbtestproc.Runtime
	t       *testing.T
	manager *Manager
	output  string
	failure error
	calls   int
}

func (r *observedDemoteRuntime) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	if bin != "ip" {
		return r.Runtime.Run(ctx, bin, args...)
	}
	r.calls++
	if r.manager.KeepalivedRunning("web") {
		r.t.Error("VIP deletion reached before actual owned keepalived exit")
	}
	if !reflect.DeepEqual(args, []string{"addr", "del", "10.0.1.100/24", "dev", "fleet0"}) {
		r.t.Error("wrong rendered deletion tuple", args)
	}
	// The private runtime validates the shape, records it and joins the actual child.
	if _, err := r.Runtime.Run(ctx, bin, args...); err != nil {
		return nil, err
	}
	return []byte(r.output), r.failure
}
func TestDemote_PrivateRuntimePreservesStopOrderAndErrors(t *testing.T) {
	for _, tc := range []struct {
		name, output  string
		fail, wantErr bool
	}{{"success", "", false, false}, {"failure", "permission denied", true, true}, {"already_absent", "Cannot assign requested address", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			m := NewManagerAt(filepath.Join(root, "config"), filepath.Join(root, "run"))
			r := &observedDemoteRuntime{Runtime: lbtestproc.New(t, false), t: t, manager: m, output: tc.output}
			if tc.fail {
				r.failure = errors.New("injected delete failure")
			}
			m.SetProcessRuntime(r)
			cfg := stickyRedirectConfig()
			cfg.Interface = "fleet0"
			if err := m.Apply(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			if !m.KeepalivedRunning("web") {
				t.Fatal("real private keepalived child never started")
			}
			err := m.DemoteByName("web", time.Second)
			if (err != nil) != tc.wantErr {
				t.Fatal("deletion error classification changed", err)
			}
			if r.calls != 1 || m.KeepalivedRunning("web") {
				t.Fatal("demotion skipped deletion/actual child stop", r.calls)
			}
			b, err := os.ReadFile(filepath.Join(r.Dir, "ip.calls"))
			if err != nil || string(b) != "addr del 10.0.1.100/24 dev fleet0\n" {
				t.Fatal("exact deletion not recorded", string(b), err)
			}
		})
	}
}
