package grpcapi

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const guestCPUXML = `<cpu mode='custom' match='exact' check='full'><model fallback='forbid'>EPYC-Milan</model><feature policy='require' name='topoext'/></cpu>`

// A target's "cannot run" is only believed when the SOURCE — which is running
// this guest right now — says it can run it. Asked the same question, a source
// that says no proves the compare itself is wrong about this guest, and that
// must be said in the log: it is the only trace of a check that stood down.
func TestSourceRunsGuestCPU(t *testing.T) {
	for _, tc := range []struct {
		name        string
		verdict     lv.CPUCompare
		err         error
		want        bool
		wantVerdict string
		wantWarn    string
	}{
		{"source superset: target refusal stands", lv.CPUCompareSuperset, nil, true, "superset", ""},
		{"source identical: target refusal stands", lv.CPUCompareIdentical, nil, true, "identical", ""},
		{"source rejects its own guest: cannot decide", lv.CPUCompareIncompatible, nil, false, "incompatible",
			"source rejects the CPU of the guest it is running"},
		{"source cannot compare: cannot decide", lv.CPUCompareSuperset, errors.New("libvirt down"), false, "error",
			"source could not compare"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			fake := libvirtfake.New()
			v := tc.verdict
			fake.CPUCompareResult = &v
			if tc.err != nil {
				fake.FailCompareCPU = func(string) error { return tc.err }
			}
			s := &Server{virt: fake, hostName: "src"}
			verdict, got := s.sourceRunsGuestCPU("vm1", "dst", guestCPUXML, "pc-q35-8.2")
			if got != tc.want || verdict != tc.wantVerdict {
				t.Fatalf("sourceRunsGuestCPU = (%q, %v), want (%q, %v)", verdict, got, tc.wantVerdict, tc.want)
			}
			asked := fake.ComparedCPUXML()
			if len(asked) != 1 || asked[0] != guestCPUXML {
				t.Fatalf("source was not asked about the guest CPU verbatim: %q", asked)
			}
			if m := fake.ComparedMachines(); len(m) != 1 || m[0] != "pc-q35-8.2" {
				t.Errorf("source compare machine = %q, want the guest's", m)
			}
			logged := buf.String()
			if tc.wantWarn == "" {
				if strings.Contains(logged, "cannot decide") {
					t.Errorf("a decisive source logged cannot-decide: %s", logged)
				}
				return
			}
			if !strings.Contains(logged, "level=WARN") || !strings.Contains(logged, "cannot decide") ||
				!strings.Contains(logged, tc.wantWarn) || !strings.Contains(logged, "vm=vm1") ||
				!strings.Contains(logged, "target=dst") {
				t.Errorf("the stand-down was not logged as a WARN naming vm and target: %q", logged)
			}
		})
	}
}
