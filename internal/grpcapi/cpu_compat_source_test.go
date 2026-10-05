package grpcapi

import (
	"errors"
	"testing"

	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const guestCPUXML = `<cpu mode='custom' match='exact' check='full'><model fallback='forbid'>EPYC-Milan</model><feature policy='require' name='topoext'/></cpu>`

// A target's "cannot run" is only believed when the SOURCE — which is running
// this guest right now — says it can run it. Asked the same question, a source
// that says no proves the compare itself is wrong about this guest.
func TestSourceRunsGuestCPU(t *testing.T) {
	for _, tc := range []struct {
		name    string
		verdict lv.CPUCompare
		err     error
		want    bool
	}{
		{"source superset: target refusal stands", lv.CPUCompareSuperset, nil, true},
		{"source identical: target refusal stands", lv.CPUCompareIdentical, nil, true},
		{"source rejects its own guest: cannot decide", lv.CPUCompareIncompatible, nil, false},
		{"source cannot compare: cannot decide", lv.CPUCompareSuperset, errors.New("libvirt down"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := libvirtfake.New()
			v := tc.verdict
			fake.CPUCompareResult = &v
			if tc.err != nil {
				fake.FailCompareCPU = func(string) error { return tc.err }
			}
			s := &Server{virt: fake, hostName: "src"}
			if got := s.sourceRunsGuestCPU("vm1", "dst", guestCPUXML); got != tc.want {
				t.Fatalf("sourceRunsGuestCPU = %v, want %v", got, tc.want)
			}
			asked := fake.ComparedCPUXML()
			if len(asked) != 1 || asked[0] != guestCPUXML {
				t.Fatalf("source was not asked about the guest CPU verbatim: %q", asked)
			}
		})
	}
}
