package ui

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestNICSettings(t *testing.T) {
	spec := &pb.VMSpec{Network: []*pb.NetworkAttachment{
		{Name: "lan0", Mac: "52:54:00:aa:bb:cc", RateMbSec: 4, Queues: 4, SecurityGroups: []string{"web"}, SpoofGuard: "off"},
		{Name: "lan1", Mac: "52:54:00:dd:ee:ff"},
	}}
	if got, want := nicSettings(spec, "52:54:00:AA:BB:CC"), "rate 4 MB/s, 4 queues, sg web, spoof-guard off"; got != want {
		t.Errorf("nicSettings = %q, want %q", got, want)
	}
	if got := nicSettings(spec, "52:54:00:dd:ee:ff"); got != "" {
		t.Errorf("plain NIC settings = %q, want empty", got)
	}
	if got := nicSettings(nil, "x"); got != "" {
		t.Errorf("nil spec = %q", got)
	}
}
