package placement

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// regionHosts gives east two nearly full hosts and west one empty host, so the
// scorer prefers west for anything that fits there. A region constraint that is
// not honoured therefore shows up as a west placement.
func regionHosts() ([]corrosion.HostRecord, []corrosion.VMRecord) {
	hosts := makeHosts("e1", "e2", "w1")
	hosts[0].Region, hosts[1].Region, hosts[2].Region = "east", "east", "west"
	vms := []corrosion.VMRecord{
		makeVM("load-e1", "e1", 24, 48000, "running"),
		makeVM("load-e2", "e2", 24, 48000, "running"),
	}
	return hosts, vms
}

func TestSelectBatch_RequireRegion_KeepsRecoveryInRegion(t *testing.T) {
	hosts, vms := regionHosts()

	// Without the constraint the empty west host wins, which is what makes the
	// constrained case below mean something.
	free, err := SelectBatch(hosts, vms, nil, nil, nil, time.Time{}, []Request{
		{VMName: "vm", CPUNeeded: 2, MemMiBNeeded: 1024},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if free["vm"].Host != "w1" {
		t.Fatalf("precondition: the scorer must prefer the empty west host, got %q", free["vm"].Host)
	}

	got, err := SelectBatch(hosts, vms, nil, nil, nil, time.Time{}, []Request{
		{VMName: "vm", CPUNeeded: 2, MemMiBNeeded: 1024, RequireRegion: "east"},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if h := got["vm"].Host; h != "e1" && h != "e2" {
		t.Fatalf("RequireRegion=east placed the VM on %q", h)
	}
}

func TestSelectBatch_RequireRegion_NoRoomIsNoEligibleHost(t *testing.T) {
	hosts, vms := regionHosts()
	got, err := SelectBatch(hosts, vms, nil, nil, nil, time.Time{}, []Request{
		// Too big for either east host, would fit west.
		{VMName: "vm", CPUNeeded: 16, MemMiBNeeded: 32768, RequireRegion: "east"},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	res := got["vm"]
	if res.Host != "" || !errors.Is(res.Err, ErrNoEligibleHost) {
		t.Fatalf("a VM that fits only outside its region must get no host, got %+v", res)
	}
	if !strings.Contains(res.Err.Error(), "region") {
		t.Fatalf("the refusal must name the region constraint for the out-of-region host: %v", res.Err)
	}
}
