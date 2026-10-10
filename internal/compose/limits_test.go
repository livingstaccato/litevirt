package compose

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

const limitsYAML = `name: lim
networks:
  n1: {}
vms:
  web:
    image: nginx
    cpu: 4
    memory: 512
    cpu-limit: 2.5
    cpu-shares: 2048
    network:
      - name: n1
        rate: 12.5
`

func TestParse_LimitsReachTheVMSpec(t *testing.T) {
	f, err := ParseBytes([]byte(limitsYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	vm := f.VMs["web"]
	spec, err := BuildVMSpec("web", "web", &vm, f)
	if err != nil {
		t.Fatal(err)
	}
	if spec.CpuLimit != 2.5 || spec.CpuShares != 2048 || len(spec.Network) != 1 || spec.Network[0].RateMbSec != 12.5 {
		t.Errorf("spec limits = %v / %v / %+v", spec.CpuLimit, spec.CpuShares, spec.Network)
	}
}

func TestParse_LimitsAreValidated(t *testing.T) {
	for name, edit := range map[string][2]string{
		"limit above cpu":  {"cpu-limit: 2.5", "cpu-limit: 5"},
		"negative limit":   {"cpu-limit: 2.5", "cpu-limit: -1"},
		"shares too small": {"cpu-shares: 2048", "cpu-shares: 1"},
		"negative rate":    {"rate: 12.5", "rate: -2"},
	} {
		_, err := ParseBytes([]byte(strings.Replace(limitsYAML, edit[0], edit[1], 1)))
		if err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

func TestNICRate(t *testing.T) {
	spec := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "a", RateMbSec: 3}, {Name: "b", RateMbSec: 4}}}
	for _, c := range []struct {
		ord  int
		net  string
		want float64
	}{{0, "a", 3}, {1, "b", 4}, {1, "a", 0}, {2, "a", 0}, {-1, "a", 0}, {0, "", 3}} {
		if got := NICRate(spec, c.ord, c.net); got != c.want {
			t.Errorf("NICRate(%d,%q) = %v, want %v", c.ord, c.net, got, c.want)
		}
	}
	if NICRate(nil, 0, "a") != 0 {
		t.Error("nil spec has a rate")
	}
}
