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
		"limit above cpu":               {"cpu-limit: 2.5", "cpu-limit: 5"},
		"negative limit":                {"cpu-limit: 2.5", "cpu-limit: -1"},
		"shares above the weight range": {"cpu-shares: 2048", "cpu-shares: 20000"},
		"shares negative":               {"cpu-shares: 2048", "cpu-shares: -3"},
		"negative rate":                 {"rate: 12.5", "rate: -2"},
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
		if got := NICRate(spec, "52:54:00:00:00:99", c.ord, c.net); got != c.want {
			t.Errorf("NICRate(%d,%q) = %v, want %v", c.ord, c.net, got, c.want)
		}
	}
	if NICRate(nil, "", 0, "a") != 0 {
		t.Error("nil spec has a rate")
	}
}

// An entry that records a MAC is the NIC's with that MAC wherever its ordinal
// is (a NIC detached and attached again takes a new one), and never the NIC's
// whose ordinal is its index.
//
// Mutation: look the entry up by ordinal first — red.
func TestNICRate_AnEntryWithAMACIsFoundByIt(t *testing.T) {
	const a, b = "52:54:00:00:00:0a", "52:54:00:00:00:0b"
	spec := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "n", Mac: a, RateMbSec: 3}, {Name: "n", RateMbSec: 4}}}
	for _, c := range []struct {
		mac  string
		ord  int
		want float64
	}{{strings.ToUpper(a), 5, 3}, {b, 0, 0}, {b, 1, 4}, {b, 7, 0}} {
		if got := NICRate(spec, c.mac, c.ord, "n"); got != c.want {
			t.Errorf("NICRate(%s,%d) = %v, want %v", c.mac, c.ord, got, c.want)
		}
	}
	if got := SpecEntryIndexForNIC(spec, a, 1); got != 0 {
		t.Errorf("SpecEntryIndexForNIC(a, 1) = %d, want 0", got)
	}
}

// cpu-limit, cpu-shares and rate are VM controls (libvirt cputune/bandwidth); a
// container entry has no such thing, so setting one is an error, not a silent no-op.
func TestParse_LimitsAreRejectedOnContainers(t *testing.T) {
	for name, extra := range map[string]string{
		"cpu-limit":  "    cpu-limit: 1\n",
		"cpu-shares": "    cpu-shares: 200\n",
	} {
		y := "name: lim\nvms:\n  c:\n    kind: lxc\n    image: alpine:3.21\n    cpu: 2\n" + extra
		if _, err := ParseBytes([]byte(y)); err == nil {
			t.Errorf("%s on an lxc entry parsed without error", name)
		}
	}
	y := "name: lim\nnetworks:\n  n1: {}\nvms:\n  c:\n    kind: oci\n    image: alpine:3.21\n    network:\n      - name: n1\n        rate: 5\n"
	if _, err := ParseBytes([]byte(y)); err == nil {
		t.Error("a NIC rate on an oci entry parsed without error")
	}
}
