package libvirt

import (
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/nictap"
)

// TestGenerateDomainXML_NICTapNamedByMAC (re-review I-10): a bridged NIC's
// tap is named in the domain XML after its MAC, so the per-NIC firewall —
// guard included — can be in force for it before the domain first runs, on
// this host and on any host it migrates to. A macvtap NIC has no tap.
func TestGenerateDomainXML_NICTapNamedByMAC(t *testing.T) {
	x, err := GenerateDomainXML(VMConfig{Name: "web", CPU: 1, MemoryMiB: 256, Networks: []NetworkConfig{
		{Bridge: "br0", MAC: "52:54:00:aa:bb:cc"},
		{Direct: "eno1", MAC: "52:54:00:aa:bb:cd"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(x, `<target dev="`+nictap.Name("52:54:00:aa:bb:cc")+`"></target>`) {
		t.Errorf("the bridged NIC's tap is not named by its MAC:\n%s", x)
	}
	if strings.Contains(x, nictap.Name("52:54:00:aa:bb:cd")) {
		t.Errorf("a macvtap NIC was given a tap name:\n%s", x)
	}
	frag, err := marshalNewNIC("", WantNIC{Bridge: "br0", MAC: "52:54:00:aa:bb:ce"})
	if err != nil || !strings.Contains(frag, nictap.Name("52:54:00:aa:bb:ce")) {
		t.Errorf("a NIC added to a stopped domain's definition is not named by its MAC: %q, %v", frag, err)
	}
	if f := bridgeInterface("br0", "", "52:54:00:aa:bb:cf"); f.Target == nil || f.Target.Dev != nictap.Name("52:54:00:aa:bb:cf") {
		t.Errorf("a hot-attached NIC is not named by its MAC: %+v", f)
	}
}

// TestStartDomain_BeforeStartRefuses: a domain whose NIC firewall cannot be
// put in force first is not started (the hook fails closed for guarded VMs).
func TestStartDomain_BeforeStartRefuses(t *testing.T) {
	c := &Client{}
	called := ""
	c.SetBeforeStart(func(name string) error { called = name; return errors.New("guards not applied") })
	if err := c.StartDomain("web"); err == nil || called != "web" || !strings.Contains(err.Error(), "guards not applied") {
		t.Fatalf("StartDomain = %v (hook saw %q); want the hook's refusal before libvirt is asked", err, called)
	}
}
