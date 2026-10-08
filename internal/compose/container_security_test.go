package compose

import (
	"strings"
	"testing"
)

// A container workload states its security opt-outs; a VM may not.
func TestParse_ContainerSecurity(t *testing.T) {
	f, err := ParseBytes([]byte("name: s\nworkloads:\n  ci:\n    kind: lxc\n    image: alpine:3.21\n    privileged: true\n    confinement: legacy\n"))
	if err != nil {
		t.Fatal(err)
	}
	if d := f.VMs["ci"]; !d.Privileged || d.Confinement != "legacy" {
		t.Fatalf("parsed %+v", d)
	}
	for _, bad := range []string{
		"name: s\nworkloads:\n  ci:\n    kind: lxc\n    image: alpine:3.21\n    confinement: unconfined\n",
		"name: s\nworkloads:\n  vm:\n    image: ubuntu\n    privileged: true\n",
	} {
		if _, err := ParseBytes([]byte(bad)); err == nil || !strings.Contains(err.Error(), "confinement") && !strings.Contains(err.Error(), "privileged") {
			t.Errorf("accepted %q (err %v)", bad, err)
		}
	}
}
