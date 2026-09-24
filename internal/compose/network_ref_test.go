package compose

import "testing"

// A NIC naming a network the file does not declare refers to the cluster
// network of that name (one made with `lv network create`), exactly as a
// network declared `external: true` does.
//
// It used to be stack-scoped like a stack-owned network. The lab failure: a
// stack "hc" attaching to the cluster network "hc" asked for "hc_hc", found no
// such record, and fell back to a flat bridge named "hc_hc" — no gateway, no
// dnsmasq — while the real network's bridge br-iso-hc stood unused.
func TestBuildVMSpec_UndeclaredNetworkIsTheClusterNetwork(t *testing.T) {
	f := baseFile("hc", map[string]NetworkDef{
		"own": {Type: "isolated", Subnet: "172.16.60.0/24"},
		"ext": {External: true},
	})
	vm := &VMDef{
		Image:   "ubuntu",
		Network: []NetworkAttachment{{Name: "hc"}, {Name: "own"}, {Name: "ext"}},
	}

	spec := mustBuildVMSpec(t, "db", "db", vm, f)

	want := []string{"hc", "hc_own", "ext"}
	if len(spec.Network) != len(want) {
		t.Fatalf("got %d NICs, want %d", len(spec.Network), len(want))
	}
	for i, w := range want {
		if got := spec.Network[i].Name; got != w {
			t.Errorf("NIC %d network = %q, want %q", i, got, w)
		}
	}
}

func TestResolveNetworkName(t *testing.T) {
	f := baseFile("st", map[string]NetworkDef{
		"own": {Type: "bridge"},
		"ext": {External: true},
	})
	for raw, want := range map[string]string{
		"own":        "st_own",
		"ext":        "ext",
		"undeclared": "undeclared",
	} {
		if got := f.ResolveNetworkName(raw); got != want {
			t.Errorf("ResolveNetworkName(%q) = %q, want %q", raw, got, want)
		}
	}
}
