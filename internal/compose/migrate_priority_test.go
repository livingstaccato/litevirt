package compose

import (
	"math"
	"testing"
)

// migrate.priority is an int32 in the stored spec. A value outside that range
// deployed before priorities were read (int32() wrapped it, so 2147483648 was
// stored as the LOWEST priority); it must keep deploying, clamped to the
// nearest bound so it keeps the order the operator meant, and the VM spec a
// redeploy builds from it carries the clamped value, which rewrites a VM
// stored with the wrapped one.
//
// Mutations: drop the clamp — 2147483648 parses through and the spec carries
// -2147483648 (wrapped), red; refuse instead of clamping — ParseBytes errors,
// red; clamp the upper bound only — the -2147483649 case is red.
func TestParseBytes_MigratePriorityClamped(t *testing.T) {
	doc := func(p string) []byte {
		return []byte("name: s\nvms:\n  web:\n    image: nginx\n    cpu: 1\n    memory: 512\n    migrate:\n      priority: " + p + "\n")
	}
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"0", 0},
		{"100", 100},
		{"-5", -5},
		{"2147483647", math.MaxInt32},
		{"-2147483648", math.MinInt32},
		{"2147483648", math.MaxInt32},
		{"3000000000", math.MaxInt32},
		{"-2147483649", math.MinInt32},
		{"-9000000000", math.MinInt32},
	} {
		f, err := ParseBytes(doc(tc.in))
		if err != nil {
			t.Errorf("priority %s: refused (%v); an out-of-range value is clamped, never refused", tc.in, err)
			continue
		}
		if got := f.VMs["web"].Migrate.Priority; got != tc.want {
			t.Errorf("priority %s parsed as %d, want %d", tc.in, got, tc.want)
		}
		vm := f.VMs["web"]
		spec, err := BuildVMSpec("web", "web", &vm, f)
		if err != nil {
			t.Fatalf("priority %s: BuildVMSpec: %v", tc.in, err)
		}
		if got := spec.GetMigrate().GetPriority(); int(got) != tc.want {
			t.Errorf("priority %s: the VM spec stores %d, want %d", tc.in, got, tc.want)
		}
	}
}
