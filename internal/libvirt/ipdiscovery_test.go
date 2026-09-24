package libvirt

import (
	"os"
	"path/filepath"
	"testing"
)

// A /proc/net/arp as the kernel prints it. Flags 0x2 is ATF_COM (a complete,
// usable entry); 0x0 is an entry being resolved or one that FAILED. A failed
// entry that was once valid keeps its hardware address, so it names a MAC
// that no longer answers at that IP — after a guest moves to a new DHCP lease
// its old address can sit here with its MAC for minutes.
const arpFixture = `IP address       HW type     Flags       HW address            Mask     Device
172.16.60.23     0x1         0x0         52:54:00:aa:bb:01     *        br0
172.16.60.9      0x1         0x0         00:00:00:00:00:00     *        br0
172.16.60.8      0x1         0x2         00:00:00:00:00:00     *        br0
172.16.60.41     0x1         0x2         52:54:00:aa:bb:01     *        br0
172.16.60.50     0x1         0x6         52:54:00:aa:bb:02     *        br0
172.16.60.77     0x1         0x0         52:54:00:aa:bb:03     *        br0
`

func withARPTable(t *testing.T, content string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "arp")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	old := arpTablePath
	arpTablePath = p
	t.Cleanup(func() { arpTablePath = old })
}

func TestGetIPFromARP_OnlyCompleteEntriesCount(t *testing.T) {
	withARPTable(t, arpFixture)
	cases := []struct {
		mac, want, why string
	}{
		{"52:54:00:aa:bb:01", "172.16.60.41", "the failed entry for the old address comes first and must be skipped"},
		{"52:54:00:AA:BB:01", "172.16.60.41", "MACs compare case-insensitively"},
		{"52:54:00:aa:bb:02", "172.16.60.50", "a permanent entry (ATF_PERM|ATF_COM) is complete"},
		{"52:54:00:aa:bb:03", "", "a MAC whose only entry failed is not answering anywhere"},
		{"00:00:00:00:00:00", "", "a zero hardware address is never a match, whatever the flags say"},
		{"52:54:00:ff:ff:ff", "", "an absent MAC"},
	}
	for _, c := range cases {
		if got := GetIPFromARP(c.mac); got != c.want {
			t.Errorf("GetIPFromARP(%s) = %q, want %q: %s", c.mac, got, c.want, c.why)
		}
	}
}

func TestGetIPFromARP_MissingTable(t *testing.T) {
	old := arpTablePath
	arpTablePath = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { arpTablePath = old })
	if got := GetIPFromARP("52:54:00:aa:bb:01"); got != "" {
		t.Errorf("GetIPFromARP with no table = %q, want \"\"", got)
	}
}
