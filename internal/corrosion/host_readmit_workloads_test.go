package corrosion

import (
	"context"
	"testing"
)

// HostRemoved is true only for a name whose hosts row is removed: a live
// host, a re-admitted one and a name this replica has never seen are not.
// The last matters most: a workload row can arrive before its host's row, and
// deleting it without a forward would skip the host that still runs it.
//
// Mutation: answer true for a name with no row — the unknown case goes red.
func TestHostRemoved(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"live", "gone", "back"} {
		if err := InsertHost(ctx, c, HostRecord{Name: n, Address: "10.0.0.1", SSHUser: "root", GRPCPort: 7443,
			State: "active", CertSerial: "aa" + n}); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"gone", "back"} {
		if err := DeleteHost(ctx, c, n); err != nil {
			t.Fatal(err)
		}
	}
	if err := AdmitHost(ctx, c, HostRecord{Name: "back", Address: "10.0.0.2", SSHUser: "root", GRPCPort: 7443,
		State: "joining", CertSerial: "bbback"}); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{"live": false, "gone": true, "back": false, "never": false} {
		got, err := HostRemoved(ctx, c, host)
		if err != nil || got != want {
			t.Errorf("HostRemoved(%s) = %v, %v; want %v", host, got, err, want)
		}
	}
}
