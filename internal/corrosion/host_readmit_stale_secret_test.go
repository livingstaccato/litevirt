package corrosion

import (
	"context"
	"testing"
)

// staleRowOverReadmission re-admits host-x on c and then merges, as
// anti-entropy would, the removed machine's whole row carrying its BMC
// password, newer than the re-admission and with a created_at inside the
// incarnation grace (hlc.MaxSkewMS), so the hosts floor lets it in. That is a
// host re-added within five minutes of its first insert whose daemon booted
// on its old database and wrote before it heard the re-admission.
func staleRowOverReadmission(t *testing.T, c *Client) {
	t.Helper()
	oldIncarnation(t, c)
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, "2999-01-01T00:00:00.000001Z", "host-x", readmitSerial,
	}})
	if _, ok := liveCredential(t, c); ok {
		t.Fatal("fixture: the re-admission did not retire the credential row")
	}
	cols, row := hostsRowImage(t, c, "host-x")
	row[indexOf(cols, "fence_strategy")] = "ipmi"
	row[indexOf(cols, "ipmi_address")] = "10.0.1.15"
	row[indexOf(cols, "ipmi_user")] = "probe"
	row[indexOf(cols, "ipmi_pass")] = "Ipmi-Probe-0928"
	row[indexOf(cols, "created_at")] = "2998-12-31T23:58:00.000000000Z"
	row[indexOf(cols, "updated_at")] = "2999-01-01T00:01:00.000001Z"
	mergeHostsRow(t, c, cols, row)
	if got := readHostSettings(t, c).ipmiPass; got != "'Ipmi-Probe-0928'" {
		t.Fatalf("fixture: the stale row did not land (hosts.ipmi_pass %s)", got)
	}
}

// A host's credential row retired by its re-admission is the answer to "what
// is this host's BMC password": none. A stale row that later brings the old
// column back must not be served in its place.
func TestReadmission_ARetiredCredentialIsNotReadFromAStaleRow(t *testing.T) {
	c := newTestDB(t)
	staleRowOverReadmission(t, c)
	h, err := GetHost(context.Background(), c, "host-x")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %+v %v", h, err)
	}
	if h.IPMIPass != "" {
		t.Errorf("GetHost serves the removed machine's BMC password %q over its retired credential row", h.IPMIPass)
	}
}

// Nor may the split pass copy it back into a live credential row, which would
// then replicate cluster-wide on the sensitive lane — before or after
// credentials_clear_v1.
func TestReadmission_TheSplitPassDoesNotReviveARetiredCredential(t *testing.T) {
	for _, tc := range []struct {
		name  string
		clear bool
	}{{"dual-write", false}, {"clearing", true}} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestDB(t)
			staleRowOverReadmission(t, c)
			c.SetCredentialsClearGate(func() bool { return tc.clear })
			if _, err := c.SplitCredentials(context.Background()); err != nil {
				t.Fatalf("SplitCredentials: %v", err)
			}
			if pass, ok := liveCredential(t, c); ok {
				t.Errorf("the split pass revived the retired credential row with %q", pass)
			}
			if got := readHostSettings(t, c).ipmiPass; tc.clear && got != "''" {
				t.Errorf("hosts.ipmi_pass = %s after a clearing pass, want ''", got)
			}
		})
	}
}
