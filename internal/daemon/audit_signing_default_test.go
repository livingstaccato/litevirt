package daemon

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Audit signing is ON unless a host's config says otherwise.
//
// It used to be opt-in, and the kvm003-f3 lab showed what that costs: five
// nodes, none with enforcement.audit_signature set, and `lv audit verify`
// reported all 212 rows as unsigned — including a user.reset-admin row whose
// commit said it was signed. Nothing was broken; nothing had ever been turned
// on.

// mustLoadConfigText is loadConfigText (gossip_keyring_test.go) for a config
// that has to load. The host name it prepends is "n".
func mustLoadConfigText(t *testing.T, text string) *Config {
	t.Helper()
	cfg, err := loadConfigText(t, text)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg
}

func TestLoadConfig_AuditSignatureDefaultsOn(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"no enforcement block", "", true},
		{"empty enforcement block", "enforcement:\n", true},
		{"empty enforcement map", "enforcement: {}\n", true},
		{"enforcement block without the key", "enforcement:\n  gossip_encryption: false\n", true},
		{"explicitly on", "enforcement:\n  audit_signature: true\n", true},
		// The kill switch survives: an explicit false is still honoured, and it
		// is what makes the next start sign the host's retirement.
		{"explicitly off", "enforcement:\n  audit_signature: false\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustLoadConfigText(t, tc.text).Enforcement.AuditSignature; got != tc.want {
				t.Fatalf("Enforcement.AuditSignature = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAuditSigning_ADefaultConfiguredDaemonSignsItsRows drives the daemon's own
// startup wiring from a config that never mentions audit signing, and checks
// what verify makes of the row: signed, and no host reported as not signing.
func TestAuditSigning_ADefaultConfiguredDaemonSignsItsRows(t *testing.T) {
	ctx := context.Background()
	const host = "n" // the host name mustLoadConfigText writes
	dir := auditPKIDir(t, host)
	d := auditTestDaemon(t, dir, host)
	d.cfg = mustLoadConfigText(t, "pki_dir: "+dir+"\n")

	d.wireAuditKeyring(ctx)

	if err := corrosion.InsertAuditLog(ctx, d.db, corrosion.AuditRecord{
		HostName: host, Username: "admin", Action: "vm.create", Target: "web", Result: "ok",
	}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}
	adoptNow(t, d)
	res, err := corrosion.VerifyAuditChain(ctx, d.db)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if res.RowsChecked != 1 || res.Unsigned != 0 || res.Tampered() || res.Unverified() || len(res.NotSigning) != 0 {
		t.Fatalf("a default-configured daemon wrote a row verify does not count as signed: %+v", res)
	}
}
