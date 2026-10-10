package daemon

import (
	"context"
	"crypto/x509"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/pki"
)

// renewOnDisk replaces pkiDir's host pair with a renewal of the served one, the
// way `lv host renew-cert` installs it, and returns the new serial.
func renewOnDisk(t *testing.T, pkiDir, host string) string {
	t.Helper()
	_, next, err := pki.RenewLocal(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key"), pkiDir, host)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func certWatchFixture(t *testing.T, host string) (*certWatch, *corrosion.Client, string) {
	t.Helper()
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	pkiDir := t.TempDir()
	caCert, caKey := filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateHostCert(caCert, caKey, filepath.Join(pkiDir, "host.crt"),
		filepath.Join(pkiDir, "host.key"), host, net.IPv4(127, 0, 0, 1)); err != nil {
		t.Fatal(err)
	}
	serial, err := pki.CertSerial(filepath.Join(pkiDir, "host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: host, Address: "10.0.0.1", State: "active", CertSerial: serial,
	}); err != nil {
		t.Fatal(err)
	}
	return newCertWatch(host, pkiDir, db, nil, nil), db, pkiDir
}

func recordedSerial(t *testing.T, db *corrosion.Client, host string) string {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT cert_serial FROM hosts WHERE name = ?`, host)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read host row: %v (%d rows)", err, len(rows))
	}
	return strings.ToLower(rows[0].String("cert_serial"))
}

// A node renewed while running re-records the serial it now serves, so the
// pin moves on and the next renewal has a recorded predecessor to name.
//
// Mutation: drop recordHostSerial from tick — the row keeps the old serial.
func TestCertWatch_ReRecordsARenewedSerial(t *testing.T) {
	w, db, pkiDir := certWatchFixture(t, "node-0")
	w.tick(context.Background(), time.Now())
	renewed := renewOnDisk(t, pkiDir, "node-0")
	w.tick(context.Background(), time.Now())
	if got := recordedSerial(t, db, "node-0"); got != renewed {
		t.Fatalf("hosts.cert_serial = %s after a renewal to %s", got, renewed)
	}
}

// The runtime re-record is the boot re-record's twin, refusals included: a
// removed host is not brought back by renewing its certificate.
//
// Mutation: drop the deleted_at check in RecordOwnCertSerial AND the
// `deleted_at IS NULL` guard in recordOwnCertSerialSQL — the tombstoned row
// takes the new serial. (Either guard alone holds it; they are belt and braces.)
func TestCertWatch_DoesNotTouchATombstonedRow(t *testing.T) {
	w, db, pkiDir := certWatchFixture(t, "node-0")
	before := recordedSerial(t, db, "node-0")
	if err := corrosion.DeleteHost(context.Background(), db, "node-0"); err != nil {
		t.Fatal(err)
	}
	renewOnDisk(t, pkiDir, "node-0")
	w.tick(context.Background(), time.Now())
	if got := recordedSerial(t, db, "node-0"); got != before {
		t.Fatalf("a removed host's row was re-recorded to %s", got)
	}
}

type recordingNotifier struct{ got []string }

func (r *recordingNotifier) ProcessOwedRevocations(context.Context) {}

func (r *recordingNotifier) NotifyCertificate(kind string, sev notify.Severity, subject, _ string) {
	r.got = append(r.got, kind+"/"+string(sev)+"/"+subject)
}

// Expiry notifies on entering each tier and repeats daily, never every tick.
//
// Mutations: raise certWarnBefore below 20 days — the 20-day warning is not
// sent; drop the renotify window check — every tick re-sends.
func TestCertWatch_NotifiesAheadOfExpiry(t *testing.T) {
	n := &recordingNotifier{}
	now := time.Now()
	notAfter := now.Add(20 * 24 * time.Hour)
	w := &certWatch{host: "node-0", notifier: n, alerts: map[string]certAlert{}}
	w.certs = []servedCert{{name: "host", renewHint: "lv host renew-cert node-0",
		leaf: func() (*x509.Certificate, error) {
			return &x509.Certificate{SerialNumber: big.NewInt(7), NotAfter: notAfter}, nil
		}}}
	ctx := context.Background()

	w.tick(ctx, now)
	w.tick(ctx, now.Add(time.Minute))
	if len(n.got) != 1 || n.got[0] != "certificate.expiring/warn/node-0/host" {
		t.Fatalf("20 days out: got %v, want one warning", n.got)
	}
	w.tick(ctx, now.Add(25*time.Hour))
	if len(n.got) != 2 {
		t.Fatalf("a standing warning was not repeated after a day: %v", n.got)
	}
	w.tick(ctx, notAfter.Add(-3*24*time.Hour))
	if last := n.got[len(n.got)-1]; last != "certificate.expiring/error/node-0/host" {
		t.Fatalf("3 days out: got %s, want an error-severity warning", last)
	}
	w.tick(ctx, notAfter.Add(time.Hour))
	if last := n.got[len(n.got)-1]; last != "certificate.expired/error/node-0/host" {
		t.Fatalf("past NotAfter: got %s", last)
	}

	// A renewal far from expiry clears the alert and sends nothing.
	sent := len(n.got)
	notAfter = now.Add(5 * 365 * 24 * time.Hour)
	w.tick(ctx, now.Add(48*time.Hour))
	if len(n.got) != sent {
		t.Fatalf("a healthy certificate notified: %v", n.got[sent:])
	}
}

// A host key held unsafely is never refused (main served it) but raised as a
// degraded condition naming the file and the fix, and resolved once fixed.
//
// Mutation: drop reportKeyFile from tick — no condition is raised.
func TestCertWatch_RaisesAnUnsafeKeyFileWithoutRefusingIt(t *testing.T) {
	ctx := context.Background()
	w, db, pkiDir := certWatchFixture(t, "node-0")
	key := filepath.Join(pkiDir, "host.key")
	outside := filepath.Join(t.TempDir(), "host.key")
	if err := os.Rename(key, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, key); err != nil {
		t.Fatal(err)
	}
	w.tick(ctx, time.Now())
	if _, err := pki.ServedHostCertificate(pkiDir); err != nil {
		t.Fatalf("the host identity was refused over its key file: %v", err)
	}
	cond := func() (corrosion.HealthCondition, bool) {
		c, ok, err := corrosion.GetHealthCondition(ctx, db, "certificate", "key_file_unsafe", "host", "node-0/host.key")
		if err != nil {
			t.Fatal(err)
		}
		return c, ok
	}
	c, ok := cond()
	if !ok || c.Lifecycle != corrosion.ConditionConfirmed || !strings.Contains(c.Evidence, "outside") {
		t.Fatalf("no degraded condition names the unsafe key: %+v %v", c, ok)
	}
	// Fixed: the key moves back into the PKI directory.
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(outside, key); err != nil {
		t.Fatal(err)
	}
	w.tick(ctx, time.Now())
	if c, _ := cond(); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("the condition was not resolved once the key was fixed: %s", c.Lifecycle)
	}
}
