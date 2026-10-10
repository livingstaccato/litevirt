package daemon

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/metrics"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/pki"
)

// The certificate watch.
//
// Two jobs, both about the certificates this node SERVES rather than whatever
// is on disk:
//
//   - a renewed host certificate is adopted at handshake time (pki.KeyPairSource),
//     and peers pin the serial in this host's row. The renewal names its
//     predecessor so peers accept it at once, but the row must still move on,
//     or the next renewal has nothing to name. RegisterHost does that at boot;
//     this does it for a node that was renewed while running.
//   - expiry: a gauge per certificate and a notification as each threshold is
//     crossed, so an operator hears about a certificate months before peers
//     start refusing it.
const (
	certWatchInterval = 30 * time.Second
	// connSweepInterval bounds how long a revoked or superseded certificate
	// keeps an established gRPC connection (pki.ConnTracker).
	connSweepInterval = 10 * time.Second
	certWarnBefore    = 30 * 24 * time.Hour
	certCritBefore    = 7 * 24 * time.Hour
	// certRenotifyEvery repeats a standing alert, so one lost delivery is not
	// the only word an operator gets before a certificate lapses.
	certRenotifyEvery = 24 * time.Hour
)

// certNotifier delivers a certificate notification. *grpcapi.Server satisfies it.
type certNotifier interface {
	NotifyCertificate(kind string, sev notify.Severity, subject, detail string)
	// ProcessOwedRevocations publishes replaced-certificate revocations that
	// were held for the voter chain once that is safe (grpcapi/cert_revocation.go).
	ProcessOwedRevocations(ctx context.Context)
}

// servedCert is one certificate the watch reports on.
type servedCert struct {
	name string // metric label and notification subject suffix
	leaf func() (*x509.Certificate, error)
	// renewHint is the command that fixes it, for the notification.
	renewHint string
}

// certWatch holds the watch's state between ticks.
type certWatch struct {
	host     string
	pkiDir   string
	db       *corrosion.Client
	notifier certNotifier
	metrics  *metrics.CertMetrics
	certs    []servedCert

	mu       sync.Mutex
	recorded string // serial last confirmed in this host's row
	alerts   map[string]certAlert
}

type certAlert struct {
	tier     int
	notAfter time.Time
	at       time.Time
}

func newCertWatch(host, pkiDir string, db *corrosion.Client, n certNotifier, m *metrics.CertMetrics) *certWatch {
	w := &certWatch{host: host, pkiDir: pkiDir, db: db, notifier: n, metrics: m, alerts: map[string]certAlert{}}
	w.certs = []servedCert{{
		name:      "host",
		leaf:      func() (*x509.Certificate, error) { return pki.ServedHostCertificate(pkiDir) },
		renewHint: fmt.Sprintf("lv host renew-cert %s", host),
	}}
	return w
}

// run ticks until ctx ends.
func (w *certWatch) run(ctx context.Context) {
	w.tick(ctx, time.Now())
	t := time.NewTicker(certWatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			w.tick(ctx, now)
		}
	}
}

// addUI adds the web UI's custom certificate to the watch. Nil-safe.
func (w *certWatch) addUI(u *uiTLS) {
	if w == nil || u == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.certs = append(w.certs, servedCert{
		name:      "ui",
		leaf:      u.CustomLeaf,
		renewHint: fmt.Sprintf("lv host ui-cert set %s --cert <chain.pem> --key <key.pem>", w.host),
	})
}

func (w *certWatch) tick(ctx context.Context, now time.Time) {
	w.recordHostSerial(ctx)
	if w.notifier != nil {
		w.notifier.ProcessOwedRevocations(ctx)
	}
	w.mu.Lock()
	certs := append([]servedCert(nil), w.certs...)
	w.mu.Unlock()
	for _, c := range certs {
		leaf, err := c.leaf()
		if err != nil || leaf == nil {
			w.metrics.Clear(c.name)
			w.mu.Lock()
			delete(w.alerts, c.name)
			w.mu.Unlock()
			continue
		}
		w.metrics.SetExpiry(c.name, leaf.NotAfter)
		w.alert(c, leaf, now)
	}
}

// recordHostSerial moves this host's row onto the serial it serves.
func (w *certWatch) recordHostSerial(ctx context.Context) {
	if w.db == nil {
		return
	}
	leaf, err := pki.ServedHostCertificate(w.pkiDir)
	if err != nil {
		return
	}
	serial := strings.ToLower(leaf.SerialNumber.Text(16))
	w.mu.Lock()
	done := w.recorded == serial
	w.mu.Unlock()
	if done {
		return
	}
	if _, err := corrosion.RecordOwnCertSerial(ctx, w.db, w.host, serial); err != nil {
		slog.Warn("could not re-record this host's certificate serial; peers accept the renewed "+
			"certificate by its predecessor until this succeeds", "serial", serial, "error", err)
		return
	}
	w.mu.Lock()
	w.recorded = serial
	w.mu.Unlock()
}

// certTier is 0 (fine), 1 (within certWarnBefore), 2 (within certCritBefore)
// or 3 (expired).
func certTier(notAfter, now time.Time) int {
	left := notAfter.Sub(now)
	switch {
	case left <= 0:
		return 3
	case left <= certCritBefore:
		return 2
	case left <= certWarnBefore:
		return 1
	}
	return 0
}

// alert notifies when c enters a worse tier, or every certRenotifyEvery while
// it stays in one. A replaced certificate (new NotAfter) starts fresh.
func (w *certWatch) alert(c servedCert, leaf *x509.Certificate, now time.Time) {
	tier := certTier(leaf.NotAfter, now)
	w.mu.Lock()
	prev, seen := w.alerts[c.name]
	if tier == 0 {
		delete(w.alerts, c.name)
		w.mu.Unlock()
		return
	}
	if seen && prev.notAfter.Equal(leaf.NotAfter) && prev.tier >= tier && now.Sub(prev.at) < certRenotifyEvery {
		w.mu.Unlock()
		return
	}
	w.alerts[c.name] = certAlert{tier: tier, notAfter: leaf.NotAfter, at: now}
	w.mu.Unlock()

	kind, sev := "certificate.expiring", notify.SevWarn
	detail := fmt.Sprintf("%s certificate (serial %s) expires %s, in %d days; renew it with `%s`",
		c.name, leaf.SerialNumber.Text(16), leaf.NotAfter.UTC().Format(time.RFC3339),
		int(leaf.NotAfter.Sub(now).Hours()/24), c.renewHint)
	switch tier {
	case 2:
		sev = notify.SevError
	case 3:
		kind, sev = "certificate.expired", notify.SevError
		detail = fmt.Sprintf("%s certificate (serial %s) EXPIRED %s; renew it with `%s`",
			c.name, leaf.SerialNumber.Text(16), leaf.NotAfter.UTC().Format(time.RFC3339), c.renewHint)
	}
	slog.Warn("certificate is close to expiry", "cert", c.name, "serial", leaf.SerialNumber.Text(16),
		"not_after", leaf.NotAfter.UTC().Format(time.RFC3339), "renew_with", c.renewHint)
	if w.notifier != nil {
		w.notifier.NotifyCertificate(kind, sev, w.host+"/"+c.name, detail)
	}
}

// CertWatchOnce runs one pass of the certificate watch for a node built
// without a Daemon (tests/fleet): re-record a renewed serial and process owed
// revocations.
func CertWatchOnce(ctx context.Context, host, pkiDir string, db *corrosion.Client, n certNotifier) {
	newCertWatch(host, pkiDir, db, n, nil).tick(ctx, time.Now())
}
