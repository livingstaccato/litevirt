package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

// qemuConfPath is where libvirt's QEMU driver reads the user QEMU runs as.
const qemuConfPath = "/etc/libvirt/qemu.conf"

// defaultQemuUsers are the distro defaults, in the order tried when qemu.conf
// names no user: Debian/Ubuntu, then Fedora/RHEL.
var defaultQemuUsers = []string{"libvirt-qemu", "qemu"}

// qemuConfUser returns the `user = "..."` qemu.conf sets, or "" when it sets
// none (commented out or absent).
func qemuConfUser(conf string) string {
	sc := bufio.NewScanner(strings.NewReader(conf))
	user := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != "user" {
			continue
		}
		user = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return user
}

// qemuOwner resolves the uid/gid QEMU processes run as, which is the only
// account the migration-TLS key may belong to.
func qemuOwner(confPath string, lookup func(string) (*user.User, error)) (int, int, error) {
	candidates := defaultQemuUsers
	data, err := os.ReadFile(confPath)
	switch {
	case err == nil:
		if u := qemuConfUser(string(data)); u != "" {
			candidates = []string{u}
		}
	case !errors.Is(err, fs.ErrNotExist):
		return -1, -1, fmt.Errorf("read %s: %w", confPath, err)
	}
	for _, name := range candidates {
		u, err := lookup(name)
		if err != nil {
			continue
		}
		uid, err1 := strconv.Atoi(u.Uid)
		gid, err2 := strconv.Atoi(u.Gid)
		if err1 != nil || err2 != nil {
			return -1, -1, fmt.Errorf("QEMU user %q has a non-numeric uid/gid", name)
		}
		return uid, gid, nil
	}
	return -1, -1, fmt.Errorf("cannot tell which user QEMU runs as: tried %s", strings.Join(candidates, ", "))
}

// migrationTLSInstaller is the grpcapi migration-TLS hook: it installs this
// host's migration credentials into QEMU's TLS directory, owned by the QEMU
// user, and reports whether they are in place. It runs at daemon start and
// before each storage migration, so credentials pushed by
// `lv host install-migration-tls` take effect without a restart.
func (d *Daemon) migrationTLSInstaller() func() (bool, error) {
	return func() (bool, error) {
		uid, gid, err := qemuOwner(qemuConfPath, user.Lookup)
		if err != nil {
			return false, err
		}
		return pki.InstallQemuMigrationTLS(d.cfg.PKIDir, pki.QemuTLSDir, uid, gid)
	}
}

// migrationTLSStatusRow is this host's MigrationTLSStatus answer. The server
// fills in the host name and the plaintext flag.
func migrationTLSStatusRow(info pki.MigrationTLSInfo, err error) *pb.MigrationTLSHostStatus {
	if err != nil {
		return &pb.MigrationTLSHostStatus{Error: err.Error()}
	}
	row := &pb.MigrationTLSHostStatus{
		Provisioned:           info.Provisioned,
		ValidationError:       info.ValidationError,
		CertIssuerFingerprint: info.CertIssuerFingerprint,
	}
	if !info.CertNotAfter.IsZero() {
		row.CertNotAfter = timestamppb.New(info.CertNotAfter)
	}
	for _, c := range info.TrustedCAs {
		row.TrustedCas = append(row.TrustedCas, &pb.MigrationTLSCA{Fingerprint: c.Fingerprint, NotAfter: timestamppb.New(c.NotAfter)})
	}
	return row
}

// logMigrationExpiry logs each migration credential that expires within
// pki.MigrationExpiryWarning: Warn before, Error after.
func logMigrationExpiry(log *slog.Logger, info pki.MigrationTLSInfo, now time.Time) {
	for _, e := range info.Expiring(now) {
		fix := "`lv host install-migration-tls --reissue`"
		if strings.HasPrefix(e.What, "CA ") {
			fix = "`lv host rotate-migration-ca`"
		}
		level, verb := slog.LevelWarn, "expires"
		if e.Expired {
			level, verb = slog.LevelError, "expired"
		}
		log.Log(context.Background(), level, fmt.Sprintf("migration TLS: the %s %s %s; storage "+
			"migrations with this host will be refused after that. Fix: %s",
			e.What, verb, e.NotAfter.Format("2006-01-02"), fix))
	}
}

// runMigrationExpiryWatch checks at start and every 24 hours.
func runMigrationExpiryWatch(ctx context.Context, pkiDir string) {
	check := func() {
		info, err := pki.InspectMigrationTLS(pkiDir, time.Now())
		if err == nil && info.Provisioned {
			logMigrationExpiry(slog.Default(), info, time.Now())
		}
	}
	check()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}
