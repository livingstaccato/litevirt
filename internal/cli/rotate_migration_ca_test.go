package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
)

// fakeRotHost is a host whose migration directory is a temp dir. Push writes
// the files there, so the fake status reads exactly what a daemon would.
type fakeRotHost struct {
	name, addr string
	pkiDir     string
	failPush   error
	pushes     int
}

func (h *fakeRotHost) Name() string    { return h.name }
func (h *fakeRotHost) Address() string { return h.addr }

// Provisioned reports whether the host holds a certificate, so
// provisionedCluster's InstallMigrationTLS sees unprovisioned hosts and mints
// the operator's CA instead of refusing a second one.
func (h *fakeRotHost) Provisioned(context.Context) (bool, error) {
	_, err := os.Stat(filepath.Join(pki.MigrationDir(h.pkiDir), pki.MigrationHostCertName))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
func (h *fakeRotHost) Push(_ context.Context, files []migrationFile) error {
	if h.failPush != nil {
		return h.failPush
	}
	h.pushes++
	for _, f := range files {
		data, err := os.ReadFile(f.local)
		if err != nil {
			return err
		}
		dst := filepath.Join(pki.MigrationDir(h.pkiDir), filepath.Base(f.remote))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// fakeStatus answers MigrationTLSStatus from each fake host's directory, as
// the daemon's pki.InspectMigrationTLS hook would.
func fakeStatus(hosts []*fakeRotHost) MigrationTLSStatusFunc {
	return func(context.Context) ([]*pb.MigrationTLSHostStatus, error) {
		var rows []*pb.MigrationTLSHostStatus
		for _, h := range hosts {
			if h.failPush != nil {
				rows = append(rows, &pb.MigrationTLSHostStatus{Host: h.name, Error: "unreachable"})
				continue
			}
			info, err := pki.InspectMigrationTLS(h.pkiDir, time.Now())
			if err != nil {
				return nil, err
			}
			row := &pb.MigrationTLSHostStatus{Host: h.name, Provisioned: info.Provisioned,
				ValidationError: info.ValidationError, CertIssuerFingerprint: info.CertIssuerFingerprint}
			for _, c := range info.TrustedCAs {
				row.TrustedCas = append(row.TrustedCas, &pb.MigrationTLSCA{Fingerprint: c.Fingerprint})
			}
			rows = append(rows, row)
		}
		return rows, nil
	}
}

// provisionedCluster is an operator pkiDir plus n hosts provisioned from its CA.
func provisionedCluster(t *testing.T, n int) (string, []*fakeRotHost) {
	t.Helper()
	op := t.TempDir()
	var hosts []*fakeRotHost
	var ifaces []MigrationTLSHost
	for i := 0; i < n; i++ {
		h := &fakeRotHost{name: "node-" + string(rune('1'+i)), addr: "10.0.0." + string(rune('1'+i)), pkiDir: t.TempDir()}
		hosts = append(hosts, h)
		ifaces = append(ifaces, h)
	}
	if err := InstallMigrationTLS(context.Background(), op, ifaces, true, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		h.pushes = 0 // count the rotation's pushes, not provisioning's
	}
	return op, hosts
}

func asHosts(hs []*fakeRotHost) []MigrationTLSHost {
	out := make([]MigrationTLSHost, len(hs))
	for i, h := range hs {
		out[i] = h
	}
	return out
}

func rotate(t *testing.T, op string, hosts []*fakeRotHost, opts RotateMigrationCAOptions) error {
	t.Helper()
	return RotateMigrationCA(context.Background(), op, asHosts(hosts), fakeStatus(hosts), opts, &bytes.Buffer{})
}

// Every host ends on the new CA alone; the operator machine holds the new CA
// as current, the old key is gone, the old certificate is retired.
//
// Mutation: skip the drop-old phase — hosts still trust two CAs.
func TestRotateMigrationCA_OverlapEndsEveryHostOnTheNewCAAlone(t *testing.T) {
	op, hosts := provisionedCluster(t, 3)
	oldFP, _ := pki.CAFileFingerprint(filepath.Join(op, pki.MigrationCACertName))
	if err := rotate(t, op, hosts, RotateMigrationCAOptions{}); err != nil {
		t.Fatal(err)
	}
	newFP, _ := pki.CAFileFingerprint(filepath.Join(op, pki.MigrationCACertName))
	if newFP == oldFP {
		t.Fatal("the operator's current CA did not change")
	}
	for _, h := range hosts {
		info, _ := pki.InspectMigrationTLS(h.pkiDir, time.Now())
		if len(info.TrustedCAs) != 1 || info.TrustedCAs[0].Fingerprint != newFP || info.CertIssuerFingerprint != newFP || info.ValidationError != "" {
			t.Errorf("%s = %+v; want only the new CA", h.name, info)
		}
	}
	for _, gone := range []string{nextCACertName, nextCAKeyName, bundleCACertName} {
		if _, err := os.Stat(filepath.Join(op, gone)); !os.IsNotExist(err) {
			t.Errorf("%s still exists after the rotation", gone)
		}
	}
	retired, _ := filepath.Glob(filepath.Join(op, "migration-ca.retired-*.crt"))
	if len(retired) != 1 {
		t.Errorf("retired certificates = %v; want one", retired)
	}
	if MigrationRotationInProgress(op) {
		t.Error("rotation still in progress after it finished")
	}
}

// Between phases every host still accepts every other: after trust-both, a
// host with an old certificate and one with a new certificate both validate.
//
// Mutation: push the new certificate in trust-both — the gate refuses
// (hosts that do not yet trust the new CA are invalid) and the run errors.
func TestRotateMigrationCA_TrustBothDoesNotTouchCertificates(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	oldFP, _ := pki.CAFileFingerprint(filepath.Join(op, pki.MigrationCACertName))
	hosts[1].failPush = errors.New("down")
	_ = rotate(t, op, hosts, RotateMigrationCAOptions{}) // stops at node-2's trust-both push
	info, _ := pki.InspectMigrationTLS(hosts[0].pkiDir, time.Now())
	if len(info.TrustedCAs) != 2 || info.CertIssuerFingerprint != oldFP {
		t.Fatalf("node-1 after trust-both = %+v; want both CAs, old certificate", info)
	}
}

// Review focus 4: an unreachable host stops the run with progress saved and
// names the host; a re-run once it is back finishes.
//
// Mutation: do not save after each host — the re-run pushes to node-1 again.
func TestRotateMigrationCA_UnreachableHostStopsAndResumes(t *testing.T) {
	op, hosts := provisionedCluster(t, 3)
	hosts[2].failPush = errors.New("connection refused")
	err := rotate(t, op, hosts, RotateMigrationCAOptions{})
	if err == nil || !strings.Contains(err.Error(), "node-3") {
		t.Fatalf("err = %v; want a stop naming node-3", err)
	}
	if !MigrationRotationInProgress(op) {
		t.Fatal("progress was not saved")
	}
	before := hosts[0].pushes
	hosts[2].failPush = nil
	if err := rotate(t, op, hosts, RotateMigrationCAOptions{}); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if hosts[0].pushes != before+2 { // reissue + drop-old; trust-both was already done
		t.Errorf("node-1 pushes on resume = %d; want 2", hosts[0].pushes-before)
	}
}

// diskProgressHost records, at each push, which hosts the state file on disk
// already says finished this phase — what a re-run would see if the process
// died right then.
type diskProgressHost struct {
	*fakeRotHost
	op     string
	onDisk map[string][]string // phase -> hosts done on disk when this host was pushed
}

func (h *diskProgressHost) Push(ctx context.Context, files []migrationFile) error {
	r, err := loadMigrationRotation(h.op)
	if err != nil {
		return err
	}
	if h.onDisk == nil {
		h.onDisk = map[string][]string{}
	}
	for host := range r.Done {
		if r.hostDone(host, r.Phase) {
			h.onDisk[r.Phase] = append(h.onDisk[r.Phase], host)
		}
	}
	return h.fakeRotHost.Push(ctx, files)
}

// A crash between two hosts loses nothing: each host's progress is on disk
// before the next host is pushed.
//
// Mutation: do not save after each host — when node-2 is pushed, the file
// does not yet say node-1 finished.
func TestRotateMigrationCA_SavesEachHostBeforeTheNext(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	second := &diskProgressHost{fakeRotHost: hosts[1], op: op}
	err := RotateMigrationCA(context.Background(), op, []MigrationTLSHost{hosts[0], second},
		fakeStatus(hosts), RotateMigrationCAOptions{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{phaseTrustBoth, phaseReissue, phaseDropOld} {
		if got := second.onDisk[phase]; len(got) != 1 || got[0] != "node-1" {
			t.Errorf("%s: done on disk when node-2 was pushed = %v; want [node-1]", phase, got)
		}
	}
}

// Mutation: ignore Force on a push error — the run stops.
func TestRotateMigrationCA_ForceSkipsAndNamesTheHost(t *testing.T) {
	op, hosts := provisionedCluster(t, 3)
	hosts[2].failPush = errors.New("powered off")
	var out bytes.Buffer
	err := RotateMigrationCA(context.Background(), op, asHosts(hosts), fakeStatus(hosts), RotateMigrationCAOptions{Force: true}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "node-3") || !strings.Contains(out.String(), "install-migration-tls --reissue") {
		t.Errorf("output does not name the skipped host and its remedy:\n%s", out.String())
	}
}

// The gate reads the daemon's view, not the push's success.
//
// Mutation: skip the gate after trust-both — the run reaches reissue.
func TestRotateMigrationCA_GateRefusesAHostThatDidNotTakeThePush(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	status := func(ctx context.Context) ([]*pb.MigrationTLSHostStatus, error) {
		rows, err := fakeStatus(hosts)(ctx)
		if err == nil {
			rows[1].TrustedCas = rows[1].TrustedCas[:1] // node-2's daemon still sees only the old CA
		}
		return rows, err
	}
	err := RotateMigrationCA(context.Background(), op, asHosts(hosts), status, RotateMigrationCAOptions{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "node-2") {
		t.Fatalf("err = %v; want the gate to stop on node-2", err)
	}
	r, _ := loadMigrationRotation(op)
	if r.Phase != phaseTrustBoth {
		t.Fatalf("phase = %s; want still trust-both", r.Phase)
	}
}

// Mutation: push the bundle in cutover — hosts end trusting two CAs.
func TestRotateMigrationCA_NoOverlapIsOnePassToTheNewCAAlone(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	if err := rotate(t, op, hosts, RotateMigrationCAOptions{NoOverlap: true}); err != nil {
		t.Fatal(err)
	}
	newFP, _ := pki.CAFileFingerprint(filepath.Join(op, pki.MigrationCACertName))
	for _, h := range hosts {
		if h.pushes != 1 {
			t.Errorf("%s pushes = %d; want 1", h.name, h.pushes)
		}
		info, _ := pki.InspectMigrationTLS(h.pkiDir, time.Now())
		if len(info.TrustedCAs) != 1 || info.CertIssuerFingerprint != newFP {
			t.Errorf("%s = %+v; want only the new CA", h.name, info)
		}
	}
}

// Review focus 3. Mutation: drop the NoOverlap comparison — the second run
// silently continues in overlap mode.
func TestRotateMigrationCA_RefusesToSwitchModeMidRotation(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	hosts[1].failPush = errors.New("down")
	_ = rotate(t, op, hosts, RotateMigrationCAOptions{})
	hosts[1].failPush = nil
	err := rotate(t, op, hosts, RotateMigrationCAOptions{NoOverlap: true})
	if err == nil || !strings.Contains(err.Error(), "--no-overlap") {
		t.Fatalf("err = %v; want a refusal naming --no-overlap", err)
	}
}

// Mutation: drop the key check — a machine without the CA key mints a new CA.
func TestRotateMigrationCA_RefusesWithoutTheCAKey(t *testing.T) {
	op, hosts := provisionedCluster(t, 1)
	os.Remove(filepath.Join(op, pki.MigrationCAKeyName))
	if err := rotate(t, op, hosts, RotateMigrationCAOptions{}); err == nil {
		t.Fatal("rotated without the CA key")
	}
	if _, err := os.Stat(filepath.Join(op, nextCACertName)); !os.IsNotExist(err) {
		t.Fatal("minted a next CA without the current key")
	}
}

// Review focus 2: a crash left the certificate renamed but not the key. The
// re-run finishes the rename; the pair always matches.
//
// Mutation: in finalize, return early when next.crt is absent — the old key
// stays as current.
func TestFinalizeMigrationRotation_FinishesAHalfDoneRename(t *testing.T) {
	op := t.TempDir()
	writeRotation(t, op, phaseDropOld, false)
	if err := os.Rename(filepath.Join(op, nextCACertName), filepath.Join(op, pki.MigrationCACertName)); err != nil {
		t.Fatal(err)
	}
	r, _ := loadMigrationRotation(op)
	if err := finalizeMigrationRotation(op, r, time.Now()); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(op, pki.MigrationCACertName)
	key := filepath.Join(op, pki.MigrationCAKeyName)
	cert, k := filepath.Join(op, "h.crt"), filepath.Join(op, "h.key")
	if err := pki.GenerateHostCert(ca, key, cert, k, "x", nil); err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(ca)
	certPEM, _ := os.ReadFile(cert)
	keyPEM, _ := os.ReadFile(k)
	if _, _, err := pki.ValidateMigrationCredentials(caPEM, certPEM, keyPEM, time.Now()); err != nil {
		t.Fatalf("current CA certificate and key do not match after finalize: %v", err)
	}
}

// A saved phase this build does not know (a hand-edited or newer state file)
// stops the run; it must not fall through to finalize with nothing pushed.
//
// Mutation: drop the unknown-phase check — finalize makes the new CA current
// while every host still holds only the old one.
func TestRotateMigrationCA_RefusesAnUnknownSavedPhase(t *testing.T) {
	op, hosts := provisionedCluster(t, 1)
	oldFP, _ := pki.CAFileFingerprint(filepath.Join(op, pki.MigrationCACertName))
	if err := pki.GenerateMigrationCA(filepath.Join(op, nextCACertName), filepath.Join(op, nextCAKeyName)); err != nil {
		t.Fatal(err)
	}
	newFP, _ := pki.CAFileFingerprint(filepath.Join(op, nextCACertName))
	if err := (&migrationRotation{Phase: "reissued", NewCAFingerprint: newFP}).save(op); err != nil {
		t.Fatal(err)
	}
	err := rotate(t, op, hosts, RotateMigrationCAOptions{})
	if err == nil || !strings.Contains(err.Error(), "reissued") {
		t.Fatalf("err = %v; want a refusal naming the unknown phase", err)
	}
	if fp, _ := pki.CAFileFingerprint(filepath.Join(op, pki.MigrationCACertName)); fp != oldFP {
		t.Fatal("finalize made the new CA current on an unknown phase")
	}
}

// A host whose daemon did not take the push is pushed again on the re-run:
// the push returning nil is not the phase being done on that host.
//
// Mutation: keep the host marked done when its gate fails — the re-run
// re-checks without re-pushing and stops on node-2 again.
func TestRotateMigrationCA_RerunRepushesAHostThatFailedItsGate(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	// node-2's first trust-both push is lost after it returns: its ca.crt is
	// put back to the old CA alone before the gate looks.
	lost := filepath.Join(pki.MigrationDir(hosts[1].pkiDir), pki.MigrationCAName)
	oldCA, err := os.ReadFile(lost)
	if err != nil {
		t.Fatal(err)
	}
	status := func(ctx context.Context) ([]*pb.MigrationTLSHostStatus, error) {
		if hosts[1].pushes == 1 {
			if err := os.WriteFile(lost, oldCA, 0o644); err != nil {
				return nil, err
			}
		}
		return fakeStatus(hosts)(ctx)
	}
	err = RotateMigrationCA(context.Background(), op, asHosts(hosts), status, RotateMigrationCAOptions{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "node-2") {
		t.Fatalf("err = %v; want the gate to stop on node-2", err)
	}
	if err := rotate(t, op, hosts, RotateMigrationCAOptions{}); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if hosts[0].pushes != 3 || hosts[1].pushes != 4 {
		t.Errorf("pushes = %d, %d; want 3 (one per phase) and 4 (trust-both twice)", hosts[0].pushes, hosts[1].pushes)
	}
}
