package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

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
	// clearAfterFail makes failPush one-shot: the host comes back right after
	// its first failed push, so a later phase would reach it.
	clearAfterFail bool
	// answersStatus keeps the host's daemon answering MigrationTLSStatus while
	// failPush is set: SSH to it fails, gRPC does not. The rotation's preflight
	// then passes, and the failure is met mid-run.
	answersStatus bool
	// installErr is what its daemon's install hook reports.
	installErr string
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
		err := h.failPush
		if h.clearAfterFail {
			h.failPush = nil
		}
		return err
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
			if h.failPush != nil && !h.answersStatus {
				rows = append(rows, &pb.MigrationTLSHostStatus{Host: h.name, Error: "unreachable"})
				continue
			}
			info, err := pki.InspectMigrationTLS(h.pkiDir, time.Now())
			if err != nil {
				return nil, err
			}
			row := &pb.MigrationTLSHostStatus{Host: h.name, Provisioned: info.Provisioned,
				ValidationError: info.ValidationError, CertIssuerFingerprint: info.CertIssuerFingerprint,
				InstallError: h.installErr}
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
	hosts[1].failPush, hosts[1].answersStatus = errors.New("down"), true
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
	hosts[2].failPush, hosts[2].answersStatus = errors.New("connection refused"), true
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
	hosts[1].failPush, hosts[1].answersStatus = errors.New("down"), true
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

// onlyOldCA fails t unless h's migration directory still trusts only oldFP
// and holds a certificate from it: nothing of the rotation reached it.
func onlyOldCA(t *testing.T, h *fakeRotHost, oldFP string) {
	t.Helper()
	info, err := pki.InspectMigrationTLS(h.pkiDir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(info.TrustedCAs) != 1 || info.TrustedCAs[0].Fingerprint != oldFP || info.CertIssuerFingerprint != oldFP {
		t.Errorf("%s = %+v; want the old CA alone, untouched", h.name, info)
	}
}

// A host skipped under --force stays skipped for the rest of the run, even
// once it is reachable again: it is never pushed a later phase.
//
// Mutation: drop the Skipped check in the push loop — node-3 is pushed
// reissue and drop-old once it comes back.
func TestRotateMigrationCA_SkippedHostIsNotPushedLaterInTheRun(t *testing.T) {
	op, hosts := provisionedCluster(t, 3)
	oldFP, _ := pki.CAFileFingerprint(filepath.Join(op, pki.MigrationCACertName))
	hosts[2].failPush, hosts[2].clearAfterFail = errors.New("powered off"), true
	if err := rotate(t, op, hosts, RotateMigrationCAOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	if hosts[2].pushes != 0 {
		t.Errorf("node-3 pushes = %d; want 0 once skipped", hosts[2].pushes)
	}
	onlyOldCA(t, hosts[2], oldFP)
}

// A host skipped in an earlier run stays skipped on the re-run, which does
// not pass --force: it is neither pushed nor gated.
//
// Mutations: drop the Skipped check in the push loop — node-3 is pushed;
// drop the Skipped check in the gate — the re-run stops on node-3, which
// still trusts only the old CA.
func TestRotateMigrationCA_SkippedHostStaysSkippedOnTheRerun(t *testing.T) {
	op, hosts := provisionedCluster(t, 3)
	oldFP, _ := pki.CAFileFingerprint(filepath.Join(op, pki.MigrationCACertName))
	hosts[2].failPush = errors.New("powered off")
	statusDown := func(ctx context.Context) ([]*pb.MigrationTLSHostStatus, error) {
		if r, _ := loadMigrationRotation(op); r != nil && r.Phase == phaseReissue {
			return nil, errors.New("cluster unreachable") // stops the run, even under --force
		}
		return fakeStatus(hosts)(ctx)
	}
	err := RotateMigrationCA(context.Background(), op, asHosts(hosts), statusDown, RotateMigrationCAOptions{Force: true}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("the first run did not stop")
	}
	if r, _ := loadMigrationRotation(op); !r.Skipped["node-3"] || r.Phase != phaseReissue {
		t.Fatalf("state after the first run = %+v; want node-3 skipped, phase reissue", r)
	}
	hosts[2].failPush = nil
	if err := rotate(t, op, hosts, RotateMigrationCAOptions{}); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if hosts[2].pushes != 0 {
		t.Errorf("node-3 pushes = %d; want 0 once skipped", hosts[2].pushes)
	}
	onlyOldCA(t, hosts[2], oldFP)
}

// A host skipped by a failed gate under --force is not pushed later phases.
//
// Mutation: drop the Skipped check in the push loop — node-2 is pushed
// reissue and drop-old after its trust-both gate skipped it.
func TestRotateMigrationCA_GateSkippedHostIsNotPushedLater(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	status := func(ctx context.Context) ([]*pb.MigrationTLSHostStatus, error) {
		rows, err := fakeStatus(hosts)(ctx)
		if err == nil {
			rows[1].TrustedCas = rows[1].TrustedCas[:1] // node-2's daemon never takes the new CA
		}
		return rows, err
	}
	if err := RotateMigrationCA(context.Background(), op, asHosts(hosts), status, RotateMigrationCAOptions{Force: true}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if r, _ := loadMigrationRotation(op); !r.Skipped["node-2"] {
		t.Fatalf("node-2 was not skipped: %+v", r)
	}
	if hosts[1].pushes != 1 {
		t.Errorf("node-2 pushes = %d; want 1 (trust-both only)", hosts[1].pushes)
	}
}

// A run that died after finalize and before "done" was saved, re-run with a
// host still owed drop-old (its gate failed, which clears its done mark),
// finishes: drop-old pushes the CA that is now current, not the next.crt
// finalize renamed away.
//
// Mutation: push nextCACertName in drop-old — the re-run fails reading it.
func TestRotateMigrationCA_DropOldResumesAfterFinalize(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	if err := rotate(t, op, hosts, RotateMigrationCAOptions{}); err != nil {
		t.Fatal(err)
	}
	newFP, _ := pki.CAFileFingerprint(filepath.Join(op, pki.MigrationCACertName))
	r, err := loadMigrationRotation(op)
	if err != nil {
		t.Fatal(err)
	}
	r.Phase = phaseDropOld // finalize ran; "done" was never saved
	r.Done["node-1"] = slices.DeleteFunc(r.Done["node-1"], func(p string) bool { return p == phaseDropOld })
	if err := r.save(op); err != nil {
		t.Fatal(err)
	}
	before := hosts[0].pushes
	if err := rotate(t, op, hosts, RotateMigrationCAOptions{}); err != nil {
		t.Fatalf("resume after finalize: %v", err)
	}
	if hosts[0].pushes != before+1 {
		t.Errorf("node-1 pushes on resume = %d; want 1", hosts[0].pushes-before)
	}
	info, _ := pki.InspectMigrationTLS(hosts[0].pkiDir, time.Now())
	if len(info.TrustedCAs) != 1 || info.TrustedCAs[0].Fingerprint != newFP {
		t.Errorf("node-1 = %+v; want the new CA alone", info)
	}
	if MigrationRotationInProgress(op) {
		t.Error("rotation still in progress after the resume")
	}
}

// nothingMinted fails t if the rotation left any trace on the operator machine.
func nothingMinted(t *testing.T, op string) {
	t.Helper()
	for _, f := range []string{nextCACertName, nextCAKeyName, bundleCACertName, rotationFileName} {
		if _, err := os.Stat(filepath.Join(op, f)); !os.IsNotExist(err) {
			t.Errorf("%s exists after a refused start", f)
		}
	}
}

// A host with no migration credentials is refused before anything is minted,
// naming the command that provisions it — which works only while no rotation
// is in progress.
//
// Mutation: skip the preflight — the run mints next.crt and stalls at the
// trust-both gate instead.
func TestRotateMigrationCA_PreflightRefusesAnUnprovisionedHost(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	if err := os.RemoveAll(pki.MigrationDir(hosts[1].pkiDir)); err != nil {
		t.Fatal(err)
	}
	err := rotate(t, op, hosts, RotateMigrationCAOptions{})
	if err == nil || !strings.Contains(err.Error(), "node-2") || !strings.Contains(err.Error(), "install-migration-tls`") {
		t.Fatalf("err = %v; want a refusal naming node-2 and install-migration-tls", err)
	}
	nothingMinted(t, op)
	if hosts[0].pushes != 0 {
		t.Errorf("node-1 was pushed %d time(s) before the refusal", hosts[0].pushes)
	}
}

// A host whose set is missing one file is refused as incomplete, with the
// --reissue remedy, not as unprovisioned.
//
// Mutation: skip the preflight — the run mints next.crt.
func TestRotateMigrationCA_PreflightRefusesAnIncompleteSet(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	if err := os.Remove(filepath.Join(pki.MigrationDir(hosts[1].pkiDir), pki.MigrationHostKeyName)); err != nil {
		t.Fatal(err)
	}
	err := rotate(t, op, hosts, RotateMigrationCAOptions{})
	if err == nil || !strings.Contains(err.Error(), "incomplete set") || !strings.Contains(err.Error(), "--reissue") {
		t.Fatalf("err = %v; want node-2 refused as an incomplete set, remedy --reissue", err)
	}
	nothingMinted(t, op)
}

// Run on a machine whose migration CA is not the cluster's, the rotation is
// refused before it mints or pushes: trust-both would otherwise push a bundle
// of the wrong old CA and the new one, which every host's certificate fails.
//
// Mutation: drop the fingerprint check — the run mints and pushes.
func TestRotateMigrationCA_PreflightRefusesAMachineWithAnotherCA(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	if err := pki.GenerateMigrationCA(filepath.Join(op, pki.MigrationCACertName), filepath.Join(op, pki.MigrationCAKeyName)); err != nil {
		t.Fatal(err)
	}
	err := rotate(t, op, hosts, RotateMigrationCAOptions{})
	if err == nil || !strings.Contains(err.Error(), "node-1, node-2") || !strings.Contains(err.Error(), "`lv host init` ran") {
		t.Fatalf("err = %v; want a refusal naming both hosts and where to run it", err)
	}
	nothingMinted(t, op)
	for _, h := range hosts {
		if h.pushes != 0 {
			t.Errorf("%s was pushed %d time(s)", h.name, h.pushes)
		}
	}
}

// A daemon too old to answer MigrationTLSStatus is found before anything is
// pushed, not after every host was.
//
// Mutation: drop the Unimplemented check — the error carries no upgrade hint.
func TestRotateMigrationCA_PreflightRefusesAnOldDaemon(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	old := func(context.Context) ([]*pb.MigrationTLSHostStatus, error) {
		return nil, grpcstatus.Error(codes.Unimplemented, "unknown method MigrationTLSStatus")
	}
	err := RotateMigrationCA(context.Background(), op, asHosts(hosts), old, RotateMigrationCAOptions{Force: true}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "upgraded node") {
		t.Fatalf("err = %v; want a refusal pointing the CLI at an upgraded node", err)
	}
	nothingMinted(t, op)
	if hosts[0].pushes != 0 {
		t.Errorf("node-1 was pushed %d time(s)", hosts[0].pushes)
	}
}

// A host that cannot answer refuses the start without --force; with it, the
// rotation proceeds and leaves that host behind.
//
// Mutation: ignore force on an error row — the --force run is refused too.
func TestRotateMigrationCA_PreflightErrorRowNeedsForce(t *testing.T) {
	op, hosts := provisionedCluster(t, 3)
	hosts[2].failPush = errors.New("powered off")
	err := rotate(t, op, hosts, RotateMigrationCAOptions{})
	if err == nil || !strings.Contains(err.Error(), "node-3") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("err = %v; want a refusal naming node-3 and --force", err)
	}
	nothingMinted(t, op)
	if err := rotate(t, op, hosts, RotateMigrationCAOptions{Force: true}); err != nil {
		t.Fatalf("--force: %v", err)
	}
}

// The trust-both gate holds a host whose set fails validation even though it
// trusts the new CA: the daemon would refuse to install it.
//
// Mutation: drop the ValidationError clause from trust-both — the run passes
// the gate and reaches reissue.
func TestRotateMigrationCA_TrustBothGateHoldsAFailedValidation(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	status := func(ctx context.Context) ([]*pb.MigrationTLSHostStatus, error) {
		rows, err := fakeStatus(hosts)(ctx)
		if r, _ := loadMigrationRotation(op); err == nil && r != nil {
			rows[1].ValidationError = "certificate signed by unknown authority"
		}
		return rows, err
	}
	err := RotateMigrationCA(context.Background(), op, asHosts(hosts), status, RotateMigrationCAOptions{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "node-2") || !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("err = %v; want the trust-both gate to stop on node-2's validation error", err)
	}
	if r, _ := loadMigrationRotation(op); r.Phase != phaseTrustBoth {
		t.Fatalf("phase = %s; want still trust-both", r.Phase)
	}
}

// Every gate holds a host whose daemon cannot install its set.
//
// Mutation: drop the InstallError check from phaseUnmet — the run finishes.
func TestRotateMigrationCA_GateHoldsAnInstallRefusal(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	status := func(ctx context.Context) ([]*pb.MigrationTLSHostStatus, error) {
		if r, _ := loadMigrationRotation(op); r != nil {
			hosts[1].installErr = "/etc/pki/qemu holds files litevirt did not put there"
		}
		return fakeStatus(hosts)(ctx)
	}
	err := RotateMigrationCA(context.Background(), op, asHosts(hosts), status, RotateMigrationCAOptions{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "node-2") || !strings.Contains(err.Error(), "/etc/pki/qemu") {
		t.Fatalf("err = %v; want the gate to stop on node-2's install refusal", err)
	}
}

// Two rotations on one day keep both retired certificates: the second goes to
// -2 instead of overwriting the first.
//
// Mutation: always use the base name — the first retired CA is overwritten.
func TestRotateMigrationCA_TwoRotationsInOneDayKeepBothRetiredCAs(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	day := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	opts := RotateMigrationCAOptions{Now: func() time.Time { return day }}
	first, _ := os.ReadFile(filepath.Join(op, pki.MigrationCACertName))
	if err := rotate(t, op, hosts, opts); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(filepath.Join(op, pki.MigrationCACertName))
	if err := rotate(t, op, hosts, opts); err != nil {
		t.Fatalf("second rotation: %v", err)
	}
	a, errA := os.ReadFile(filepath.Join(op, "migration-ca.retired-20261004.crt"))
	b, errB := os.ReadFile(filepath.Join(op, "migration-ca.retired-20261004-2.crt"))
	if errA != nil || errB != nil {
		t.Fatalf("retired certificates: %v, %v; want both", errA, errB)
	}
	if !bytes.Equal(a, first) || !bytes.Equal(b, second) || bytes.Equal(a, b) {
		t.Error("the retired certificates are not the two CAs rotated out, in order")
	}
}

// A finalize re-run after it already retired the CA reuses that file rather
// than writing a second copy under -2.
//
// Mutation: skip the same-bytes check — the re-run writes -2.
func TestFinalizeMigrationRotation_RerunDoesNotDuplicateTheRetiredCA(t *testing.T) {
	op := t.TempDir()
	writeRotation(t, op, phaseDropOld, false)
	r, _ := loadMigrationRotation(op)
	day := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	cur, _ := os.ReadFile(filepath.Join(op, pki.MigrationCACertName))
	if err := os.WriteFile(filepath.Join(op, "migration-ca.retired-20261004.crt"), cur, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := finalizeMigrationRotation(op, r, day); err != nil {
		t.Fatal(err)
	}
	if got, _ := filepath.Glob(filepath.Join(op, "migration-ca.retired-*.crt")); len(got) != 1 {
		t.Errorf("retired certificates = %v; want the one already written", got)
	}
}
