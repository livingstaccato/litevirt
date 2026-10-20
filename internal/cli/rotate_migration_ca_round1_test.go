package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
)

func gateRow(issuer, validation string, trusts ...string) *pb.MigrationTLSHostStatus {
	r := &pb.MigrationTLSHostStatus{Host: "h", Provisioned: true, CertIssuerFingerprint: issuer, ValidationError: validation}
	for _, fp := range trusts {
		r.TrustedCas = append(r.TrustedCas, &pb.MigrationTLSCA{Fingerprint: fp})
	}
	return r
}

// The drop-old (and cutover) gate is what makes "every host trusts only the
// new CA" true when the rotation says done: a host still trusting the old CA
// beside the new one does not pass it, however valid its certificate.
//
// Mutation: weaken the drop-old gate to "trusts the new CA" (R4) — the
// two-CA row passes.
func TestPhaseUnmet_DropOldRequiresTheNewCAAlone(t *testing.T) {
	for _, phase := range []string{phaseDropOld, phaseCutover} {
		if why := phaseUnmet(phase, "new", gateRow("new", "", "old", "new")); why == "" {
			t.Errorf("%s: a host still trusting the old CA passed", phase)
		}
		if why := phaseUnmet(phase, "new", gateRow("old", "", "new")); why == "" {
			t.Errorf("%s: a certificate from the old CA passed", phase)
		}
		if why := phaseUnmet(phase, "new", gateRow("new", "", "new")); why != "" {
			t.Errorf("%s: the finished host was held: %s", phase, why)
		}
	}
}

// The reissue gate keeps drop-old from removing the old CA from a host whose
// certificate the old CA still signs.
//
// Mutation: drop the issuer comparison from the reissue gate (R14) — the
// old-CA certificate passes.
func TestPhaseUnmet_ReissueRequiresACertificateFromTheNewCA(t *testing.T) {
	if why := phaseUnmet(phaseReissue, "new", gateRow("old", "", "old", "new")); why == "" {
		t.Error("a certificate still from the old CA passed the reissue gate")
	}
	if why := phaseUnmet(phaseReissue, "new", gateRow("new", "", "old", "new")); why != "" {
		t.Errorf("a reissued host was held: %s", why)
	}
}

// A host that joins while a run executes is not in that run's host list, so
// the run would never push it the later phases and would still say every
// host trusts only the new CA. The gate stops on any host it is not
// rotating, --force or not, and a re-run (which lists hosts afresh) brings it
// through.
//
// Mutation: ignore status rows for hosts outside the run's list in
// gatePhase — the first run finishes and node-3 keeps trusting the old CA.
func TestRotateMigrationCA_AHostThatJoinedMidRunStopsTheGate(t *testing.T) {
	for _, force := range []bool{false, true} {
		op, hosts := provisionedCluster(t, 3)
		// node-3 is added after the run listed hosts and passed its preflight.
		calls := 0
		joins := func(ctx context.Context) ([]*pb.MigrationTLSHostStatus, error) {
			calls++
			if calls == 1 {
				return fakeStatus(hosts[:2])(ctx)
			}
			return fakeStatus(hosts)(ctx)
		}
		err := RotateMigrationCA(t.Context(), op, asHosts(hosts[:2]), joins,
			RotateMigrationCAOptions{Force: force}, &strings.Builder{})
		if err == nil || !strings.Contains(err.Error(), "node-3") {
			t.Fatalf("force=%v: err = %v; want the run stopped, naming node-3", force, err)
		}
		r, lerr := loadMigrationRotation(op)
		if lerr != nil || !r.inProgress() {
			t.Fatalf("force=%v: rotation = %+v, %v; want it still in progress", force, r, lerr)
		}
		if r.Skipped["node-3"] {
			t.Fatalf("force=%v: node-3 was recorded skipped; it was never part of the run", force)
		}
		if err := rotate(t, op, hosts, RotateMigrationCAOptions{Force: force}); err != nil {
			t.Fatalf("force=%v: re-run with every host: %v", force, err)
		}
		newFP, _ := pki.CAFileFingerprint(filepath.Join(op, pki.MigrationCACertName))
		info, _ := pki.InspectMigrationTLS(hosts[2].pkiDir, time.Now())
		if len(info.TrustedCAs) != 1 || info.TrustedCAs[0].Fingerprint != newFP || info.CertIssuerFingerprint != newFP {
			t.Errorf("force=%v: node-3 = %+v; want only the new CA, with a certificate from it", force, info)
		}
	}
}

// A rotation state file that cannot be read is treated as a rotation in
// progress, so lv host install-migration-tls refuses rather than issuing
// from a CA the rotation may be replacing.
//
// Mutation: read an unreadable state as "not in progress" (R12) — false.
func TestMigrationRotationInProgress_UnreadableStateFailsClosed(t *testing.T) {
	op := t.TempDir()
	if MigrationRotationInProgress(op) {
		t.Fatal("no state file reads as a rotation in progress")
	}
	if err := os.Mkdir(filepath.Join(op, rotationFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if !MigrationRotationInProgress(op) {
		t.Fatal("an unreadable rotation state reads as no rotation")
	}
}

// Two runs on the operator machine at once would each mint a next CA. The
// second refuses before it mints or pushes anything, and runs once the first
// lets go.
//
// Mutation: skip lockMigrationRotation — the second run mints.
func TestRotateMigrationCA_RefusesWhileAnotherRunHoldsTheLock(t *testing.T) {
	op, hosts := provisionedCluster(t, 2)
	unlock, err := lockMigrationRotation(op)
	if err != nil {
		t.Fatal(err)
	}
	err = rotate(t, op, hosts, RotateMigrationCAOptions{})
	if err == nil || !strings.Contains(err.Error(), "another `lv host rotate-migration-ca`") {
		t.Fatalf("err = %v; want a refusal naming the other run", err)
	}
	nothingMinted(t, op)
	for _, h := range hosts {
		if h.pushes != 0 {
			t.Errorf("%s was pushed %d time(s)", h.name, h.pushes)
		}
	}
	unlock()
	if err := rotate(t, op, hosts, RotateMigrationCAOptions{}); err != nil {
		t.Fatalf("after the lock is released: %v", err)
	}
}

// The same host already present when the run starts is refused by the
// preflight, before anything is minted.
//
// Mutation: ignore unlisted rows in preflightRotation — the run mints.
func TestRotateMigrationCA_PreflightRefusesAHostTheRunDidNotList(t *testing.T) {
	op, hosts := provisionedCluster(t, 3)
	err := RotateMigrationCA(t.Context(), op, asHosts(hosts[:2]), fakeStatus(hosts),
		RotateMigrationCAOptions{Force: true}, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "node-3") {
		t.Fatalf("err = %v; want a refusal naming node-3", err)
	}
	nothingMinted(t, op)
}
