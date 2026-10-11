package grpcapi

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// hostAccessBackup seeds a stopped container "web" whose spec carries a host
// mount and a device, backs it up, and deletes its row, so a restore of it
// is a disaster-recovery restore of a host-access backup.
func hostAccessBackup(t *testing.T) (*Server, *fakeCTRuntime, string, string) {
	t.Helper()
	s, rt := secServer(t)
	enableUsbMountsMemory(s)
	repo := ctTestRepo(t)
	const ts = "2026-06-27T12:00:00Z"
	seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{Template: "download",
		Mounts:  []corrosion.ContainerHostMount{{HostPath: "/srv/data", ContainerPath: "/data"}},
		Devices: []corrosion.ContainerHostDevice{{HostPath: "/dev/ttyUSB0"}}})
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{Name: "web", HostName: "host-a", RepoPath: repo, Timestamp: ts}, bk); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteContainer(context.Background(), s.db, "host-a", "web"); err != nil {
		t.Fatal(err)
	}
	return s, rt, repo, ts
}

// ctRestoreAudit returns the detail of every ct.restore audit row for name.
func ctRestoreAudit(t *testing.T, s *Server, name string) []string {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT detail, result FROM audit_log WHERE action = 'ct.restore' AND target = ? ORDER BY seq`, name)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.String("result")+": "+r.String("detail"))
	}
	return out
}

// After the latch, an admin's restore of a host-access backup whose grant the
// release gate refuses is refused with the gate's text, and tears down what
// it imported: the runtime container is deleted, no row lands, no restore
// marker is left, and the refusal is audited. The refusal names the way out
// (--without-host-access, n1).
//
// Mutation: drop the DeleteContainer, the audit or the hint from
// RestoreContainer's host-access refusal branch — red. (The marker check
// only says nothing is left: a restore marker is written for a proof-carrying
// peer restore, which never reaches this branch, so dropping its removal
// there survives.)
func TestRestoreContainer_HostAccessGateRefusalCleansUp(t *testing.T) {
	s, rt, repo, ts := hostAccessBackup(t)
	s.SetReleaseFeatureGate(latchedButRefusingGate{})
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: "web", HostName: "host-a", RepoPath: repo, Timestamp: ts}, rs)
	wantReleaseRefusal(t, "admin restore of a host-access backup, grant refused", err)
	if err != nil && !strings.Contains(err.Error(), "--without-host-access") {
		t.Errorf("the refusal does not name the way out: %v", err)
	}
	if !slices.Contains(rt.deleteCalls, "web") {
		t.Errorf("the imported container was not deleted; deleteCalls=%v", rt.deleteCalls)
	}
	if row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "web"); row != nil {
		t.Errorf("a refused restore left a row: %+v", row)
	}
	if _, err := os.Stat(s.restoreMarkerPath("web")); !os.IsNotExist(err) {
		t.Errorf("a refused restore left its marker (%v)", err)
	}
	audit := ctRestoreAudit(t, s, "web")
	if !slices.ContainsFunc(audit, func(a string) bool {
		return strings.HasPrefix(a, "error: ") && strings.Contains(a, "release gate refused")
	}) {
		t.Errorf("the refusal was not audited: %q", audit)
	}
}

// n1. While the gate cannot grant the first use (a host down for good, or in
// release probation), an admin restores the container now, without its host
// mounts and devices, by asking for it: no grant is asked, the row and the
// rendered config carry none, and the audit says it was requested and what
// was left out.
//
// Mutation: ignore WithoutHostAccess in authorizeRestoredHostAccess — the
// restore is refused and this goes red.
func TestRestoreContainer_WithoutHostAccessRestoresDespiteTheGate(t *testing.T) {
	s, rt, repo, ts := hostAccessBackup(t)
	s.SetReleaseFeatureGate(latchedButRefusingGate{})
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: "web", HostName: "host-a", RepoPath: repo, Timestamp: ts,
		WithoutHostAccess: true}, rs); err != nil {
		t.Fatalf("admin restore --without-host-access while the gate refuses: %v", err)
	}
	if spec := specOf(t, s, "host-a", "web"); len(spec.Mounts) != 0 || len(spec.Devices) != 0 {
		t.Errorf("the row carries host access: %+v", spec)
	}
	if rb, ok := rt.lastRebuild("web"); !ok || len(rb.cfg.Mounts) != 0 || len(rb.cfg.Devices) != 0 {
		t.Errorf("the config was rendered with %+v (ok %v); want no host access", rb, ok)
	}
	audit := ctRestoreAudit(t, s, "web")
	if !slices.ContainsFunc(audit, func(a string) bool {
		return strings.Contains(a, "--without-host-access") && strings.Contains(a, "mount=/srv/data:/data") &&
			strings.Contains(a, "device=/dev/ttyUSB0")
	}) {
		t.Errorf("the requested strip is not audited with what it left out: %q", audit)
	}
}

// The option is an operator restore's only: a peer move keeps what its
// source row records whatever the request says, and a restore that carries
// no host access is unaffected by it.
//
// Mutation: honour the option on a peer move — red.
func TestAuthorizeRestoredHostAccess_WithoutHostAccess(t *testing.T) {
	s, _ := secServer(t)
	enableUsbMountsMemory(s)
	cs := corrosion.ContainerCreateSpec{Template: "download",
		Mounts: []corrosion.ContainerHostMount{{HostPath: "/srv/data", ContainerPath: "/data"}}}
	source := &corrosion.ContainerRecord{Name: "m", CreateSpec: corrosion.EncodeCreateSpec(cs)}

	got, stripped, g, err := s.authorizeRestoredHostAccess(adminCtx(), cs, nil, false, true)
	if err != nil || len(got.Mounts) != 0 || stripped == "" || passthroughGranted(g) {
		t.Errorf("admin restore without host access: mounts=%v stripped=%q granted=%v err=%v; want stripped, no grant",
			got.Mounts, stripped, passthroughGranted(g), err)
	}
	got, stripped, _, err = s.authorizeRestoredHostAccess(adminCtx(), cs, source, true, true)
	if err != nil || len(got.Mounts) != 1 || stripped != "" {
		t.Errorf("peer move with the option set: mounts=%v stripped=%q err=%v; want the source row's mount kept",
			got.Mounts, stripped, err)
	}
	plain := corrosion.ContainerCreateSpec{Template: "download"}
	if _, stripped, _, err = s.authorizeRestoredHostAccess(adminCtx(), plain, nil, false, true); err != nil || stripped != "" {
		t.Errorf("restore with nothing to strip: stripped=%q err=%v", stripped, err)
	}
}
