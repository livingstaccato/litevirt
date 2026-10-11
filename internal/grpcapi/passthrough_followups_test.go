package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
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

// I-1. A container whose host-access lock a stuck refresh holds: the start
// and lv ct convert fail Unavailable (retryable) naming why, rather than
// Internal or FailedPrecondition, and the container's own lock is released
// with them, so its stop stays reachable.
//
// Mutation: map the runtime error as before (Internal / FailedPrecondition)
// — red.
func TestHostAccessBusy_IsUnavailableAndReleasesTheContainer(t *testing.T) {
	s, rt := secServer(t)
	enableUsbMountsMemory(s)
	seedSecCT(t, s, rt, "a", "stopped", corrosion.ContainerCreateSpec{Template: "download"})
	busy := fmt.Errorf("container %q: %w", "a", lxc.ErrHostAccessBusy)
	rt.startErr = busy
	_, err := s.StartContainer(adminCtx(), &pb.StartContainerRequest{Name: "a", HostName: "host-a"})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), lxc.ErrHostAccessBusy.Error()) {
		t.Errorf("start behind a stuck host-access refresh = %v; want Unavailable naming it", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.StopContainer(adminCtx(), &pb.StopContainerRequest{Name: "a", HostName: "host-a"})
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stop could not take the container's lock after a refused start")
	}
	rt.startErr = nil
	rt.hostAccessErr = busy
	_, err = s.ConvertContainer(adminCtx(), &pb.ConvertContainerRequest{Name: "a", HostName: "host-a", SetHostAccess: true,
		Mounts: []*pb.ContainerMount{{HostPath: "/srv/data", ContainerPath: "/data"}}})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("convert behind a stuck host-access refresh = %v; want Unavailable", err)
	}
}

// m-1, m-2. The way out (--without-host-access) is named only where it helps:
// on a refusal that will last (the gate's FailedPrecondition, or a first use
// some host has not acknowledged), and only on a restore that accepts the
// flag — never on a replica restore, whose request has no such option, and
// never on a transient read error, where a plain retry is the answer.
//
// Mutation: name it on every error, or on the replica path — red.
func TestRestoreHostAccessRefusal_HintOnlyWhereItHelps(t *testing.T) {
	const hint = "--without-host-access"
	gate := status.Error(codes.FailedPrecondition, "the cluster upgrade must finish first (usb_mounts_memory needs release_2026_11_v1): host-z does not advertise it")
	unacked := status.Error(codes.Unavailable, "usb_mounts_memory's use is recorded here but not yet acknowledged by host-z; the write is refused until every host holds the record — retry")
	transient := status.Error(codes.Unavailable, "read whether usb_mounts_memory is in use: database is locked")
	replica := context.WithValue(adminCtx(), operatorReplicaRestoreKey{}, true)
	for _, tc := range []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"gate refusal", adminCtx(), gate, true},
		{"unacknowledged first use", adminCtx(), unacked, true},
		{"transient read error", adminCtx(), transient, false},
		{"replica restore, gate refusal", replica, gate, false},
		{"replica restore, unacknowledged", replica, unacked, false},
	} {
		got := restoreHostAccessRefusal(tc.ctx, tc.err)
		if status.Code(got) != status.Code(tc.err) || !strings.HasPrefix(status.Convert(got).Message(), status.Convert(tc.err).Message()) {
			t.Errorf("%s: %v; want the gate's own code and text first", tc.name, got)
		}
		if strings.Contains(got.Error(), hint) != tc.want {
			t.Errorf("%s: %v; want hint=%v", tc.name, got, tc.want)
		}
	}
}

// m-3. The "restored --without-host-access" row is written once the restore
// has landed: a restore that fails after the strip (here, its config render)
// leaves no "ok" row claiming a container that does not exist.
//
// Mutation: write the row where the strip is decided, as before — red.
func TestRestoreContainer_WithoutHostAccessAuditedOnlyOnceLanded(t *testing.T) {
	s, rt, repo, ts := hostAccessBackup(t)
	s.SetReleaseFeatureGate(latchedButRefusingGate{})
	rt.rebuildErr = errors.New("render failed")
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: "web", HostName: "host-a", RepoPath: repo, Timestamp: ts,
		WithoutHostAccess: true}, rs); err == nil {
		t.Fatal("restore succeeded although its config render failed")
	}
	for _, a := range ctRestoreAudit(t, s, "web") {
		if strings.HasPrefix(a, "ok: ") && strings.Contains(a, "--without-host-access") {
			t.Errorf("a failed restore left an ok row: %q", a)
		}
	}
}

// N-1. A config render behind a stuck host-access refresh — the path snapshot
// revert, clone and restore take — fails Unavailable (retry), as start and
// convert do, not Internal.
//
// Mutation: map a render error to Internal unconditionally — red.
func TestRenderContainerConfig_BusyIsUnavailable(t *testing.T) {
	s, rt := secServer(t)
	rt.rebuildErr = fmt.Errorf("container %q: %w", "a", lxc.ErrHostAccessBusy)
	spec := corrosion.ContainerCreateSpec{Template: "download"}
	if err := s.rebuildContainerConfig(context.Background(), "a", spec); status.Code(err) != codes.Unavailable {
		t.Errorf("rebuild (revert, clone) behind a stuck refresh = %v; want Unavailable", err)
	}
	if _, err := s.renderContainerConfig(context.Background(), "a", spec, networkRender); status.Code(err) != codes.Unavailable {
		t.Errorf("render (restore) behind a stuck refresh = %v; want Unavailable", err)
	}
	rt.rebuildErr = errors.New("disk full")
	if err := s.rebuildContainerConfig(context.Background(), "a", spec); status.Code(err) != codes.Internal {
		t.Errorf("any other render error = %v; want Internal, as before", err)
	}
}
