package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
)

// A restore onto a filesystem that dropped attributes it does not support
// succeeds and records a container event naming each one.
func TestRestoreContainer_DroppedAttributesAreAnEvent(t *testing.T) {
	s, rt := secServer(t)
	s.events = events.NewBus()
	repo := ctTestRepo(t)
	seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{Template: "download"})
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{Name: "web", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-27T12:00:00Z"}, bk); err != nil {
		t.Fatal(err)
	}
	_ = corrosion.DeleteContainer(context.Background(), s.db, "host-a", "web")
	rt.dropped = map[string][]string{"web": {"web/rootfs/var/log/journal system.posix_acl_access", "web/rootfs/bin/ping security.capability"}}
	ch, unsub := s.events.Subscribe()
	defer unsub()
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: "web", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-27T12:00:00Z"}, rs); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case e := <-ch:
			if e.Action == "ct.attrs.dropped" && e.Target == "web" &&
				strings.Contains(e.Detail, "bin/ping security.capability") && strings.Contains(e.Detail, "journal system.posix_acl_access") {
				return
			}
		case <-deadline:
			t.Fatal("no ct.attrs.dropped event for the restore")
		}
	}
}
