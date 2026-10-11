package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Container replication and reverse replication against REAL LXC on two hosts.
//
// tests/fleet drives the same paths over an in-process runtime fake. What only
// this can show is that the rootfs that reaches the other host is the container's
// real one, read back by that host's own kernel.
//
// It needs a backup repo on the TARGET host, registered under a logical name in
// that host's backup_repos (config.yaml) and initialised (lv backup repo init).
// Name it in LV_E2E_DR_REPO; without it the test skips, because a replica has
// nowhere to go.
//
//	export LV_E2E_DR_REPO=dr      # a repo name the other host has in backup_repos
//
// The container is migrated onto its replica host, which is how a planned
// failback happens; the failover-driven promotion needs a fenced host and is a
// drill (drill_recovery_test.go), not run here.

func scheduleRow(t *testing.T, name string) []string {
	t.Helper()
	for _, line := range strings.Split(lv(t, "replication", "schedule", "ls"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "ct:"+name {
			return f
		}
	}
	return nil
}

func TestContainerReplication_ReplicatesThenFollowsAPlannedMove(t *testing.T) {
	requireLXC(t)
	requireHosts(t, 2)
	repoName := os.Getenv("LV_E2E_DR_REPO")
	if repoName == "" {
		t.Skip("LV_E2E_DR_REPO unset: name a backup repo the second host has in backup_repos")
	}
	target := otherHost(t)

	name := uniqueName("ct")
	cleanup(t, func() {
		lvErr(t, "replication", "schedule", "rm", name, "--container", "--target-pool", repoName)
		lvErr(t, "ct", "rm", name, "--host", localHost, "--force")
		lvErr(t, "ct", "rm", name, "--host", target, "--force")
	})
	if out, err := lvErr(t, "ct", "create", name, "--host", localHost); err != nil {
		t.Skipf("cannot create a container on %s: %v\n%s", localHost, err, out)
	}
	const marker = "e2e-replica-marker-do-not-edit"
	payload := "payload-" + name
	if err := os.WriteFile(filepath.Join(ctDir(name), "rootfs", marker), []byte(payload), 0o644); err != nil {
		t.Fatalf("plant marker: %v", err)
	}
	if out, err := lvErr(t, "ct", "start", name, "--host", localHost); err != nil {
		t.Fatalf("start: %v\n%s", err, out)
	}
	waitCT(t, name, "running", 60*time.Second)

	// Every minute, so the run lands while the test waits.
	if out, err := lvErr(t, "replication", "schedule", "add", name, "--container",
		"--cron", "* * * * *", "--target-host", target, "--target-pool", repoName, "--keep", "2"); err != nil {
		if strings.Contains(out+err.Error(), "cluster upgrade must finish first") {
			t.Skipf("container replication is the container_replication release feature, not open on this cluster: %s", out)
		}
		t.Fatalf("schedule add: %v\n%s", err, out)
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		row := scheduleRow(t, name)
		// ct:NAME REPO HOST INCR AUTO KEEP LASTRUN LASTERR
		if len(row) >= 8 && row[6] != "-" && row[7] == "-" {
			break
		}
		if len(row) >= 8 && row[7] != "-" {
			t.Fatalf("a replication run failed: %v", row)
		}
		if time.Now().After(deadline) {
			t.Fatalf("no successful replication run within 3 minutes: %v", row)
		}
		time.Sleep(5 * time.Second)
	}

	// The replica is in the target repo's replica namespace, listed as current.
	if out := lv(t, "replication", "replicas", name, "--host", target, "--target-pool", repoName); !strings.Contains(out, "current") {
		t.Fatalf("the replica host lists no current replica of %s:\n%s", name, out)
	}

	// Move the container onto its replica host (cold migrate, as for any move).
	stagingRepo := filepath.Join(t.TempDir(), "migrate-repo")
	lv(t, "backup", "repo", "init", stagingRepo)
	if out, err := lvErr(t, "ct", "migrate", name, target, "--repo", stagingRepo); err != nil {
		t.Fatalf("migrate %s -> %s: %v\n%s", localHost, target, err, out)
	}

	// Reverse replication: the schedule now targets the host the container left.
	row := scheduleRow(t, name)
	if len(row) < 3 || row[2] != localHost {
		t.Fatalf("after the move the schedule should replicate back to %s, got %v", localHost, row)
	}

	// The migrated rootfs is the real one: read the marker inside it, on the target.
	if out, err := lvErr(t, "ct", "start", name, "--host", target); err != nil {
		t.Fatalf("start on %s: %v\n%s", target, err, out)
	}
	waitCT(t, name, "running", 60*time.Second)
	got, err := lvErr(t, "ct", "exec", name, "--host", target, "--", "cat", "/"+marker)
	if err != nil || !strings.Contains(got, payload) {
		t.Fatalf("marker inside the moved container = %q (%v), want %q", got, err, payload)
	}
}
