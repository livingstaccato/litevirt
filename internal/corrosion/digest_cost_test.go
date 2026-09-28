package corrosion

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// BenchmarkStateDigest_50Nodes measures one full public digest — what every
// anti-entropy pass computes locally and every GetStateDigest a peer sends it
// recomputes — over a 50-node cluster's worth of rows: a full host_health mesh
// (2,450 edges) and 40 VMs per host (2,000 VMs). It is the baseline any
// incremental digest would be judged against (#262 (d)).
//
//	go test ./internal/corrosion/ -run '^$' -bench BenchmarkStateDigest_50Nodes -benchtime 20x
func BenchmarkStateDigest_50Nodes(b *testing.B) {
	c := NewTestClientT(b)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		b.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	c.mu.Lock()
	tx, err := c.db.Begin()
	if err != nil {
		c.mu.Unlock()
		b.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		for j := 0; j < 50; j++ {
			if i == j {
				continue
			}
			if _, err := tx.Exec(`INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
				VALUES (?, ?, 'healthy', 0, ?, ?)`, fmt.Sprintf("node-%02d", i), fmt.Sprintf("node-%02d", j), now, now); err != nil {
				b.Fatal(err)
			}
		}
		for v := 0; v < 40; v++ {
			if _, err := tx.Exec(`INSERT INTO vms (name, host_name, spec, state, created_at, updated_at)
				VALUES (?, ?, '{"vcpus":2,"memory_mib":2048,"disks":[{"size_gib":20}]}', 'running', ?, ?)`, fmt.Sprintf("vm-%02d-%02d", i, v), fmt.Sprintf("node-%02d", i), now, now); err != nil {
				b.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		c.mu.Unlock()
		b.Fatal(err)
	}
	c.mu.Unlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.StateDigest(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
