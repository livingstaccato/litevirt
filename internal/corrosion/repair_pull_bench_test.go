package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// BenchmarkRepairPull compares one whole-table repair of 20,000 rows as a blob
// (dump, inflate, unmarshal, merge) and as pages merged as they arrive.
// max-unit-B is the largest decoded unit the receiver holds at once: the
// whole payload for the blob, one page for the paged pull.
//
//	go test ./internal/corrosion/ -run '^$' -bench BenchmarkRepairPull -benchtime 3x -benchmem
func BenchmarkRepairPull(b *testing.B) {
	ctx := context.Background()
	src := NewTestClientT(b)
	if err := InitSchema(ctx, src); err != nil {
		b.Fatal(err)
	}
	src.mu.Lock()
	tx, err := src.db.Begin()
	if err != nil {
		src.mu.Unlock()
		b.Fatal(err)
	}
	for i := 0; i < 20000; i++ {
		if _, err := tx.Exec(`INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at)
			VALUES (?, 'h', ?, 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
			fmt.Sprintf("stack-%05d", i), fmt.Sprintf("services: {web: {image: img-%d}}", i)); err != nil {
			b.Fatal(err)
		}
	}
	err = tx.Commit()
	src.mu.Unlock()
	if err != nil {
		b.Fatal(err)
	}
	fresh := func(b *testing.B) *Client {
		dst := NewTestClientT(b)
		if err := InitSchema(ctx, dst); err != nil {
			b.Fatal(err)
		}
		return dst
	}

	b.Run("blob", func(b *testing.B) {
		b.ReportAllocs()
		maxUnit := 0
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			dst := fresh(b)
			b.StartTimer()
			data, err := src.DumpTablesBytes([]string{"stacks"})
			if err != nil {
				b.Fatal(err)
			}
			if p, err := decompressPayload(data); err == nil {
				raw, _ := json.Marshal(p)
				maxUnit = max(maxUnit, len(raw))
			}
			if err := dst.MergeStateBytesLWW(data); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(maxUnit), "max-unit-B")
	})
	b.Run("paged", func(b *testing.B) {
		b.ReportAllocs()
		maxUnit := 0
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			dst := fresh(b)
			b.StartTimer()
			pages := make(chan *pb.TableRowsPage, 4)
			go func() {
				_ = src.StreamTableRowsScoped(ctx, []string{"stacks"}, nil, func(p *pb.TableRowsPage) error {
					pages <- p
					return nil
				})
				close(pages)
			}()
			recv := func() (*pb.TableRowsPage, error) {
				p, ok := <-pages
				if !ok {
					return nil, io.EOF
				}
				if rows, _ := decodePageRows(p); rows != nil {
					raw, _ := json.Marshal(rows)
					maxUnit = max(maxUnit, len(raw))
				}
				return p, nil
			}
			if _, _, perr, merr := dst.mergeTableRowsStream(recv, replicatedTableSet, nil); perr != nil || merr != nil {
				b.Fatal(perr, merr)
			}
		}
		b.ReportMetric(float64(maxUnit), "max-unit-B")
	})
}
