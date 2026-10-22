package grpcapi

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// panicValuer panics when the driver converts it, i.e. inside the statement
// loop of a write, while the client's lock is held.
type panicValuer struct{}

func (panicValuer) Value() (driver.Value, error) { panic("statement param bug") }

// returnsWithin fails the test if fn has not returned after d. A wedged lock blocks
// fn for good, so the test reports it rather than hanging until its timeout.
func returnsWithin(t *testing.T, d time.Duration, what string, fn func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(d):
		t.Fatalf("WEDGED: %s still blocked %s after a recovered panic (a held lock or an open write transaction)", what, d)
	}
}

// A panic under the corrosion client's write lock, answered Internal by the
// recovery interceptor, must not leave that lock held. Before, the lock was
// released only on each return path: a guard or statement that panicked left
// it held, every later Query blocked behind it (RLock ignores ctx), Ping and
// the partition pauser parked on their first read, and the daemon lived on as
// a zombie that answered nothing and never paused.
//
// Mutations: drop the deferred release (heldLock) in ExecuteEntriesGuarded or
// executeBatchInternal, or either deferred tx.Rollback, and the matching case
// goes red.
func TestRecoveredPanicUnderClientLock_LeavesTheDBUsable(t *testing.T) {
	info := &grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/StartVM"}
	cases := map[string]func(ctx context.Context, db *corrosion.Client) error{
		"guard panics (ExecuteEntriesGuarded)": func(ctx context.Context, db *corrosion.Client) error {
			_, err := db.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
				// A write first, so the open transaction holds the write lock.
				if _, err := tx.ExecContext(ctx, `UPDATE hosts SET address = '10.0.0.2' WHERE name = 'nobody'`); err != nil {
					return false, err
				}
				var m map[string]int
				m["guard bug"]++
				return true, nil
			}, nil)
			return err
		},
		"statement panics (executeBatchInternal)": func(ctx context.Context, db *corrosion.Client) error {
			return db.ExecuteBatch(ctx, []corrosion.Statement{
				{SQL: `UPDATE hosts SET address = ? WHERE name = 'nobody'`, Params: []interface{}{"10.0.0.2"}},
				{SQL: `UPDATE hosts SET address = ? WHERE name = 'nobody'`, Params: []interface{}{panicValuer{}}},
			})
		},
		"statement panics (guarded)": func(ctx context.Context, db *corrosion.Client) error {
			_, err := db.ExecuteBatchGuarded(ctx, func(*sql.Tx) (bool, error) { return true, nil },
				[]corrosion.Statement{
					{SQL: `UPDATE hosts SET address = ? WHERE name = 'nobody'`, Params: []interface{}{"10.0.0.2"}},
					{SQL: `UPDATE hosts SET address = ? WHERE name = 'nobody'`, Params: []interface{}{panicValuer{}}},
				})
			return err
		},
	}
	for name, write := range cases {
		t.Run(name, func(t *testing.T) {
			db := corrosion.NewTestClientT(t)
			ctx := context.Background()
			if err := corrosion.InitSchema(ctx, db); err != nil {
				t.Fatal(err)
			}
			_, err := RecoverUnaryInterceptor(ctx, nil, info, func(ctx context.Context, _ any) (any, error) {
				return nil, write(ctx, db)
			})
			if status.Code(err) != codes.Internal {
				t.Fatalf("the panicking write was answered %v, want Internal", err)
			}
			returnsWithin(t, 3*time.Second, "a read", func() error {
				_, err := db.Query(ctx, "SELECT 1")
				return err
			})
			returnsWithin(t, 3*time.Second, "a later guarded write", func() error {
				_, err := db.ExecuteBatchGuarded(ctx, func(*sql.Tx) (bool, error) { return false, nil }, nil)
				return err
			})
			// A write that takes the database's write lock, under a context
			// nothing cancels: the panicked transaction must have been rolled
			// back (the deferred tx.Rollback), not left open holding it.
			returnsWithin(t, 3*time.Second, "a later write under context.Background", func() error {
				return db.ExecuteBatch(context.Background(), []corrosion.Statement{{
					SQL: `UPDATE hosts SET address = ? WHERE name = 'nobody'`, Params: []interface{}{"10.0.0.1"},
				}})
			})
		})
	}
}
