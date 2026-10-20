package fleet

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Isolate the actual fleet loop/stop boundary from sockets and replication.
// This exercises startServerLoops (also used by buildServer), downNode and
// Cluster.Stop with real servers and databases. Transport/handler/network
// joins retain their existing integration tests; no transport is faked here.
func firmwareLifetimeNode(t *testing.T, name string, observe func(context.Context, string, string)) *Node {
	t.Helper()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	db.MarkReplicaCaughtUpForTests("peer")
	virt := libvirtfake.New()
	s := grpcapi.NewServerForTests(grpcapi.TestServerOpts{
		HostName: name, DataDir: t.TempDir(), DB: db, Virt: virt, DBWorkerEvent: observe,
	})
	return &Node{Name: name, DB: db, Server: s, Virt: virt}
}

func TestFleetFirmwareWorkers_StopHoldsDependencies(t *testing.T) {
	// Mutation: cancel firmware loops without joining their terminals or the
	// startup children they admitted. The raw incoming startup fails here.
	for _, worker := range []string{"firmware_hold", "firmware_retained", "firmware_recovery", "firmware_startup_discard"} {
		t.Run(worker, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var enterOnce, exitOnce sync.Once
				n := firmwareLifetimeNode(t, "node-0", func(_ context.Context, name, event string) {
					if name != worker {
						return
					}
					if event == "entry" {
						enterOnce.Do(func() { close(entered); <-release })
					}
					if event == "exit" {
						exitOnce.Do(func() { close(exited) })
					}
				})
				peer := firmwareLifetimeNode(t, "node-1", nil)
				c := &Cluster{t: t, ctx: ctx, cancel: cancel, Nodes: []*Node{n, peer}, opts: Options{SharedCRDT: true}}
				closing := make(chan string, 2)
				c.beforeDependencyClose = func(n *Node) { closing <- n.Name }
				c.startServerLoops(n)
				c.startServerLoops(peer)
				<-entered
				stopped := make(chan struct{})
				go func() { c.Stop(); close(stopped) }()
				synctest.Wait()
				select {
				case name := <-closing:
					t.Errorf("closed %s dependencies while the old server's firmware work was held", name)
				default:
				}
				close(release)
				<-exited
				<-stopped
				synctest.Wait()
			})
		})
	}
}

func TestFleetFirmwareWorkers_DownNodeJoinsCurrentServerBeforeReplacement(t *testing.T) {
	// Mutation: restart's old-server stop returns while its admitted child
	// still owns the firmware paths that the replacement will reuse.
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
		n := firmwareLifetimeNode(t, "node-0", func(_ context.Context, worker, event string) {
			if worker != "firmware_startup_discard" {
				return
			}
			if event == "entry" {
				close(entered)
				<-release
			} else if event == "exit" {
				close(exited)
			}
		})
		old := n.Server
		c := &Cluster{t: t, ctx: ctx, cancel: cancel, Nodes: []*Node{n}, opts: Options{SharedCRDT: true}}
		c.startServerLoops(n)
		<-entered
		replacement := grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: n.Name, DataDir: t.TempDir(), DB: n.DB, Virt: n.Virt})
		replaced := make(chan struct{})
		go func() {
			// This is restartNode's real down boundary. The replacement
			// publication witnesses when the old server ceases to be owned.
			downNode(n)
			n.Server = replacement
			close(replaced)
		}()
		synctest.Wait()
		select {
		case <-replaced:
			t.Error("restart published a replacement while the old server's firmware child was held")
		default:
			if n.Server != old {
				t.Error("restart changed the current server before the old child joined")
			}
		}
		if _, err := corrosion.ListHosts(context.Background(), n.DB); err != nil {
			t.Errorf("restart closed its shared DB while the old child was held: %v", err)
		}
		close(release)
		<-exited
		<-replaced
		synctest.Wait()
	})
}
