package fleet

import (
	"bytes"
	"context"
	"fmt"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"weak"
)

// Each server buildServer starts is a generation of its node's daemon. Every
// goroutine buildServer starts for it carries the generation as a pprof
// goroutine label, and so does every goroutine those start in turn (a label
// is inherited at go): its loops, its recovery workers, its gRPC server and
// every handler it runs, and whatever a handler spawns. A scenario that
// kills a daemon (fwliveCrash) waits for the goroutines of its generation to
// be gone. A server method a scenario calls on its own goroutine runs
// unlabelled; such a call is the scenario's, not the daemon's.

const serverLabelKey = "fleet-server"

var (
	serverGenSeq atomic.Int64
	serverGens   sync.Map // weak *Node → its current server's generation
)

// labelServerGoroutines labels the goroutines the calling goroutine starts
// from now on with n's new server generation; the returned func takes the
// label off it again.
func (n *Node) labelServerGoroutines() (unlabel func()) {
	gen := n.Name + "#" + strconv.FormatInt(serverGenSeq.Add(1), 10)
	serverGens.Store(weak.Make(n), gen)
	pprof.SetGoroutineLabels(pprof.WithLabels(context.Background(), pprof.Labels(serverLabelKey, gen)))
	return func() { pprof.SetGoroutineLabels(context.Background()) }
}

// serverGeneration is n's current server generation.
func (n *Node) serverGeneration() string {
	g, _ := serverGens.Load(weak.Make(n))
	s, _ := g.(string)
	return s
}

// serverGoroutines counts the live goroutines of generation gen, and returns
// their stacks.
func serverGoroutines(gen string) (count int, stacks string) {
	var buf bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&buf, 1); err != nil {
		panic(fmt.Sprintf("goroutine profile: %v", err))
	}
	want := fmt.Sprintf("%q:%q", serverLabelKey, gen)
	var out strings.Builder
	for _, rec := range strings.Split(buf.String(), "\n\n") {
		if !strings.Contains(rec, "# labels: ") || !strings.Contains(rec, want) {
			continue
		}
		head, _, _ := strings.Cut(rec, " @ ")
		if i := strings.LastIndexByte(head, '\n'); i >= 0 {
			head = head[i+1:] // the profile's header line
		}
		n, err := strconv.Atoi(strings.TrimSpace(head))
		if err != nil {
			continue
		}
		count += n
		out.WriteString(rec)
		out.WriteString("\n\n")
	}
	return count, out.String()
}
