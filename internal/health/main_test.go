package health

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"
)

func TestMain(m *testing.M) {
	// canary: a goroutine blocked forever on an unreachable channel; the profile must report it.
	go leakCanary()
	code := m.Run()
	dumpLeakProfile()
	os.Exit(code)
}

// dumpLeakProfile writes the goroutineleak profile (debug=1) to $LEAK_OUT.
func dumpLeakProfile() {
	out := os.Getenv("LEAK_OUT")
	if out == "" {
		return
	}
	p := pprof.Lookup("goroutineleak")
	if p == nil {
		fmt.Fprintln(os.Stderr, "LEAKPROFILE: profile unavailable (GOEXPERIMENT missing)")
		return
	}
	runtime.GC()
	f, err := os.Create(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "LEAKPROFILE:", err)
		return
	}
	defer f.Close()
	_ = p.WriteTo(f, 1)
	if g, err := os.Create(out + ".d2"); err == nil {
		_ = p.WriteTo(g, 2)
		g.Close()
	}
	fmt.Fprintf(os.Stderr, "LEAKPROFILE: count=%d file=%s\n", p.Count(), out)
}

func leakCanary() {
	c := make(chan int)
	<-c
}
