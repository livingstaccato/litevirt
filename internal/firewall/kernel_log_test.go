//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net"
	"syscall"
	"testing"
	"time"
)

// TestKernelChild_LogBudget (spec §3.7, C8): a guest floods a logged drop
// rule with 10,000 frames in about a second, read by this package's own NFLOG
// listener. The per-NIC-side budget (rate r, burst b) bounds the records: at
// least b arrive (the log line is reached and the listener reads it) and at
// most b + r·t + 1, t the flood's length. Every frame still gets the drop.
// With two logged rules, each matching half the frames, the count stays
// within the same bound: the budget is the NIC side's, not the rule's. The
// logging probe passes on this kernel.
//
// It declares its own modules (logFormsModules) and skips, or fails under
// LITEVIRT_NFT_REQUIRE=1, without them.
//
// Mutations (each red on a kernel with the modules): put the limit on the
// verdict line (frames past the budget pass: delivered > 0); render no log
// line (zero records); a limit per rule rather than per NIC side (the
// two-rule count passes the bound).
func TestKernelChild_LogBudget(t *testing.T) {
	inNetns(t)
	skipUnlessModules(t, "the log budget test", logFormsModules...)
	const group, rate, burst = 29, 5, 10
	if err := ProbeLogging(context.Background(), group); err != nil {
		t.Fatalf("the logging probe was refused on a kernel with the modules: %v", err)
	}
	l := newBridgeLab(t)
	for _, tc := range []struct {
		name  string
		rules []Rule
		ports []uint16
	}{
		{"one logged rule", []Rule{{ID: "r1", Direction: Egress, Proto: "udp", PortRange: "5000", Action: Drop, Log: true}}, []uint16{5000}},
		{"two logged rules", []Rule{
			{ID: "r1", Direction: Egress, Proto: "udp", PortRange: "5000", Action: Drop, Log: true},
			{ID: "r2", Direction: Egress, Proto: "udp", PortRange: "5001", Action: Drop, Log: true},
		}, []uint16{5000, 5001}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewApplier(NftBinary{})
			if _, err := a.Apply(context.Background(), Plan{
				NICMode:   NICModeEnforce,
				LogPolicy: LogPolicy{Available: true, Group: group, Rate: rate, Burst: burst},
				NICs: []NICBinding{
					{NICDev: "lvh0", VMName: "guest", ExtraRules: tc.rules},
					{NICDev: "lvh1", VMName: "other"},
				},
			}); err != nil {
				t.Fatalf("apply: %v", err)
			}
			store, err := OpenLogStore(LogStoreOptions{MaxRate: 1 << 30})
			if err != nil {
				t.Fatal(err)
			}
			bound := make(chan error, 1)
			ln := &LogListener{Group: group, Store: store, OnBind: func(err error) {
				select {
				case bound <- err:
				default:
				}
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go ln.Run(ctx)
			select {
			case err := <-bound:
				if err != nil {
					t.Fatalf("bind NFLOG group %d: %v", group, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the listener never bound")
			}

			tx := packetSocket(t, "lvg0")
			rx := packetSocket(t, "lvg1")
			ifc, _ := net.InterfaceByName("lvg0")
			marker := []byte(fmt.Sprintf("LVLOG%027d", time.Now().UnixNano()))
			const frames = 10000
			start := time.Now()
			for i := 0; i < frames; i++ {
				f := ether(l.guestMAC, 0x0800, ipv4UDP("10.0.0.5", "10.0.0.9", 4000, tc.ports[i%len(tc.ports)]))
				f = append(f, marker...)
				if err := syscall.Sendto(tx, f, 0, &syscall.SockaddrLinklayer{Ifindex: ifc.Index, Halen: 6}); err != nil {
					t.Fatalf("send: %v", err)
				}
				if next := start.Add(time.Duration(i+1) * 100 * time.Microsecond); time.Until(next) > 0 {
					time.Sleep(time.Until(next))
				}
			}
			elapsed := time.Since(start)
			delivered := 0
			buf := make([]byte, 4096)
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				n, _, err := syscall.Recvfrom(rx, buf, 0)
				if err == nil && bytes.Contains(buf[:n], marker) {
					delivered++
				}
			}
			cancel()
			got := len(store.List(LogFilter{Limit: LogRingSize}))
			max := burst + int(math.Ceil(rate*elapsed.Seconds())) + 1
			t.Logf("%d frames in %v: %d records (bound %d..%d), %d delivered", frames, elapsed, got, burst, max, delivered)
			if got < burst || got > max {
				t.Errorf("records = %d, want %d..%d", got, burst, max)
			}
			if delivered != 0 {
				t.Errorf("%d of %d frames passed a drop rule that logs", delivered, frames)
			}
			for _, r := range store.List(LogFilter{Limit: 1}) {
				if r.Device != "lvh0" || r.Side != "out" || r.Verdict != "drop" || r.Dport < 5000 || r.Src != "10.0.0.5" {
					t.Errorf("record = %+v, want lvh0 out drop from 10.0.0.5", r)
				}
			}
		})
	}
}
