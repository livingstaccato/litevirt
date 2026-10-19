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
// Each record carries the kernel's timestamp of its frame.
//
// Mutations (each red on a kernel with the modules): put the limit on the
// verdict line (frames past the budget pass: delivered > 0); render no log
// line (zero records); a limit per rule rather than per NIC side (the
// two-rule count passes the bound); ignore the kernel's timestamp (the
// records say "received").
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
				// A frame the bridge forwards carries the kernel's timestamp.
				if r.TimeSource != LogTimePacket || time.Since(r.Time) > time.Minute {
					t.Errorf("record time %v (%q), want the packet's", r.Time, r.TimeSource)
				}
			}
		})
	}
}

// TestKernelChild_HostSentRecordIsPrompt (anomaly 5 of lab1-fwbc2): a
// datagram the host itself sends to a guest is logged by the guest NIC's
// ingress rule, and its record reaches this package's own listener (the
// group as openNflog configures it) within logPromptBound of the send,
// carrying a time within logPromptBound of it. A packet the host sends has
// no kernel timestamp, so the record's time is the receive time. Each
// datagram goes alone, after the last record arrived, so no other record
// can push it out early: with the kernel's 1 s flush timer each one arrives
// about 1 s late.
//
// Mutations (each red on a kernel with the modules): leave the flush timeout
// unset (records ~1 s late); a timeout of 100 (1 s, the same). Red on
// e4c38889e, which set neither: every record about 1.02-1.06 s late.
func TestKernelChild_HostSentRecordIsPrompt(t *testing.T) {
	inNetns(t)
	skipUnlessModules(t, "the host-sent log timing test", logFormsModules...)
	const group = 30
	const logPromptBound = 250 * time.Millisecond
	l := newGuestLab(t, map[string]string{"gt": "10.20.0.7"})
	if !l.ping("", "10.20.0.7") { // the neighbour entry, so no send waits on ARP
		t.Fatal("the host cannot reach the guest before any rule")
	}
	if _, err := NewApplier(NftBinary{}).Apply(context.Background(), Plan{
		NICMode:   NICModeEnforce,
		LogPolicy: LogPolicy{Available: true, Group: group, Rate: 1000, Burst: 1000},
		NICs: []NICBinding{{NICDev: "pgt", VMName: "gt", Bridge: "gwbr0", ExtraRules: []Rule{
			{ID: "r1", Direction: Ingress, Proto: "udp", PortRange: "5000", Action: Drop, Log: true}}}},
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
	conn, err := net.Dial("udp4", "10.20.0.7:5000")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 5; i++ {
		n := len(store.List(LogFilter{Limit: LogRingSize}))
		sent := time.Now()
		if _, err := conn.Write([]byte(fmt.Sprintf("LVTS%d", i))); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		var got []LogRecord
		for time.Since(sent) < 3*time.Second {
			if got = store.List(LogFilter{Limit: LogRingSize}); len(got) > n {
				break
			}
			time.Sleep(time.Millisecond)
		}
		arrived := time.Since(sent)
		if len(got) <= n {
			t.Fatalf("send %d: no record within 3 s", i)
		}
		r := got[len(got)-1]
		skew := r.Time.Sub(sent)
		t.Logf("send %d: record after %v, time %+v from the send: %+v", i, arrived, skew, r)
		if r.Device != "pgt" || r.Side != "in" || r.Dport != 5000 || r.Src != "10.20.0.254" {
			t.Errorf("send %d: record = %+v, want pgt in from 10.20.0.254 to port 5000", i, r)
		}
		if arrived > logPromptBound {
			t.Errorf("send %d: the record arrived %v after the send, want at most %v", i, arrived, logPromptBound)
		}
		if skew < -logPromptBound || skew > logPromptBound {
			t.Errorf("send %d: the record's time is %v from the send, want within %v", i, skew, logPromptBound)
		}
	}
}
