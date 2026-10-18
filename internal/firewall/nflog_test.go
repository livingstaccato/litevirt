package firewall

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	nflog "github.com/florianl/go-nflog/v2"
)

// ipv4TCP is an IPv4 TCP segment from src:sport to dst:dport with flags.
func ipv4TCP(src, dst string, sport, dport uint16, flags byte, totalLen uint16) []byte {
	b := make([]byte, 40)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], totalLen)
	b[9] = 6
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	b[20+12] = 5 << 4
	b[20+13] = flags
	return b
}

// ipv6UDPHopByHop is an IPv6 UDP datagram behind a hop-by-hop header.
func ipv6UDPHopByHop(src, dst string, sport, dport uint16, payloadLen uint16) []byte {
	b := make([]byte, 40+8+8)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], payloadLen)
	b[6] = 0 // hop-by-hop
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	b[40] = 17 // next: udp
	b[41] = 0  // 8 bytes
	binary.BigEndian.PutUint16(b[48:], sport)
	binary.BigEndian.PutUint16(b[50:], dport)
	return b
}

// C4b: the prefix the renderer writes parses into the device, side, rule and
// verdict; anything else is not a litevirt record.
//
// Mutation: accept any prefix — "other 1 2 3 4" parses, red.
func TestParseLogPrefix(t *testing.T) {
	r, ok := parseLogPrefix("lv-log lvt0123456789ab in 0f3c9a2b11aa44cc drop\x00")
	if !ok || r.Device != "lvt0123456789ab" || r.Side != "in" || r.RuleID != "0f3c9a2b11aa44cc" || r.Verdict != "drop" || r.Tier != "nic" {
		t.Errorf("per-NIC prefix = %+v, %v", r, ok)
	}
	r, ok = parseLogPrefix("lv-log - - rule would-drop")
	if !ok || r.Device != "-" || r.Tier != "routed" || r.Verdict != "would-drop" {
		t.Errorf("routed prefix = %+v, %v", r, ok)
	}
	for _, p := range []string{"", "other a in r drop", "lv-log a in r", "lv-log a in r drop extra", "lv-log a sideways r drop", "lv-log a in r maybe"} {
		if _, ok := parseLogPrefix(p); ok {
			t.Errorf("prefix %q parsed", p)
		}
	}
}

// C4b: the packet headers parse into the record: family, protocol,
// addresses, ports, the IP length (not the snapped payload's) and TCP flags;
// an IPv6 extension header is skipped; a truncated packet keeps what it has.
//
// Mutation: read the ports at a fixed IPv6 offset — the hop-by-hop case gets
// the extension header's bytes, red.
func TestParseLogPacket(t *testing.T) {
	var r LogRecord
	parseLogPacket(&r, ipv4TCP("10.0.0.1", "10.0.0.2", 40000, 22, 0x02, 1500))
	if r.Family != "ip" || r.Proto != "tcp" || r.Src != "10.0.0.1" || r.Dst != "10.0.0.2" || r.Sport != 40000 ||
		r.Dport != 22 || r.Length != 1500 || r.TCPFlags != "S" {
		t.Errorf("IPv4 TCP SYN = %+v", r)
	}
	r = LogRecord{}
	parseLogPacket(&r, ipv6UDPHopByHop("2001:db8::1", "2001:db8::2", 5353, 53, 100))
	if r.Family != "ip6" || r.Proto != "udp" || r.Src != "2001:db8::1" || r.Sport != 5353 || r.Dport != 53 || r.Length != 140 {
		t.Errorf("IPv6 UDP behind hop-by-hop = %+v", r)
	}
	r = LogRecord{}
	parseLogPacket(&r, ipv4TCP("10.0.0.1", "10.0.0.2", 1, 2, 0x12, 60)[:22])
	if r.Src != "10.0.0.1" || r.Sport != 0 || r.TCPFlags != "" {
		t.Errorf("truncated = %+v, want the addresses and no ports", r)
	}
	for _, junk := range [][]byte{nil, {0x45}, {0x60, 0, 0}, {0xff, 1, 2, 3}} {
		r = LogRecord{}
		parseLogPacket(&r, junk) // must not panic
	}
}

// fakeNflog is an nflog connection the test drives.
type fakeNflog struct {
	mu     sync.Mutex
	hook   nflog.HookFunc
	errfn  nflog.ErrorFunc
	closed bool
}

func (f *fakeNflog) RegisterWithErrorFunc(_ context.Context, fn nflog.HookFunc, errfn nflog.ErrorFunc) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook, f.errfn = fn, errfn
	return nil
}

func (f *fakeNflog) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func ptr[T any](v T) *T { return &v }

// C4b: a record names its device; the device resolves to its workload and
// MAC through the plan in force; a packet whose prefix is not litevirt's is
// ignored; a gap in the kernel's per-group sequence is counted as overflow.
//
// Mutations: skip the resolver — no workload, red; ignore the sequence — no
// overflow counted, red.
func TestLogListener_RecordsResolveThroughThePlan(t *testing.T) {
	cnt := &countingLog{}
	store := openStore(t, LogStoreOptions{MaxRate: 1 << 30, Counter: cnt})
	conn := &fakeNflog{}
	l := &LogListener{Group: 27, Store: store,
		Resolve: func(dev string) (string, string) {
			if dev == "lvt0" {
				return "web-1", "52:54:00:00:00:01"
			}
			return "", ""
		},
		open: func(g uint16) (nflogConn, error) { return conn, nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn.mu.Lock()
		h := conn.hook
		conn.mu.Unlock()
		if h != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the listener never registered")
		}
		time.Sleep(time.Millisecond)
	}
	pkt := ipv4TCP("10.0.0.9", "10.0.0.1", 40000, 22, 0x02, 60)
	conn.hook(nflog.Attribute{Prefix: ptr("lv-log lvt0 in r1 drop"), Payload: &pkt, Seq: ptr(uint32(1))})
	conn.hook(nflog.Attribute{Prefix: ptr("someone else's"), Payload: &pkt, Seq: ptr(uint32(2))})
	conn.hook(nflog.Attribute{Prefix: ptr("lv-log lvt9 out default accept"), Payload: &pkt, Seq: ptr(uint32(6))})
	got := store.List(LogFilter{})
	if len(got) != 2 {
		t.Fatalf("records = %+v, want two", got)
	}
	if got[0].Workload != "web-1" || got[0].MAC != "52:54:00:00:00:01" || got[0].Dport != 22 || got[0].RuleID != "r1" {
		t.Errorf("first record = %+v", got[0])
	}
	if got[1].Workload != "" || got[1].RuleID != "default" || got[1].Verdict != "accept" {
		t.Errorf("second record = %+v", got[1])
	}
	if n := cnt.get(LogOutcomeOverflow); n != 3 {
		t.Errorf("overflow = %d, want 3 (sequence 3, 4, 5 never arrived)", n)
	}
}

// C4b (spec §3.5): a failed bind is reported once per transition — failing,
// bound again, failing again — however many retries fail in between.
//
// Mutation: report every failed attempt — red.
func TestLogListener_BindFailureOncePerTransition(t *testing.T) {
	store := openStore(t, LogStoreOptions{MaxRate: 10})
	var mu sync.Mutex
	attempts := 0
	var reports []string
	conns := make(chan *fakeNflog, 4)
	l := &LogListener{Group: 27, Store: store, retry: time.Millisecond,
		OnBind: func(err error) {
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				reports = append(reports, "bound")
			} else {
				reports = append(reports, "failed")
			}
		},
		open: func(g uint16) (nflogConn, error) {
			mu.Lock()
			attempts++
			a := attempts
			mu.Unlock()
			if a <= 3 || (a > 4 && a <= 7) {
				return nil, errors.New("device or resource busy")
			}
			c := &fakeNflog{}
			conns <- c
			return c, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Run(ctx)
	c := <-conns
	for {
		c.mu.Lock()
		errfn := c.errfn
		c.mu.Unlock()
		if errfn != nil {
			// The socket dies: the listener rebinds, failing three times.
			errfn(errors.New("socket closed"))
			break
		}
		time.Sleep(time.Millisecond)
	}
	<-conns
	time.Sleep(20 * time.Millisecond)
	cancel()
	mu.Lock()
	defer mu.Unlock()
	want := []string{"failed", "bound", "failed", "bound"}
	if len(reports) != len(want) {
		t.Fatalf("reports = %v, want %v", reports, want)
	}
	for i := range want {
		if reports[i] != want[i] {
			t.Fatalf("reports = %v, want %v", reports, want)
		}
	}
}

// C4b: the applied state names each guest device's workload and MAC, which
// the listener resolves a record's device through.
//
// Mutation: leave the MAC out — red.
func TestReconciler_ResolveLogDevice(t *testing.T) {
	r := &Reconciler{}
	r.recordState(context.Background(), Plan{NICs: []NICBinding{{NICDev: "lvt0", VMName: "web-1", MAC: "52:54:00:00:00:01"}}}, nil)
	if w, m := r.ResolveLogDevice("lvt0"); w != "web-1" || m != "52:54:00:00:00:01" {
		t.Errorf("lvt0 = %q %q", w, m)
	}
	if w, m := r.ResolveLogDevice("nope"); w != "" || m != "" {
		t.Errorf("unknown dev = %q %q", w, m)
	}
}
