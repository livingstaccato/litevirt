package firewall

// The NFLOG listener (docs/firewall.md, "Logging"; spec §3.5, L-1, L-2):
// every log line the renderer writes sends its packet to NFLOG group
// firewall.log_group, never to the kernel log. This listener reads that group
// into the LogStore. With no listener the kernel discards the records.

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	nflog "github.com/florianl/go-nflog/v2"
)

// DefaultLogGroup is the NFLOG group the daemon listens on with no
// firewall.log_group.
const DefaultLogGroup = 27

// nflogConn is the part of a go-nflog connection the listener uses.
type nflogConn interface {
	RegisterWithErrorFunc(ctx context.Context, fn nflog.HookFunc, errfn nflog.ErrorFunc) error
	Close() error
}

// How long the kernel holds a record for the listener, and how many it
// holds, before it sends them (NFULA_CFG_TIMEOUT, NFULA_CFG_QTHRESH). Left
// unset the kernel holds them up to 1 s, or until about 21 fill its buffer,
// and a record without a packet timestamp is stamped that late.
//
// The timeout is in 1/100 s and 1 is the least go-nflog sends (it leaves 0
// at the kernel's 1 s): a record reaches the store within about 10 ms. That
// is at most 100 timer flushes a second, however many records there are.
// The threshold sends a batch at once when 16 are held, below the ~21 a
// buffer holds, so it is what decides under load. The kernel's record rate R
// is bounded by the log lines' limits (each NIC side's rate, and
// lv_lg_routed), not by firewall.log_max_rate, which the store applies after
// it: R records a second cost at most 100 + R/16 sends, against R with a
// threshold of 1. One side's default burst (10) never reaches 16 alone, and
// at R = 200 (the default log_max_rate) that is at most about 113 sends a
// second.
const (
	logFlushTimeout = 1  // 1/100 s
	logQThresh      = 16 // records
)

// nflogConfig is the group's configuration: each packet's headers, records
// numbered (FlagSeq: a gap is a record the kernel dropped before the listener
// read it, a full socket buffer), sent within logFlushTimeout or at
// logQThresh records.
func nflogConfig(group uint16) *nflog.Config {
	return &nflog.Config{Group: group, Copymode: nflog.CopyPacket, Bufsize: logSnaplen, Flags: nflog.FlagSeq,
		Timeout: logFlushTimeout, QThresh: logQThresh}
}

// openNflog binds a netlink socket to group (nflogConfig).
func openNflog(group uint16) (nflogConn, error) {
	return nflog.Open(nflogConfig(group))
}

// LogListener reads NFLOG group Group into Store.
type LogListener struct {
	Group uint16
	Store *LogStore
	// Resolve names the workload and MAC of a guest device through the plan
	// in force (Reconciler.ResolveLogDevice); nil resolves nothing.
	Resolve func(dev string) (workload, mac string)
	// OnBind is told each change of the listener's state: an error when it
	// cannot bind (or loses) the group, nil once it is bound. It is called
	// once per transition, never per retry.
	OnBind func(err error)

	open  func(group uint16) (nflogConn, error) // openNflog; a test seam
	retry time.Duration                         // between binds; 30 s

	mu      sync.Mutex
	lastSeq uint32
	haveSeq bool
}

// Run binds the group and reads it until ctx ends, binding again whenever the
// socket fails.
func (l *LogListener) Run(ctx context.Context) {
	open := l.open
	if open == nil {
		open = openNflog
	}
	retry := l.retry
	if retry <= 0 {
		retry = 30 * time.Second
	}
	var reported *bool // nil before the first state; then whether bound
	report := func(err error) {
		bound := err == nil
		if reported != nil && *reported == bound {
			return
		}
		reported = &bound
		if l.OnBind != nil {
			l.OnBind(err)
		}
	}
	for ctx.Err() == nil {
		err := l.serve(ctx, open, report)
		if ctx.Err() != nil {
			return
		}
		report(err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
	}
}

// serve binds once and reads until the socket fails or ctx ends; it reports
// the bind itself.
func (l *LogListener) serve(ctx context.Context, open func(uint16) (nflogConn, error), report func(error)) error {
	conn, err := open(l.Group)
	if err != nil {
		return err
	}
	defer conn.Close()
	l.mu.Lock()
	l.haveSeq = false
	l.mu.Unlock()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	dead := make(chan error, 1)
	errfn := func(err error) int {
		if errors.Is(err, syscall.ENOBUFS) {
			// The socket overflowed; the sequence gap counts what was lost.
			return 0
		}
		var op interface{ Timeout() bool }
		if errors.As(err, &op) && op.Timeout() && sctx.Err() == nil {
			return 0
		}
		select {
		case dead <- err:
		default:
		}
		return 1
	}
	if err := conn.RegisterWithErrorFunc(sctx, l.handle, errfn); err != nil {
		return err
	}
	report(nil)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-dead:
		// Reported before the deferred close: the pass that removes the log
		// lines is asked for while this socket still holds the group.
		report(err)
		return err
	}
}

// handle keeps one record. It never fails the socket.
func (l *LogListener) handle(a nflog.Attribute) int {
	if a.Seq != nil {
		l.mu.Lock()
		if l.haveSeq && *a.Seq > l.lastSeq+1 {
			l.Store.Overflow(int(*a.Seq - l.lastSeq - 1))
		}
		l.lastSeq, l.haveSeq = *a.Seq, true
		l.mu.Unlock()
	}
	if a.Prefix == nil {
		return 0
	}
	r, ok := parseLogPrefix(*a.Prefix)
	if !ok {
		return 0
	}
	if a.Timestamp != nil {
		// The kernel's time for the packet; the store keeps it unless it is
		// implausible. A packet the host sends carries none, and the store
		// stamps the time it receives the record.
		r.Time, r.TimeSource = *a.Timestamp, LogTimePacket
	}
	if a.Payload != nil {
		parseLogPacket(&r, *a.Payload)
	}
	if l.Resolve != nil && r.Device != "-" {
		r.Workload, r.MAC = l.Resolve(r.Device)
	}
	l.Store.Add(r)
	return 0
}

// parseLogPrefix reads the prefix the renderer writes,
// "lv-log <dev> <in|out|-> <rule-id|rule|default> <accept|drop|would-drop>".
func parseLogPrefix(p string) (LogRecord, bool) {
	f := strings.Fields(strings.TrimRight(p, "\x00"))
	if len(f) != 5 || f[0] != "lv-log" {
		return LogRecord{}, false
	}
	switch f[2] {
	case "in", "out", "-":
	default:
		return LogRecord{}, false
	}
	switch f[4] {
	case "accept", "drop", "would-drop":
	default:
		return LogRecord{}, false
	}
	// Only what the renderer writes (another program can send a prefix of
	// this shape to the group): a device is an interface name or "-", a rule
	// a logRuleID, "rule" or "default".
	if (f[1] != "-" && !logDevName(f[1])) || !logRuleField(f[3]) {
		return LogRecord{}, false
	}
	r := LogRecord{Device: f[1], Side: f[2], RuleID: f[3], Verdict: f[4], Tier: "nic"}
	if f[1] == "-" {
		r.Tier = "routed"
	}
	return r, true
}

// logDevName reports whether s can be an interface name as a prefix carries
// it: 1-15 bytes of [A-Za-z0-9._@-].
func logDevName(s string) bool {
	if len(s) == 0 || len(s) > 15 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '@' || c == '-') {
			return false
		}
	}
	return true
}

// logRuleField reports whether s is a rule as a prefix carries it:
// [0-9a-z-]{1,32}, which "rule" and "default" are.
func logRuleField(s string) bool {
	if len(s) == 0 || len(s) > maxLogRuleID {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// ipv6ExtHeaders are the IPv6 extension headers parseLogPacket steps over to
// reach the transport header.
var ipv6ExtHeaders = map[byte]bool{0: true, 43: true, 60: true}

// parseLogPacket fills r from the packet's network and transport headers (the
// bridge family logs from the network header). A truncated or unknown packet
// keeps what could be read.
func parseLogPacket(r *LogRecord, b []byte) {
	if len(b) < 1 {
		return
	}
	var l4 []byte
	var proto byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return
		}
		ihl := int(b[0]&0x0f) * 4
		r.Family = "ip"
		r.Length = uint32(binary.BigEndian.Uint16(b[2:]))
		proto = b[9]
		r.Src = netip.AddrFrom4([4]byte(b[12:16])).String()
		r.Dst = netip.AddrFrom4([4]byte(b[16:20])).String()
		fragOff := binary.BigEndian.Uint16(b[6:]) & 0x1fff
		if ihl >= 20 && fragOff == 0 && len(b) > ihl {
			l4 = b[ihl:]
		}
	case 6:
		if len(b) < 40 {
			return
		}
		r.Family = "ip6"
		r.Length = uint32(binary.BigEndian.Uint16(b[4:])) + 40
		r.Src = netip.AddrFrom16([16]byte(b[8:24])).String()
		r.Dst = netip.AddrFrom16([16]byte(b[24:40])).String()
		proto, off := b[6], 40
		for i := 0; i < 8 && ipv6ExtHeaders[proto]; i++ {
			if len(b) < off+2 {
				off = -1
				break
			}
			proto, off = b[off], off+(int(b[off+1])+1)*8
		}
		if proto == 44 { // a fragment: the transport header may not be here
			off = -1
		}
		if off > 0 && len(b) > off {
			l4 = b[off:]
		}
		r.Proto = protoName(proto)
		parseL4(r, proto, l4)
		return
	default:
		return
	}
	r.Proto = protoName(proto)
	parseL4(r, proto, l4)
}

func parseL4(r *LogRecord, proto byte, l4 []byte) {
	switch proto {
	case 6, 17, 132, 136: // tcp, udp, sctp, udplite
		if len(l4) < 4 {
			return
		}
		r.Sport = binary.BigEndian.Uint16(l4[0:])
		r.Dport = binary.BigEndian.Uint16(l4[2:])
		if proto == 6 && len(l4) >= 14 {
			r.TCPFlags = tcpFlags(l4[13])
		}
	}
}

func protoName(p byte) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	}
	return strconv.Itoa(int(p))
}

// tcpFlags is the TCP flags byte as letters, tcpdump's order.
func tcpFlags(f byte) string {
	var b strings.Builder
	for _, x := range []struct {
		bit byte
		c   byte
	}{{0x01, 'F'}, {0x02, 'S'}, {0x04, 'R'}, {0x08, 'P'}, {0x10, '.'}, {0x20, 'U'}, {0x40, 'E'}, {0x80, 'W'}} {
		if f&x.bit != 0 {
			b.WriteByte(x.c)
		}
	}
	return b.String()
}
