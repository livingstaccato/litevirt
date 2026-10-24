package rulefield

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServicesFile is the services database nft resolves a port name against: it
// calls getaddrinfo, whose NSS "files" source reads this file. A name is
// matched exactly (nft refuses `dport SSH`), as a service's name or one of its
// aliases, under any protocol (`udp dport http` loads although http is listed
// for tcp only). With no file, nft resolves no name at all.
const ServicesFile = "/etc/services"

// ProtocolsFile is the protocols database nft resolves a protocol name
// against (getprotobyname), beside the names its own parser knows
// (nftProtoNames). A name is matched exactly, as a protocol's name or alias.
const ProtocolsFile = "/etc/protocols"

// services is this host's services database, re-read when the file changes.
var services = &nameDB{path: ServicesFile, parse: parseServices}

// protocols is this host's protocols database.
var protocols = &nameDB{path: ProtocolsFile, parse: parseProtocols}

// nftProtoNames are the protocol names nft's parser turns into a number
// itself, with or without /etc/protocols (checked with the file emptied, on
// nft 1.0.9 and 1.1.6).
var nftProtoNames = map[string]uint64{"tcp": 6, "udp": 17, "udplite": 136, "esp": 50, "ah": 51, "icmp": 1,
	"igmp": 2, "icmpv6": 58, "gre": 47, "comp": 108, "dccp": 33, "sctp": 132}

// nameDB is a names database file (services(5), protocols(5)), re-read when
// it changes.
type nameDB struct {
	mu     sync.Mutex
	path   string
	parse  func([]byte) map[string]uint64
	mod    time.Time
	size   int64
	loaded bool
	ports  map[string]uint64 // name or alias → the first number listed for it
	fixed  map[string]uint64 // Set*ForTest
}

// lookup is the number nft resolves name to, and whether it resolves.
func (d *nameDB) lookup(name string) (uint64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fixed != nil {
		p, ok := d.fixed[name]
		return p, ok
	}
	fi, err := os.Stat(d.path)
	if err != nil {
		d.loaded, d.ports = false, nil
		return 0, false
	}
	if !d.loaded || !fi.ModTime().Equal(d.mod) || fi.Size() != d.size {
		data, err := os.ReadFile(d.path)
		if err != nil {
			d.loaded, d.ports = false, nil
			return 0, false
		}
		d.ports, d.mod, d.size, d.loaded = d.parse(data), fi.ModTime(), fi.Size(), true
	}
	p, ok := d.ports[name]
	return p, ok
}

// resolverProtos are the protocols getaddrinfo(NULL, name, NULL) tries a
// service name under. A name listed only for another (ddp: rtmp, nbp, zip)
// does not resolve: nft refuses `tcp dport rtmp`.
var resolverProtos = map[string]bool{"tcp": true, "udp": true, "sctp": true, "dccp": true, "udplite": true}

// parseServices reads services(5) text: "name port/proto [aliases...]", with
// '#' starting a comment. Only the protocols getaddrinfo tries count.
func parseServices(data []byte) map[string]uint64 {
	out := map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		num, proto, ok := strings.Cut(f[1], "/")
		if !ok || !resolverProtos[proto] {
			continue
		}
		port, err := strconv.ParseUint(num, 10, 16)
		if err != nil {
			continue
		}
		for _, name := range append([]string{f[0]}, f[2:]...) {
			if _, seen := out[name]; !seen {
				out[name] = port
			}
		}
	}
	return out
}

// parseProtocols reads protocols(5) text: "name number [aliases...]".
func parseProtocols(data []byte) map[string]uint64 {
	out := map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 8)
		if err != nil {
			continue
		}
		for _, name := range append([]string{f[0]}, f[2:]...) {
			if _, seen := out[name]; !seen {
				out[name] = n
			}
		}
	}
	return out
}

func (d *nameDB) setForTest(m map[string]uint64) (restore func()) {
	d.mu.Lock()
	prev := d.fixed
	d.fixed = m
	d.mu.Unlock()
	return func() {
		d.mu.Lock()
		d.fixed = prev
		d.mu.Unlock()
	}
}

// SetServicesForTest makes the services database the given name → port map
// until the returned func restores it. Not for a parallel test.
func SetServicesForTest(ports map[string]uint64) (restore func()) { return services.setForTest(ports) }

// SetProtocolsForTest makes the protocols database the given name → number
// map until the returned func restores it. Not for a parallel test.
func SetProtocolsForTest(protos map[string]uint64) (restore func()) {
	return protocols.setForTest(protos)
}

// nftPortVal is a port word as nft reads it: 0x-hex, octal after a leading
// zero when every digit is octal (`026` is 22, `0000022` is 18), otherwise
// decimal (`08` is 8). ok is false for a word that is not a number.
// overflow reports a value too large to hold.
func nftPortVal(w string) (v uint64, ok, overflow bool) {
	if h, isHex := strings.CutPrefix(strings.ToLower(w), "0x"); isHex {
		if h == "" || strings.Trim(h, "0123456789abcdef") != "" {
			return 0, false, false
		}
		v, err := strconv.ParseUint(h, 16, 64)
		return v, true, err != nil
	}
	if w == "" || strings.Trim(w, "0123456789") != "" {
		return 0, false, false
	}
	base := 10
	if len(w) > 1 && w[0] == '0' && strings.Trim(w, "01234567") == "" {
		base = 8
	}
	v, err := strconv.ParseUint(w, base, 64)
	return v, true, err != nil
}

// strtoumaxVal is a protocol word as nft reads it (strtoumax, base 0, the
// whole word): 0x-hex, octal after a leading zero, else decimal. `08` is not
// a number to it (it stops at the 8), so it is looked up as a name and
// refused.
func strtoumaxVal(w string) (v uint64, ok, overflow bool) {
	l := strings.ToLower(w)
	base := 10
	switch {
	case strings.HasPrefix(l, "0x"):
		l, base = l[2:], 16
	case len(l) > 1 && l[0] == '0':
		l, base = l[1:], 8
	}
	if l == "" {
		return 0, false, false
	}
	for _, r := range l {
		if !(r >= '0' && r <= '9' && (base != 8 || r <= '7')) && !(base == 16 && r >= 'a' && r <= 'f') {
			return 0, false, false
		}
	}
	v, err := strconv.ParseUint(l, base, 64)
	return v, true, err != nil
}

// ProtoUnresolvable is why nft cannot resolve a protocol the renderer writes,
// or "": a number past 255 (nft: "Protocol out of range"), a name neither
// nft's parser nor this host's protocols database knows ("Could not resolve
// protocol name"), or a range whose end is below its start ("Range negative
// size"). The renderer writes the protocol lower case.
func ProtoUnresolvable(s string) string {
	if !RendersProto(s) {
		return ""
	}
	for _, words := range portWords(s) {
		var vals []uint64
		for _, w := range words {
			v, num, overflow := strtoumaxVal(w)
			switch {
			case num && (overflow || v > 255):
				return fmt.Sprintf("protocol %s is outside 0-255", w)
			case num:
			default:
				p, ok := nftProtoNames[w]
				if !ok {
					p, ok = protocols.lookup(w)
				}
				if !ok {
					return fmt.Sprintf("protocol %q is neither one nft knows nor in this host's protocols database (%s), so nft cannot resolve it", w, ProtocolsFile)
				}
				v = p
			}
			vals = append(vals, v)
		}
		if len(vals) == 2 && vals[0] > vals[1] {
			return fmt.Sprintf("range %s-%s runs backwards (%d-%d as nft reads it)", words[0], words[1], vals[0], vals[1])
		}
	}
	return ""
}

// orderOps are the relational operators that order values. nft refuses one in
// front of a set, a range or a prefix ("Relational expression (<) is
// undefined for set expressions"); equality and its negation take all three.
var orderOps = map[string]bool{"<": true, ">": true, "<=": true, ">=": true, "lt": true, "gt": true, "le": true, "ge": true}

// RelationalMisuse is why nft refuses value s of field (proto, port or cidr)
// for its relational operator, or "": an ordering operator in front of a
// braced list, a range or (cidr) a prefix. A single value takes one.
func RelationalMisuse(field, s string) string {
	_, v := stripMask(trimBlank(blanks(s)))
	op, rest := cutOp(v)
	if !orderOps[op] || strings.HasPrefix(rest, "@") {
		return ""
	}
	what := ""
	switch {
	case strings.HasPrefix(rest, "{"):
		what = "set"
	case field == "cidr":
		if _, _, r := cutRange(rest); r || strings.Count(rest, "-") == 1 && looksV4Range(rest) {
			what = "range"
		} else if strings.Contains(rest, "/") {
			what = "prefix"
		}
	default:
		if w := portWords(rest); len(w) == 1 && len(w[0]) == 2 {
			what = "range"
		}
	}
	if what == "" {
		return ""
	}
	return fmt.Sprintf("nft cannot compare a %s with %s (\"Relational expression is undefined for %s expressions\"); use == or != with a list, range or prefix", what, op, what)
}

// portWords are the value words of a port match as nft reads them, lower
// case as the renderer writes them: the bitmask, then each list element, a
// range as its two ends. An unspaced dash after a number makes a range; after
// a letter it is part of a service name (netbios-ns). A protocol match reads
// the same way.
func portWords(s string) [][]string {
	v := trimBlank(blanks(strings.ToLower(s)))
	var out [][]string
	mask, v := stripMask(v)
	if mask != "" {
		out = append(out, []string{mask})
	}
	v = stripOp(v)
	var elems []string
	if strings.HasPrefix(v, "{") {
		inner := strings.TrimSuffix(trimBlank(v[1:]), "}")
		for _, e := range strings.Split(inner, ",") {
			if e = trimBlank(e); e != "" {
				elems = append(elems, e)
			}
		}
	} else if v != "" {
		elems = []string{v}
	}
	for _, e := range elems {
		lo, hi, isRange := cutRange(e)
		if !isRange {
			if l, h, found := strings.Cut(e, "-"); found {
				if _, num, _ := nftPortVal(l); num {
					lo, hi, isRange = l, h, true
				}
			}
		}
		if isRange {
			out = append(out, []string{lo, hi})
		} else {
			out = append(out, []string{lo})
		}
	}
	return out
}

// PortUnresolvable is why nft on this host cannot resolve a port the renderer
// writes (tcp and udp), or "": a number outside 0-65535, a name not in the
// services database (ServicesFile), or a range whose end is below its start.
// nft refuses the whole ruleset over any of them.
func PortUnresolvable(proto, s string) string {
	if !RendersPort(proto) || s == "" {
		return ""
	}
	for _, words := range portWords(s) {
		var vals []uint64
		for _, w := range words {
			v, num, overflow := nftPortVal(w)
			if num {
				if overflow || v > 65535 {
					return fmt.Sprintf("port %s is outside 0-65535", w)
				}
			} else {
				p, ok := services.lookup(w)
				if !ok {
					return fmt.Sprintf("service %q is not in this host's services database (%s), so nft cannot resolve it", w, ServicesFile)
				}
				v = p
			}
			vals = append(vals, v)
		}
		if len(vals) == 2 && vals[0] > vals[1] {
			return fmt.Sprintf("range %s-%s runs backwards (%d-%d as nft reads it)", words[0], words[1], vals[0], vals[1])
		}
	}
	return ""
}
