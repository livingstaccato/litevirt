package rulefield

// nftKeywords are the words nft refuses as a set name: each is a keyword where
// a set name goes, so `set drop {` fails with "syntax error, unexpected drop"
// and so does the whole ruleset. The candidates were every keyword rule in
// nftables' scanner.l for 1.0.9 and 1.1.6 (the operator words ne, gt, ge, xor,
// lshift and rshift among them) and every word in libnftables; each was
// loaded as a set name, declared and referenced, with `nft -c` on both
// versions. This is the union of the refusals: 1.0.9 refuses the same words
// less tunnel. Case matters: `DROP` is a name.
var nftKeywords = map[string]bool{}

func init() {
	for _, w := range []string{
		".", "accept", "add", "ah", "all", "and", "arp", "auto-merge", "bridge", "cgroup", "chain",
		"comment", "comp", "constant", "continue", "counter", "cpu", "create", "ct", "day", "dccp",
		"define", "delete", "describe", "destroy", "device", "devices", "dnat", "drop", "dst", "dup",
		"dynamic", "ecn", "element", "elements", "eq", "esp", "ether", "exists", "expires", "export",
		"exthdr", "fib", "flags", "flow", "flowtable", "flush", "frag", "fwd", "gc-interval", "ge",
		"geneve", "get", "goto", "gre", "gretap", "gt", "handle", "hbh", "hook", "hour", "ibriport",
		"ibrname", "icmp", "icmpv6", "igmp", "iif", "iifgroup", "iifname", "iiftype", "import",
		"include", "index", "inet", "insert", "interval", "ip", "ip6", "ipsec", "jhash", "jump", "le",
		"limit", "list", "ll", "log", "lshift", "lt", "map", "mark", "masquerade", "meta", "meter", "mh",
		"missing", "monitor", "ne", "netdev", "nftrace", "nh", "not", "notrack", "numgen", "obriport",
		"obrname", "offload", "oif", "oifgroup", "oifname", "oiftype", "or", "osf", "pkttype", "policy",
		"position", "priority", "queue", "quota", "random", "redefine", "redirect", "reject", "rename",
		"replace", "reset", "return", "rshift", "rt", "rt0", "rt2", "rtclassid", "rule", "ruleset",
		"sctp", "secmark", "set", "size", "skgid", "skuid", "snat", "socket", "srh", "symhash",
		"synproxy", "table", "tcp", "th", "time", "timeout", "tproxy", "tunnel", "type", "typeof", "udp",
		"udplite", "undefine", "update", "vlan", "vmap", "vni", "vxlan", "xor", "xt",
	} {
		nftKeywords[w] = true
	}
}
