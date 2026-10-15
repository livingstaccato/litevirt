package rulefield

// nftKeywords are the words nft (1.1.6) refuses as a set name: each is a
// keyword where a set name goes, so `set drop {` fails with "syntax error,
// unexpected drop" and so does the whole ruleset. Found by loading every word
// in libnftables as a set name (declared and referenced) with `nft -c`. Case
// matters: `DROP` is a name.
var nftKeywords = map[string]bool{}

func init() {
	for _, w := range []string{
		".", "accept", "add", "ah", "all", "and", "arp", "auto-merge", "bridge", "cgroup", "chain",
		"comment", "comp", "constant", "continue", "counter", "cpu", "create", "ct", "day", "dccp",
		"define", "delete", "describe", "destroy", "device", "devices", "dnat", "drop", "dst", "dup",
		"dynamic", "ecn", "element", "elements", "eq", "esp", "ether", "exists", "expires", "export",
		"exthdr", "fib", "flags", "flow", "flowtable", "flush", "frag", "fwd", "gc-interval", "geneve",
		"get", "goto", "gre", "gretap", "handle", "hbh", "hook", "hour", "ibriport", "ibrname", "icmp",
		"icmpv6", "igmp", "iif", "iifgroup", "iifname", "iiftype", "import", "include", "index", "inet",
		"insert", "interval", "ip", "ip6", "ipsec", "jhash", "jump", "le", "limit", "list", "ll", "log",
		"lt", "map", "mark", "masquerade", "meta", "meter", "mh", "missing", "monitor", "netdev",
		"nftrace", "nh", "not", "notrack", "numgen", "obriport", "obrname", "offload", "oif", "oifgroup",
		"oifname", "oiftype", "or", "osf", "pkttype", "policy", "position", "priority", "queue", "quota",
		"random", "redefine", "redirect", "reject", "rename", "replace", "reset", "return", "rt", "rt0",
		"rt2", "rtclassid", "rule", "ruleset", "sctp", "secmark", "set", "size", "skgid", "skuid", "snat",
		"socket", "srh", "symhash", "synproxy", "table", "tcp", "th", "time", "timeout", "tproxy",
		"tunnel", "type", "typeof", "udp", "udplite", "undefine", "update", "vlan", "vmap", "vni",
		"vxlan", "xt",
	} {
		nftKeywords[w] = true
	}
}
