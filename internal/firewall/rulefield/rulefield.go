// Package rulefield is the grammar of the firewall fields the renderer
// (internal/firewall) writes into an nftables script as text: a rule's
// protocol, port and IPv4 CIDR (written verbatim), its comment (quoted), and
// an ip set's name and elements (verbatim).
//
// `nft -f -` loads every host's ruleset as one transaction, so a value nft
// cannot parse stops every host's firewall from applying, and a value carrying
// a newline, a `;`, a `#`, a brace, a quote or a second word adds nft syntax of
// its own to every host's ruleset (finding F-1).
//
// There are two levels, because a stored row that applies today must keep
// applying, byte for byte, after an upgrade:
//
//   - Syntax (RenderProto, RenderPort, RenderCIDR, RenderSetName,
//     RenderSetElement) is what the renderer checks on every row it is handed,
//     including rows a peer on an older build replicated. It refuses only
//     text that can add or break nft syntax: anything but the value's own
//     words (letters, digits and . _ : / - @), an optional relational operator
//     in front, a braced list, and a range with spaces around its dash. It
//     does not judge a word: whether `ssh` is a service or a name resolves is
//     nft's business, exactly as before.
//
//   - Grammar (Rule, Direction, Proto, Port, CIDR, Action, Comment, IPSet) is
//     what every writer checks before a row is stored (corrosion's rule and
//     ip-set writers, the gRPC handlers, the stack deploy, the compose
//     validator). It is Syntax plus what can be judged without the host: port
//     numbers 0-65535, ranges that do not run backwards, protocol numbers
//     0-255, IPv4 addresses that parse, no bare comma list (nft refuses one:
//     "not bitmask"). It accepts every form nft accepts in the renderer's
//     position, including relational operators (`!= 22`, `< 1024`), braced
//     lists (`{ 80, 443 }`), ranges, service and protocol names, DNS names in
//     a CIDR, `!= @set`, and protocol names in any case.
//
// The package imports only the standard library, so corrosion, compose and the
// renderer can all share it.
package rulefield

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// FieldError names the field and the value a check refused.
type FieldError struct {
	Field  string // "direction", "proto", "port", "cidr", "action", "comment", "ipset name", "ipset element"
	Value  string
	Reason string
}

// maxShownValue bounds the value an error (and so a log line or a replicated
// health condition) repeats: a row from a peer on an older build can be
// megabytes long.
const maxShownValue = 64

func (e *FieldError) Error() string {
	return fmt.Sprintf("invalid %s %q: %s", e.Field, shown(e.Value), e.Reason)
}

// shown is v cut to maxShownValue bytes at a rune boundary, marked when cut.
func shown(v string) string {
	if len(v) <= maxShownValue {
		return v
	}
	cut := maxShownValue
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + "…"
}

func refuse(field, value, format string, args ...any) error {
	return &FieldError{Field: field, Value: value, Reason: fmt.Sprintf(format, args...)}
}

// SetRef is the ip-set name a CIDR references, after any relational operator
// ("@x", "!= @x", "!=@x"), and whether it references one.
func SetRef(cidr string) (string, bool) {
	v := stripOp(trimBlank(blanks(cidr)))
	if name, ok := strings.CutPrefix(v, "@"); ok {
		return name, true
	}
	return "", false
}

// NegatedSetRef reports whether cidr is a negated set reference ("!= @x",
// "ne @x").
func NegatedSetRef(cidr string) bool {
	v := trimBlank(blanks(cidr))
	return strings.HasPrefix(v, "!=") || strings.HasPrefix(v, "ne ")
}

// NormaliseSetElements splits every element on ',' and drops the empty
// pieces and the blanks around them: `--cidr 10.0.0.1,10.0.0.2` is two
// elements. A stored element holding a comma renders inside nft's element
// list either way; this keeps what a writer stores one element per entry.
func NormaliseSetElements(elems []string) []string {
	var out []string
	for _, e := range elems {
		for _, piece := range strings.Split(e, ",") {
			if piece = trimBlank(piece); piece != "" {
				out = append(out, piece)
			}
		}
	}
	return out
}

// blanks turns tabs into spaces for analysis only: nft separates words with
// either. The value is always rendered as stored.
func blanks(s string) string { return strings.ReplaceAll(s, "\t", " ") }

// MaxCommentBytes is nft's limit on a rule comment ("comment too long, 128
// characters maximum allowed"), counted on the text between the quotes the
// renderer writes.
const MaxCommentBytes = 128

// maxNameLen is nft's limit on a set name (NFT_NAME_MAXLEN less the NUL).
const maxNameLen = 255

// maxValueLen bounds any one value, so a list cannot grow without limit.
const maxValueLen = 4096

// QuotedLen is the length of s between the quotes as the renderer writes it
// (Go %q, which escapes control characters and invalid UTF-8).
func QuotedLen(s string) int { return len(strconv.Quote(s)) - 2 }

// trimBlank strips the spaces and tabs nft ignores around a value. A newline is
// never stripped: it ends an nft statement.
func trimBlank(s string) string { return strings.Trim(s, " \t") }

// RendersPort reports whether the renderer writes a rule's port: only for
// tcp and udp, matched as the renderer matches them.
func RendersPort(proto string) bool {
	switch strings.ToLower(proto) {
	case "tcp", "udp":
		return true
	}
	return false
}

// RendersProto reports whether the renderer writes a rule's protocol as text.
func RendersProto(proto string) bool {
	switch strings.ToLower(proto) {
	case "", "all", "tcp", "udp", "icmp", "icmpv6", "ipv6-icmp":
		return false
	}
	return true
}

// ── Syntax: what the renderer checks ───────────────────────────────────────

// RenderProto refuses a protocol the renderer would write as anything but
// nft words.
func RenderProto(s string) error {
	if !RendersProto(s) {
		return nil
	}
	if why := syntax(strings.ToLower(s), true); why != "" {
		return refuse("proto", s, "%s", why)
	}
	return nil
}

// RenderPort refuses a port the renderer would write (tcp and udp only) as
// anything but nft words.
func RenderPort(proto, s string) error {
	if !RendersPort(proto) || s == "" {
		return nil
	}
	if why := syntax(s, true); why != "" {
		return refuse("port", s, "%s", why)
	}
	return nil
}

// RenderCIDR refuses an IPv4 CIDR the renderer would write as anything but nft
// words. A set reference and an IPv6 CIDR are checked by the renderer itself,
// as they always were.
func RenderCIDR(s string) error {
	if s == "" || strings.HasPrefix(s, "@") || (strings.Contains(s, ":")) {
		return nil
	}
	if why := syntax(s, true); why != "" {
		return refuse("cidr", s, "%s", why)
	}
	return nil
}

// RenderSetName refuses a set name that is not one nft word.
func RenderSetName(s string) error {
	if s == "" {
		return refuse("ipset name", s, "a set name cannot be empty")
	}
	if !isWord(s) || strings.Contains(s, "@") {
		return refuse("ipset name", s, "a set name is one word of letters, digits and . _ - /")
	}
	return nil
}

// RenderSetElement refuses a set element that is not nft words or ranges
// separated by commas. Inside `elements = { ... }` a comma separates elements,
// so a stored element holding one, or an empty piece between commas, adds no
// syntax (and nft accepts double and trailing commas).
//
// An element with no value, or one that starts with a comma, is refused: it
// can sort first, and nft refuses `elements = { , ...` and `{  }`.
func RenderSetElement(s string) error {
	if len(s) > maxValueLen {
		return refuse("ipset element", s, "longer than %d bytes", maxValueLen)
	}
	pieces := strings.Split(blanks(s), ",")
	if trimBlank(pieces[0]) == "" {
		return refuse("ipset element", s, "an element cannot be empty or start with a comma")
	}
	for _, piece := range pieces {
		if piece = trimBlank(piece); piece == "" {
			continue
		}
		if why := syntaxElem(piece); why != "" {
			return refuse("ipset element", s, "%s", why)
		}
	}
	return nil
}

// syntax matches s as [ op ] ( elem | "{" elem { "," elem } "}" ), elem being
// a word or a range "word - word" (list allows the op and the braces). It
// returns why s does not match, or "".
func syntax(s string, list bool) string {
	if len(s) > maxValueLen {
		return fmt.Sprintf("longer than %d bytes", maxValueLen)
	}
	v := trimBlank(blanks(s))
	if v == "" {
		return "blank"
	}
	if list {
		var mask string
		mask, v = stripMask(v)
		if mask != "" && !isWord(mask) {
			return fmt.Sprintf("%q is not a single nft word", mask)
		}
		v = stripOp(v)
	}
	if list && strings.HasPrefix(v, "{") {
		inner, ok := strings.CutSuffix(v, "}")
		if !ok {
			return "a list opened with '{' must end with '}'"
		}
		// Empty pieces (a double or trailing comma) add no syntax.
		for _, e := range strings.Split(inner[1:], ",") {
			if e = trimBlank(e); e == "" {
				continue
			}
			if why := syntaxElem(e); why != "" {
				return why
			}
		}
		return ""
	}
	if strings.Contains(v, ",") {
		return "nft does not accept a bare list; write it braced, as { a, b }"
	}
	return syntaxElem(v)
}

func syntaxElem(e string) string {
	if e == "" {
		return "an empty list element"
	}
	lo, hi, isRange := cutRange(e)
	if !isWord(lo) || (isRange && !isWord(hi)) {
		return fmt.Sprintf("%q is not a single nft word: only letters, digits and . _ : / - @ are written as-is", e)
	}
	return ""
}

// relOps are the relational operators nft accepts in front of a value.
var relOps = []string{"!=", "==", "<=", ">=", "<", ">"}

// relWords are their keyword spellings, which need a space after them.
var relWords = []string{"eq", "ne", "lt", "gt", "le", "ge"}

// stripMask removes a leading bitmask, "& <mask>", and returns the mask.
func stripMask(v string) (mask, rest string) {
	r, ok := strings.CutPrefix(v, "&")
	if !ok {
		return "", v
	}
	r = trimBlank(r)
	mask, rest, _ = strings.Cut(r, " ")
	return mask, trimBlank(rest)
}

// stripOp removes one leading relational operator.
func stripOp(v string) string {
	for _, op := range relOps {
		if rest, ok := strings.CutPrefix(v, op); ok {
			return trimBlank(rest)
		}
	}
	for _, w := range relWords {
		if rest, ok := strings.CutPrefix(v, w+" "); ok {
			return trimBlank(rest)
		}
	}
	return v
}

// cutRange splits "a-b" or "a - b". An element whose dash has no space around
// it and is not between two plausible ends (a service name such as
// netbios-ns) is one word; the caller judges it.
func cutRange(e string) (lo, hi string, ok bool) {
	if l, h, found := strings.Cut(e, " -"); found {
		return trimBlank(l), trimBlank(strings.TrimPrefix(h, " ")), true
	}
	if l, h, found := strings.Cut(e, "- "); found {
		return trimBlank(l), trimBlank(h), true
	}
	return e, "", false
}

// isWord is a run of the characters nft reads as one value token here.
func isWord(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(isLetter(r) || isDigit(r) || strings.ContainsRune("._:/-@", r)) {
			return false
		}
	}
	return true
}

// ── Grammar: what every writer checks ──────────────────────────────────────

// Rule checks every field of one rule and returns the first refusal.
func Rule(direction, proto, port, cidr, action, comment string) error {
	for _, err := range []error{
		Direction(direction), Proto(proto), Port(proto, port), CIDR(cidr), Action(action), Comment(comment),
	} {
		if err != nil {
			return err
		}
	}
	return nil
}

// Direction is never written into a script: ingress and egress (any case)
// name a side, and anything else is read as ingress, as it always has been
// (a writer that requires one checks that itself). Only text that could never
// be a word is refused.
func Direction(s string) error {
	if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return refuse("direction", s, "want ingress or egress")
	}
	return nil
}

// Action accepts "", accept, drop and reject, in any case: the renderer
// refuses a plan with any other, so no other action has ever applied.
func Action(s string) error {
	switch strings.ToLower(s) {
	case "", "accept", "drop", "reject":
		return nil
	}
	return refuse("action", s, "want accept, drop or reject")
}

// Comment accepts any text the renderer can quote for nft: no double quote
// (nft's quoted string has no escape, so a quote ends it and the rest of the
// comment is read as rules) and at most MaxCommentBytes once quoted.
func Comment(s string) error {
	if strings.Contains(s, `"`) {
		return refuse("comment", s, "a comment cannot contain a double quote")
	}
	if n := QuotedLen(s); n > MaxCommentBytes {
		return refuse("comment", s, "%d bytes once quoted; nft allows at most %d", n, MaxCommentBytes)
	}
	return nil
}

// Proto accepts "", "all", tcp, udp, icmp, icmpv6, or a protocol match: a
// protocol name or a number 0-255, or a braced list of them, after an
// optional relational operator. Case does not matter (the renderer lowercases
// it).
func Proto(s string) error {
	if !RendersProto(s) {
		return nil
	}
	if err := RenderProto(s); err != nil {
		return err
	}
	if why := grammar(strings.ToLower(s), protoElem); why != "" {
		return refuse("proto", s, "%s", why)
	}
	return nil
}

func protoElem(e string) string {
	if isDigits(e) {
		if n, _ := strconv.Atoi(e); n > 255 {
			return fmt.Sprintf("protocol number %s is outside 0-255", e)
		}
		return ""
	}
	if !isName(e) {
		return fmt.Sprintf("%q is not a protocol name or number", e)
	}
	if e == "all" {
		return `"all" cannot be negated or listed`
	}
	return ""
}

// Port accepts, for tcp and udp, "" or a port match: a number 0-65535, a range
// N-M (N <= M; M may be a service name), a service name, or a braced list of
// them, after an optional relational operator. For any other protocol the
// port is never written into a script, and only text that could never be a
// word is refused.
func Port(proto, s string) error {
	if !RendersPort(proto) {
		if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return refuse("port", s, "a control character")
		}
		return nil
	}
	if s == "" {
		return nil
	}
	if err := RenderPort(proto, s); err != nil {
		return err
	}
	if why := grammar(s, portElem); why != "" {
		return refuse("port", s, "%s", why)
	}
	return nil
}

func portElem(e string) string {
	lo, hi, isRange := cutRange(e)
	if !isRange && isPortNum(lo) {
		return portNum(lo)
	}
	if !isRange {
		// Unspaced, a dash after a number is a range; after a letter it is
		// part of a service name (nft reads "netbios-ns" as one word).
		l, h, found := strings.Cut(e, "-")
		if found && isPortNum(l) {
			lo, hi, isRange = l, h, true
		}
	}
	if !isRange {
		if isName(e) {
			return "" // a service name; it may contain '-'
		}
		return fmt.Sprintf("%q is not a port, a range or a service name", e)
	}
	for _, end := range []string{lo, hi} {
		if isPortNum(end) {
			if why := portNum(end); why != "" {
				return why
			}
		} else if !isName(end) {
			return fmt.Sprintf("%q is not a port, a range or a service name", e)
		}
	}
	if isPortNum(lo) && isPortNum(hi) && portVal(lo) > portVal(hi) {
		return fmt.Sprintf("range %s runs backwards", e)
	}
	return ""
}

// isPortNum is a decimal or 0x-hex number.
func isPortNum(s string) bool {
	if h, ok := strings.CutPrefix(strings.ToLower(s), "0x"); ok {
		if h == "" || len(h) > 8 {
			return false
		}
		for _, r := range h {
			if !isDigit(r) && (r < 'a' || r > 'f') {
				return false
			}
		}
		return true
	}
	return isDigits(s)
}

// portVal is a port number's value: hex after 0x, otherwise decimal (nft
// reads a leading zero as decimal).
func portVal(s string) int64 {
	if h, ok := strings.CutPrefix(strings.ToLower(s), "0x"); ok {
		n, _ := strconv.ParseInt(h, 16, 64)
		return n
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func portNum(s string) string {
	if portVal(s) > 65535 {
		return fmt.Sprintf("port %s is outside 0-65535", s)
	}
	return ""
}

// CIDR accepts "", a set reference "@<name>", one IPv6 address or prefix
// (exactly as written, as the IPv6 renderer has always required), or an IPv4
// match: an address, a prefix, a range A-B (A <= B), a DNS name, or a braced
// list of them, after an optional relational operator; a negated set
// reference ("!= @name") too.
func CIDR(s string) error {
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "@") {
		if err := SetName(s[1:]); err != nil {
			return refuse("cidr", s, "set reference: %s", err.(*FieldError).Reason)
		}
		return nil
	}
	if strings.Contains(s, ":") {
		if !v6AddrOrPrefix(s) {
			return refuse("cidr", s, "not an IPv6 address or prefix")
		}
		return nil
	}
	if err := RenderCIDR(s); err != nil {
		return err
	}
	if name, ok := SetRef(s); ok {
		if err := SetName(name); err != nil {
			return refuse("cidr", s, "set reference: %s", err.(*FieldError).Reason)
		}
		return nil
	}
	if why := grammar(s, v4Elem); why != "" {
		return refuse("cidr", s, "%s", why)
	}
	return nil
}

func v4Elem(e string) string {
	if strings.HasPrefix(e, "@") {
		return "a set reference cannot be listed"
	}
	if lo, hi, ok := cutRange(e); ok || strings.Count(e, "-") == 1 && looksV4Range(e) {
		if !ok {
			lo, hi, _ = strings.Cut(e, "-")
		}
		a, err1 := netip.ParseAddr(lo)
		b, err2 := netip.ParseAddr(hi)
		if err1 != nil || err2 != nil || !a.Is4() || !b.Is4() {
			return fmt.Sprintf("%q is not an IPv4 range", e)
		}
		if b.Less(a) {
			return fmt.Sprintf("range %s runs backwards", e)
		}
		return ""
	}
	if v4AddrOrPrefix(e) || isDNSName(e) {
		return ""
	}
	return fmt.Sprintf("%q is not an IPv4 address, prefix, range or DNS name", e)
}

// looksV4Range is "digits-and-dots - digits-and-dots", which is an address
// range rather than a DNS name with a hyphen.
func looksV4Range(e string) bool {
	lo, hi, _ := strings.Cut(e, "-")
	return isDotted(lo) && isDotted(hi)
}

func isDotted(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isDigit(r) && r != '.' {
			return false
		}
	}
	return true
}

// SetName accepts an nft set name: a letter, '_' or '.', then letters,
// digits, '_', '.', '-' or '/', at most 255 bytes.
func SetName(s string) error {
	if s == "" {
		return refuse("ipset name", s, "a set name cannot be empty")
	}
	if len(s) > maxNameLen {
		return refuse("ipset name", s, "longer than %d bytes", maxNameLen)
	}
	for i, r := range s {
		ok := r == '_' || r == '.' || isLetter(r) ||
			(i > 0 && (isDigit(r) || r == '-' || r == '/'))
		if !ok {
			return refuse("ipset name", s, "want a letter, '_' or '.' first, then letters, digits, '_', '.', '-' or '/'")
		}
	}
	return nil
}

// SetElement accepts one ip-set element: an IPv6 address or prefix exactly as
// written, or an IPv4 address, prefix, range A-B or DNS name.
//
// An element holding commas (`--cidr 10.0.0.1,10.0.0.2`) is several elements,
// each checked; writers store them split (NormaliseSetElements).
func SetElement(s string) error {
	pieces := NormaliseSetElements([]string{s})
	if len(pieces) == 0 {
		return refuse("ipset element", s, "an element cannot be empty")
	}
	for _, p := range pieces {
		if err := RenderSetElement(p); err != nil {
			return refuse("ipset element", s, "%s", err.(*FieldError).Reason)
		}
		if strings.Contains(p, ":") {
			if !v6AddrOrPrefix(p) {
				return refuse("ipset element", s, "%q is not an IPv6 address or prefix", p)
			}
			continue
		}
		if why := v4Elem(p); why != "" {
			return refuse("ipset element", s, "%s", why)
		}
	}
	return nil
}

// IPSet checks a set's name and every element, returning the first refusal.
func IPSet(name string, elems []string) error {
	if err := SetName(name); err != nil {
		return err
	}
	for _, e := range elems {
		if err := SetElement(e); err != nil {
			return err
		}
	}
	return nil
}

// grammar judges each element of a value that has passed syntax.
func grammar(s string, elem func(string) string) string {
	mask, v := stripMask(trimBlank(blanks(s)))
	if mask != "" {
		if why := elem(mask); why != "" {
			return why
		}
	}
	v = stripOp(v)
	if strings.HasPrefix(v, "{") {
		inner := strings.TrimSuffix(trimBlank(v[1:]), "}")
		pieces := strings.Split(inner, ",")
		// nft takes a double or a trailing comma, not a leading one or none
		// at all.
		if trimBlank(pieces[0]) == "" {
			return "a list cannot start with a comma or be empty"
		}
		for _, e := range pieces {
			if e = trimBlank(e); e == "" {
				continue
			}
			if why := elem(e); why != "" {
				return why
			}
		}
		return ""
	}
	return elem(v)
}

func isDigits(s string) bool {
	if s == "" || len(s) > 6 {
		return false
	}
	for _, r := range s {
		if !isDigit(r) {
			return false
		}
	}
	return true
}

// isName is an nft name word: a letter, then letters, digits, '.', '_' or '-'.
func isName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		if !(isLetter(r) || (i > 0 && (isDigit(r) || r == '.' || r == '_' || r == '-'))) {
			return false
		}
	}
	return true
}

// isDNSName is a host name nft resolves when it loads the ruleset: labels of
// letters, digits and '-', separated by '.', with a letter somewhere (so a
// malformed address is not taken for a name).
func isDNSName(s string) bool {
	if s == "" || len(s) > 253 || !strings.ContainsFunc(s, isLetter) {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(isLetter(r) || isDigit(r) || r == '-') {
				return false
			}
		}
	}
	return true
}

func isLetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }
func isDigit(r rune) bool  { return r >= '0' && r <= '9' }

func v4AddrOrPrefix(s string) bool {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().Is4()
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

// v6AddrOrPrefix matches the renderer's validAddrOrPrefix(s, true): an IPv6
// (or IPv4-mapped) address or prefix with no zone.
func v6AddrOrPrefix(s string) bool {
	if p, err := netip.ParsePrefix(s); err == nil {
		return !p.Addr().Is4() && p.Addr().Zone() == ""
	}
	a, err := netip.ParseAddr(s)
	return err == nil && !a.Is4() && a.Zone() == ""
}
