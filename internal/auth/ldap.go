package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// LDAPConfig describes one LDAP/AD bind. Realm name becomes
// "ldap:<ShortName>" so role-bindings reference a specific directory.
type LDAPConfig struct {
	ShortName string

	// URL is the LDAP server URL, e.g. "ldaps://ad.corp.example:636".
	URL string

	// BindDN / BindPassword — the service account we use to search for users.
	// Anonymous bind is supported: leave both empty.
	BindDN       string
	BindPassword string

	// UserBaseDN is the subtree to search for users, e.g.
	// "ou=Users,dc=corp,dc=example".
	UserBaseDN string

	// UserFilter selects the user record. Use "%s" as the literal username
	// placeholder; we escape it before substitution. Defaults to:
	//   (&(objectClass=person)(|(uid=%s)(sAMAccountName=%s)))
	UserFilter string

	// GroupBaseDN scopes the group search; empty disables explicit group
	// search and we rely on the user record's memberOf attribute instead.
	GroupBaseDN string

	// GroupFilter is the search filter for groups the user belongs to.
	// "%s" is replaced with the user DN. Defaults to:
	//   (&(objectClass=group)(member=%s))
	GroupFilter string

	// UserLoginAttr, when set, is the one attribute the typed login name must
	// literally match (after normalization): it must be present and
	// single-valued on the entry, or the login is refused. Empty: the typed
	// name must match a value of some attribute UserFilter matches it against
	// ("(uid=%s)" → uid), or the entry DN's own RDN (rereview N5).
	UserLoginAttr string

	// Attributes — overridable so non-standard schemas can be handled.
	UserNameAttr  string // default "cn"
	UserMailAttr  string // default "mail"
	UserGroupAttr string // default "memberOf"
	GroupNameAttr string // default "cn"

	// SkipTLSVerify disables certificate validation. Use only for self-
	// signed dev directories; production deployments should ship CA certs
	// via the host trust store.
	SkipTLSVerify bool

	// Dialer lets tests inject a fake LDAP connection. Production callers
	// leave this nil — we then use ldap.DialURL.
	Dialer LDAPDialer
}

// LDAPConn is the subset of *ldap.Conn we depend on. Tests implement this
// directly without standing up a real server.
type LDAPConn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// LDAPDialer returns a connected LDAPConn. Production: ldap.DialURL.
type LDAPDialer interface {
	Dial(ctx context.Context, url string, skipTLSVerify bool) (LDAPConn, error)
}

// LDAPRealm authenticates against an LDAP/AD directory.
type LDAPRealm struct {
	cfg LDAPConfig
}

// NewLDAPRealm validates required config and returns a realm ready to
// authenticate. Connection is per-request so a single bad connection does
// not poison subsequent logins.
func NewLDAPRealm(cfg LDAPConfig) (*LDAPRealm, error) {
	if cfg.ShortName == "" {
		return nil, errors.New("ldap: ShortName required")
	}
	if cfg.URL == "" || cfg.UserBaseDN == "" {
		return nil, errors.New("ldap: URL and UserBaseDN required")
	}
	cfg.UserFilter = defaultStr(cfg.UserFilter, "(&(objectClass=person)(|(uid=%s)(sAMAccountName=%s)))")
	cfg.GroupFilter = defaultStr(cfg.GroupFilter, "(&(objectClass=group)(member=%s))")
	cfg.UserNameAttr = defaultStr(cfg.UserNameAttr, "cn")
	cfg.UserMailAttr = defaultStr(cfg.UserMailAttr, "mail")
	cfg.UserGroupAttr = defaultStr(cfg.UserGroupAttr, "memberOf")
	cfg.GroupNameAttr = defaultStr(cfg.GroupNameAttr, "cn")
	if cfg.Dialer == nil {
		cfg.Dialer = realLDAPDialer{}
	}
	// Warn loudly about transport configurations that expose the bind
	// password (search-then-bind sends it in the clear over plain LDAP). We
	// don't refuse — some clusters tunnel LDAP over an already-encrypted link
	// (stunnel/VPN) — but a misconfiguration shouldn't be silent.
	if strings.HasPrefix(strings.ToLower(cfg.URL), "ldap://") {
		slog.Warn("LDAP realm uses plaintext ldap:// — bind credentials are sent unencrypted; prefer ldaps:// or StartTLS",
			"realm", "ldap:"+cfg.ShortName, "url", cfg.URL)
	}
	if cfg.SkipTLSVerify {
		slog.Warn("LDAP realm has SkipTLSVerify=true — server certificate is NOT validated, exposing logins to MITM",
			"realm", "ldap:"+cfg.ShortName)
	}
	return &LDAPRealm{cfg: cfg}, nil
}

// Name returns "ldap:<ShortName>".
func (r *LDAPRealm) Name() string { return "ldap:" + r.cfg.ShortName }

// Authenticate performs a search-then-bind:
//  1. Bind as service account (or anonymous).
//  2. Search for the user; require exactly one result.
//  3. Bind as the user with the supplied password — this is the actual
//     credential check.
//  4. Read groups from `memberOf` and/or a follow-up search.
//
// Returns ErrInvalidCredentials on any failed bind or zero search hits;
// ErrRealmUnavailable on dial/search transport failures.
func (r *LDAPRealm) Authenticate(ctx context.Context, creds Credentials) (*Principal, error) {
	if creds.Username == "" || creds.Password == "" {
		return nil, ErrInvalidCredentials
	}
	conn, err := r.cfg.Dialer.Dial(ctx, r.cfg.URL, r.cfg.SkipTLSVerify)
	if err != nil {
		return nil, fmt.Errorf("%w: dial: %v", ErrRealmUnavailable, err)
	}
	defer conn.Close()

	if r.cfg.BindDN != "" {
		if err := conn.Bind(r.cfg.BindDN, r.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("%w: service bind: %v", ErrRealmUnavailable, err)
		}
	}

	// The account name is the normalized TYPED login name, as it always was
	// (no account is re-keyed on upgrade). Three things keep two directory
	// entries from becoming one account (rereview N5): the search must
	// return exactly one entry; the typed name must name-match that entry's
	// own login value (below); and the login handler binds the account to the
	// entry's immutable id (Principal.ExternalID) and refuses any other.
	username := strings.TrimSpace(creds.Username)
	filter := substituteUser(r.cfg.UserFilter, username)
	req := ldap.NewSearchRequest(
		r.cfg.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 0, false, // SizeLimit=2 → fast-fail on duplicates
		filter,
		append(append([]string{"dn", r.cfg.UserNameAttr, r.cfg.UserMailAttr, r.cfg.UserGroupAttr}, r.loginAttrs()...),
			immutableIDAttrs...),
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("%w: user search: %v", ErrRealmUnavailable, err)
	}
	if len(res.Entries) == 0 {
		return nil, ErrInvalidCredentials
	}
	if len(res.Entries) > 1 {
		// Filter is too loose — refuse rather than guess.
		return nil, fmt.Errorf("%w: ambiguous user filter (%d results)", ErrInvalidCredentials, len(res.Entries))
	}
	entry := res.Entries[0]

	// Now actually verify the password by binding as the user.
	if err := conn.Bind(entry.DN, creds.Password); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Group memberships are keyed by each group's full normalized DN, never
	// by a short name: a cn is unique only within its container, so keying
	// by it would let anyone who can create a group of that name anywhere
	// in the directory take on its bindings. memberOf lists every group in
	// the directory; with group_base_dn set, only groups under it count.
	groups := entry.GetAttributeValues(r.cfg.UserGroupAttr)
	if r.cfg.GroupBaseDN != "" {
		extra, gErr := r.searchGroups(conn, entry.DN)
		if gErr != nil {
			// Group-search failures are surfaced as ErrRealmUnavailable
			// rather than silently dropped — a sysadmin investigating a
			// permissions miss needs to see the LDAP error, not get a
			// successful login with mysteriously-empty groups.
			return nil, fmt.Errorf("%w: group search: %v", ErrRealmUnavailable, gErr)
		}
		groups = append(groups, extra...)
	}
	groups = normalizeGroupDNs(groups, r.cfg.GroupBaseDN)

	// Name match: the directory matches width, case and compatibility
	// variants of a name (RFC 4518: `ａｌｉｃｅ` binds as alice's entry); the
	// typed name must equal the entry's OWN login value after litevirt's
	// normalization, so a variant is refused rather than becoming a second,
	// never-disabled account (rereview N4).
	if err := r.nameMatches(entry, username); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCredentials, err)
	}
	p := &Principal{
		Subject:     corrosion.NormalizeUsername(username),
		ExternalID:  entryImmutableID(entry),
		ExternalIDs: entryImmutableIDs(entry),
		Realm:       r.Name(),
		Email:       firstAttr(entry, r.cfg.UserMailAttr),
		Name:        firstAttr(entry, r.cfg.UserNameAttr),
		Groups:      groups,
		Claims: map[string]string{
			"dn": entry.DN,
		},
	}
	return p, nil
}

// filterAttrRe finds each "(attr=%s)" in a user filter.
var filterAttrRe = regexp.MustCompile(`\(([A-Za-z][A-Za-z0-9-]*)=%s\)`)

// loginAttrs is the attributes a typed name is matched against: the
// configured UserLoginAttr alone when set, else each attribute UserFilter
// matches the typed name against ("(uid=%s)" → uid), in filter order.
func (r *LDAPRealm) loginAttrs() []string {
	if r.cfg.UserLoginAttr != "" {
		return []string{r.cfg.UserLoginAttr}
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range filterAttrRe.FindAllStringSubmatch(r.cfg.UserFilter, -1) {
		if a := m[1]; !seen[strings.ToLower(a)] {
			seen[strings.ToLower(a)] = true
			out = append(out, a)
		}
	}
	return out
}

// nameMatches checks the typed name against the entry's own login value.
//
// With user_login_attr configured, that attribute must be present and
// single-valued, and its value must normalize to the typed name — no
// fall-through to any other attribute.
//
// Without it, some value of an attribute the filter matched the name against
// (or the DN's own RDN when its attribute is one of those) must normalize to
// the typed name. Only literal values count: a directory's width, case and
// compatibility folding is not litevirt's.
func (r *LDAPRealm) nameMatches(e *ldap.Entry, typed string) error {
	want := corrosion.NormalizeUsername(typed)
	if r.cfg.UserLoginAttr != "" {
		vals := e.GetAttributeValues(r.cfg.UserLoginAttr)
		if len(vals) != 1 {
			return fmt.Errorf("entry %q has %d values of user_login_attr %q; exactly one is required",
				e.DN, len(vals), r.cfg.UserLoginAttr)
		}
		if corrosion.NormalizeUsername(vals[0]) != want {
			return fmt.Errorf("the name does not match entry %q's %s", e.DN, r.cfg.UserLoginAttr)
		}
		return nil
	}
	attrs := r.loginAttrs()
	if len(attrs) == 0 {
		return fmt.Errorf("user_filter matches the name against no (attr=%%s) term; set user_login_attr")
	}
	for _, a := range attrs {
		for _, v := range e.GetAttributeValues(a) {
			if corrosion.NormalizeUsername(v) == want {
				return nil
			}
		}
	}
	if dn, err := ldap.ParseDN(e.DN); err == nil && len(dn.RDNs) > 0 {
		for _, av := range dn.RDNs[0].Attributes {
			for _, a := range attrs {
				if strings.EqualFold(av.Type, a) && corrosion.NormalizeUsername(av.Value) == want {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("the name is not literally the login value of entry %q", e.DN)
}

// immutableIDAttrs are the directory attributes that identify an entry for
// its whole life, in the order they are tried: entryUUID (RFC 4530; OpenLDAP
// and most servers), objectGUID (Active Directory), nsUniqueId (389/RHDS).
var immutableIDAttrs = []string{"entryUUID", "objectGUID", "nsUniqueId"}

// entryImmutableID is the identity an account is bound to: the first
// immutable id attribute the server returned ("entryUUID:<v>",
// "objectGUID:<hex>", "nsUniqueId:<v>"), else the entry's DN, lower-cased
// ("dn:<dn>"). A DN changes when an entry is renamed or moved, so a directory
// without an immutable id rebinds on those (docs/auth.md).
func entryImmutableID(e *ldap.Entry) string {
	for _, a := range immutableIDAttrs {
		raw := e.GetRawAttributeValue(a)
		if len(raw) == 0 {
			continue
		}
		if a == "objectGUID" {
			return a + ":" + hex.EncodeToString(raw)
		}
		return a + ":" + string(raw)
	}
	return "dn:" + strings.ToLower(e.DN)
}

// entryImmutableIDs is every id entryImmutableID could have returned for the
// entry, in the same order, and its DN form last (re-review 3, m-3). An
// account bound to any of them matches the entry: the binding was made under
// one of them when the directory returned a different set (389 DS enabling
// its entryUUID plugin, an ACL change), so the entry is the same entry. The
// login handler compares the BOUND id against this list, so a DN only ever
// matches a binding that was itself made by DN — it never stands in for an
// immutable id.
func entryImmutableIDs(e *ldap.Entry) []string {
	var out []string
	for _, a := range immutableIDAttrs {
		raw := e.GetRawAttributeValue(a)
		if len(raw) == 0 {
			continue
		}
		if a == "objectGUID" {
			out = append(out, a+":"+hex.EncodeToString(raw))
			continue
		}
		out = append(out, a+":"+string(raw))
	}
	return append(out, "dn:"+strings.ToLower(e.DN))
}

// SyncGroups is a no-op — group memberships are pulled at login time.
func (r *LDAPRealm) SyncGroups(ctx context.Context) error { return nil }

func (r *LDAPRealm) searchGroups(conn LDAPConn, userDN string) ([]string, error) {
	filter := strings.ReplaceAll(r.cfg.GroupFilter, "%s", ldap.EscapeFilter(userDN))
	req := ldap.NewSearchRequest(
		r.cfg.GroupBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		if e.DN != "" {
			out = append(out, e.DN)
		}
	}
	return out, nil
}

func substituteUser(filter, username string) string {
	esc := ldap.EscapeFilter(username)
	return strings.ReplaceAll(filter, "%s", esc)
}

// normalizeGroupDNs keys each group by its full DN in one canonical spelling
// (NormalizeDN), so `CN=Ops,OU=Groups,DC=corp` and `cn=ops, ou=groups,dc=corp`
// are one group and `cn=ops,ou=contractors,dc=corp` is another. A value that
// is not a DN is dropped: a bare name cannot say which container's group it
// is. With base set, only groups at or under it are kept.
func normalizeGroupDNs(groups []string, base string) []string {
	var baseDN *ldap.DN
	if base != "" {
		if d, err := ldap.ParseDN(base); err == nil {
			baseDN = d
		} else {
			return nil // an unparsable base scopes to nothing rather than everything
		}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		d, err := ldap.ParseDN(g)
		if err != nil || len(d.RDNs) == 0 {
			continue
		}
		if baseDN != nil && !baseDN.EqualFold(d) && !baseDN.AncestorOfFold(d) {
			continue
		}
		n := canonicalDN(d)
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// NormalizeDN is dn in canonical form: attribute types and values lower-cased,
// each RDN's attributes in a fixed order, RFC 4514 escaping, no spaces around
// separators. ok is false when dn does not parse.
func NormalizeDN(dn string) (string, bool) {
	d, err := ldap.ParseDN(dn)
	if err != nil || len(d.RDNs) == 0 {
		return "", false
	}
	return canonicalDN(d), true
}

func canonicalDN(d *ldap.DN) string {
	rdns := make([]string, 0, len(d.RDNs))
	for _, r := range d.RDNs {
		avas := make([]string, 0, len(r.Attributes))
		for _, a := range r.Attributes {
			avas = append(avas, strings.ToLower(a.Type)+"="+ldap.EscapeDN(strings.ToLower(a.Value)))
		}
		sort.Strings(avas)
		rdns = append(rdns, strings.Join(avas, "+"))
	}
	return strings.Join(rdns, ",")
}

func firstAttr(e *ldap.Entry, attr string) string {
	v := e.GetAttributeValue(attr)
	return v
}

// realLDAPDialer is the production dialer using github.com/go-ldap/ldap/v3.
type realLDAPDialer struct{}

func (realLDAPDialer) Dial(ctx context.Context, url string, skipTLSVerify bool) (LDAPConn, error) {
	opts := []ldap.DialOpt{}
	if skipTLSVerify {
		opts = append(opts, ldap.DialWithTLSConfig(insecureTLS()))
	}
	conn, err := ldap.DialURL(url, opts...)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
