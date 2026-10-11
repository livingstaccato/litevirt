package auth

// Rereview 2, N5. The litevirt account name is the normalized TYPED login
// name, as on main, so no account is re-keyed on upgrade; it must name-match
// the directory's own value for the attribute it was found by; and the
// account is bound to the entry's immutable id (Principal.ExternalID), which
// the login handler enforces. These tests cover what the realm decides:
// the name match, the ambiguity refusals, and the id.

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

const (
	svcDN = "cn=svc,dc=corp,dc=example"
	base  = "ou=Users,dc=corp,dc=example"
)

func entry(dn string, attrs map[string][]string) *ldap.Entry {
	e := &ldap.Entry{DN: dn}
	for k, v := range attrs {
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: k, Values: v,
			ByteValues: func() [][]byte {
				out := make([][]byte, len(v))
				for i, s := range v {
					out[i] = []byte(s)
				}
				return out
			}()})
	}
	return e
}

func defaultFilter(name string) string {
	esc := ldap.EscapeFilter(name)
	return "(&(objectClass=person)(|(uid=" + esc + ")(sAMAccountName=" + esc + ")))"
}

func realmWith(t *testing.T, cfg LDAPConfig, entries map[string][]*ldap.Entry, pw map[string]string) *LDAPRealm {
	t.Helper()
	conn := &fakeLDAPConn{userPasswords: map[string]string{svcDN: "svc-pw"}, userEntriesMulti: entries}
	for dn, p := range pw {
		conn.userPasswords[dn] = p
	}
	cfg.ShortName, cfg.URL, cfg.BindDN, cfg.BindPassword, cfg.UserBaseDN = "corp", "ldaps://ad.example", svcDN, "svc-pw", base
	cfg.Dialer = &fakeDialer{conn: conn}
	r, err := NewLDAPRealm(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func login(r *LDAPRealm, name, pw string) (*Principal, error) {
	return r.Authenticate(context.Background(), Credentials{Username: name, Password: pw})
}

// The account name is the typed name, normalized — never another attribute's
// value — and it must name-match the directory's own value.
func TestLDAP_SubjectIsTheTypedNameAndMustNameMatch(t *testing.T) {
	alice := entry("uid=alice,"+base, map[string][]string{"uid": {"alice"}, "entryUUID": {"u-alice"}})
	r := realmWith(t, LDAPConfig{}, map[string][]*ldap.Entry{
		defaultFilter("alice"): {alice},
		defaultFilter("ALICE"): {alice}, // the directory matches case-insensitively
		defaultFilter("ａｌｉｃｅ"): {alice}, // and width-insensitively (RFC 4518)
	}, map[string]string{alice.DN: "pw"})
	for _, typed := range []string{"alice", "ALICE", " alice "} {
		p, err := login(r, typed, "pw")
		if err != nil || p.Subject != "alice" || p.ExternalID != "entryUUID:u-alice" {
			t.Fatalf("%q: %+v %v, want subject alice bound to entryUUID:u-alice", typed, p, err)
		}
	}
	// A fullwidth spelling binds as alice's entry in the directory but does
	// not name-match it: refused, never a second account.
	if p, err := login(r, "ａｌｉｃｅ", "pw"); err == nil {
		t.Fatalf("fullwidth alice authenticated as %q", p.Subject)
	}
}

// X has uid=alice and sAMAccountName=mallory; Y (the real alice) has
// sAMAccountName=alice. X logging in as mallory is the account "mallory" —
// never "alice". Typing "alice" matches both entries and is refused.
func TestLDAP_UidEqualToAnothersSAMAccountName(t *testing.T) {
	x := entry("cn=X,"+base, map[string][]string{"uid": {"alice"}, "sAMAccountName": {"mallory"}, "objectGUID": {"\x01\x02"}})
	y := entry("cn=Y,"+base, map[string][]string{"sAMAccountName": {"alice"}, "objectGUID": {"\x03\x04"}})
	r := realmWith(t, LDAPConfig{}, map[string][]*ldap.Entry{
		defaultFilter("mallory"): {x},
		defaultFilter("alice"):   {x, y},
	}, map[string]string{x.DN: "x-pw", y.DN: "y-pw"})
	p, err := login(r, "mallory", "x-pw")
	if err != nil || p.Subject != "mallory" || p.ExternalID != "objectGUID:"+hex.EncodeToString([]byte{1, 2}) {
		t.Fatalf("X as mallory: %+v %v, want the account mallory bound to X's objectGUID", p, err)
	}
	if _, err := login(r, "alice", "y-pw"); err == nil {
		t.Fatal("a name two entries carry was authenticated")
	}
}

// Two entries sharing a uid: typing it is ambiguous and refused; each still
// logs in under its own unique name, as its own account.
func TestLDAP_SharedUidIsRefusedNotMerged(t *testing.T) {
	a := entry("cn=jdoe,"+base, map[string][]string{"uid": {"jdoe"}, "sAMAccountName": {"jdoe"}, "entryUUID": {"u-a"}})
	b := entry("cn=jdoe-admin,"+base, map[string][]string{"uid": {"jdoe"}, "sAMAccountName": {"jdoe-admin"}, "entryUUID": {"u-b"}})
	r := realmWith(t, LDAPConfig{}, map[string][]*ldap.Entry{
		defaultFilter("jdoe"):       {a, b},
		defaultFilter("jdoe-admin"): {b},
	}, map[string]string{a.DN: "a-pw", b.DN: "b-pw"})
	if _, err := login(r, "jdoe", "a-pw"); err == nil {
		t.Fatal("a uid two entries share was authenticated")
	}
	p, err := login(r, "jdoe-admin", "b-pw")
	if err != nil || p.Subject != "jdoe-admin" || p.ExternalID != "entryUUID:u-b" {
		t.Fatalf("jdoe-admin: %+v %v", p, err)
	}
}

// A configured user_login_attr must be present and single-valued; no
// fall-through to the filter's attributes or the RDN.
func TestLDAP_ConfiguredLoginAttrMustBeSingleValued(t *testing.T) {
	multi := entry("uid=alice,"+base, map[string][]string{"uid": {"alice", "x2"}, "entryUUID": {"u"}})
	missing := entry("uid=bob,"+base, map[string][]string{"sAMAccountName": {"bob"}, "entryUUID": {"u2"}})
	r := realmWith(t, LDAPConfig{UserLoginAttr: "uid"}, map[string][]*ldap.Entry{
		defaultFilter("alice"): {multi},
		defaultFilter("bob"):   {missing},
	}, map[string]string{multi.DN: "pw", missing.DN: "pw"})
	if _, err := login(r, "alice", "pw"); err == nil {
		t.Fatal("a multi-valued configured login attribute was accepted")
	}
	if _, err := login(r, "bob", "pw"); err == nil {
		t.Fatal("an entry missing the configured login attribute fell through and was accepted")
	}
}

// With no immutable id the id falls back to the DN, so two entries with the
// same name in different OUs carry different ids (the binding refuses the
// second); and two at once are refused as ambiguous.
func TestLDAP_DNFallbackAndCrossOUCollision(t *testing.T) {
	staff := entry("uid=alice,ou=Staff,"+base, map[string][]string{"uid": {"alice"}})
	contr := entry("uid=alice,ou=Contractors,"+base, map[string][]string{"uid": {"alice"}})
	r := realmWith(t, LDAPConfig{}, map[string][]*ldap.Entry{defaultFilter("alice"): {staff}},
		map[string]string{staff.DN: "pw", contr.DN: "pw"})
	p, err := login(r, "alice", "pw")
	if err != nil || p.ExternalID != "dn:uid=alice,ou=staff,ou=users,dc=corp,dc=example" {
		t.Fatalf("staff alice: %+v %v, want the DN fallback id", p, err)
	}
	r2 := realmWith(t, LDAPConfig{}, map[string][]*ldap.Entry{defaultFilter("alice"): {contr}},
		map[string]string{contr.DN: "pw"})
	p2, err := login(r2, "alice", "pw")
	if err != nil || p2.ExternalID == p.ExternalID {
		t.Fatalf("contractor alice: %+v %v, want a different id from staff alice", p2, err)
	}
	r3 := realmWith(t, LDAPConfig{}, map[string][]*ldap.Entry{defaultFilter("alice"): {staff, contr}},
		map[string]string{staff.DN: "pw", contr.DN: "pw"})
	if _, err := login(r3, "alice", "pw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("two OUs' alice at once: %v, want refused", err)
	}
}
