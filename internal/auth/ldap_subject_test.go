package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// TestLDAPRealm_SubjectIsTheDirectorysValue (rereview N4): directories match
// width, case and space variants of a name (RFC 4518 string preparation), so
// the subject must be the entry's own value, not what was typed. A fullwidth
// or NBSP-padded spelling of alice binds as alice's entry and must come back
// as "alice".
func TestLDAPRealm_SubjectIsTheDirectorysValue(t *testing.T) {
	userDN := "uid=alice,ou=Users,dc=corp,dc=example"
	for _, typed := range []string{"ａｌｉｃｅ", "alice ", "ALICE", "Alice"} {
		entry := makeUserEntry(userDN, "Alice Example", "alice@example.test", nil)
		entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: "uid", Values: []string{"alice"}})
		sent := strings.TrimSpace(typed) // what the realm searches with
		filter := "(&(objectClass=person)(|(uid=" + ldap.EscapeFilter(sent) + ")(sAMAccountName=" + ldap.EscapeFilter(sent) + ")))"
		conn := &fakeLDAPConn{
			userPasswords: map[string]string{"cn=svc,dc=corp,dc=example": "svc-pw", userDN: "alice-pw"},
			userEntries:   map[string]*ldap.Entry{filter: entry},
		}
		realm, err := NewLDAPRealm(LDAPConfig{
			ShortName: "corp", URL: "ldaps://ad.example", BindDN: "cn=svc,dc=corp,dc=example",
			BindPassword: "svc-pw", UserBaseDN: "ou=Users,dc=corp,dc=example", Dialer: &fakeDialer{conn: conn},
		})
		if err != nil {
			t.Fatal(err)
		}
		p, err := realm.Authenticate(context.Background(), Credentials{Username: typed, Password: "alice-pw"})
		if err != nil {
			t.Fatalf("%q: Authenticate: %v", typed, err)
		}
		if p.Subject != "alice" {
			t.Errorf("typed %q: subject %q, want the directory's own %q", typed, p.Subject, "alice")
		}
	}
}

// TestLDAPRealm_NoLoginAttributeRefuses: an entry with no login attribute
// value (neither the configured one, the filter's, nor the DN's RDN) is
// refused rather than mapped to whatever was typed.
func TestLDAPRealm_NoLoginAttributeRefuses(t *testing.T) {
	userDN := "cn=Alice Example,ou=Users,dc=corp,dc=example"
	entry := makeUserEntry(userDN, "Alice Example", "alice@example.test", nil)
	conn := &fakeLDAPConn{
		userPasswords: map[string]string{"cn=svc,dc=corp,dc=example": "svc-pw", userDN: "alice-pw"},
		userEntries: map[string]*ldap.Entry{
			"(&(objectClass=person)(|(uid=alice)(sAMAccountName=alice)))": entry,
		},
	}
	realm, err := NewLDAPRealm(LDAPConfig{
		ShortName: "corp", URL: "ldaps://ad.example", BindDN: "cn=svc,dc=corp,dc=example",
		BindPassword: "svc-pw", UserBaseDN: "ou=Users,dc=corp,dc=example", Dialer: &fakeDialer{conn: conn},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p, err := realm.Authenticate(context.Background(), Credentials{Username: "alice", Password: "alice-pw"}); err == nil {
		t.Fatalf("an entry with no login attribute authenticated as %q", p.Subject)
	}
}
