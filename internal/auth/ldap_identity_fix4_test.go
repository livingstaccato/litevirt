package auth

import (
	"slices"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// Re-review 3, m-3: the principal carries every immutable id the entry has,
// and its DN, so an account bound by one id still matches when the directory
// starts returning another first (389 DS enabling entryUUID).
func TestLDAP_PrincipalCarriesEveryImmutableID(t *testing.T) {
	alice := entry("uid=alice,"+base, map[string][]string{
		"uid": {"alice"}, "entryUUID": {"u-1"}, "nsUniqueId": {"n-1"}})
	r := realmWith(t, LDAPConfig{}, map[string][]*ldap.Entry{defaultFilter("alice"): {alice}},
		map[string]string{alice.DN: "pw"})
	p, err := login(r, "alice", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if p.ExternalID != "entryUUID:u-1" {
		t.Errorf("ExternalID = %q, want the strongest id entryUUID:u-1", p.ExternalID)
	}
	for _, want := range []string{"entryUUID:u-1", "nsUniqueId:n-1", "dn:uid=alice,ou=users,dc=corp,dc=example"} {
		if !slices.Contains(p.ExternalIDs, want) {
			t.Errorf("ExternalIDs = %v, missing %s", p.ExternalIDs, want)
		}
	}
}
