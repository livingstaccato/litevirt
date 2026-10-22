package contract

// ParentLifetime records exact facts from a current parent owner. It is not a
// certified identity or evidence of originating observation.
type ParentLifetime struct {
	Kind, Alias, Realm, Birth string
}
