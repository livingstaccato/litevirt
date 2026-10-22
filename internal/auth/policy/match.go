// Package policy contains the pure matching rules shared by the cached RBAC
// engine and authorization performed against one database transaction.
package policy

import "strings"

const OwnerManage = "automation.owner.manage"

func CanonicalPath(p string) string {
	if p == "" {
		return "/"
	}
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	if p[0] != '/' {
		p = "/" + p
	}
	return p
}

func PathPrefixOf(prefix, path string) bool {
	prefix, path = CanonicalPath(prefix), CanonicalPath(path)
	return prefix == "/" || strings.HasPrefix(path, prefix) && (len(path) == len(prefix) || path[len(prefix)] == '/')
}

func BindingApplies(bound, path string, propagate bool) bool {
	if propagate {
		return PathPrefixOf(bound, path)
	}
	return CanonicalPath(bound) == CanonicalPath(path)
}

func VerbMatches(grants []string, verb string) bool {
	for _, g := range grants {
		if g == "*" || g == verb {
			return true
		}
		if strings.HasSuffix(g, ".*") && !strings.HasPrefix(g, "*") && strings.HasPrefix(verb, g[:len(g)-2]+".") {
			return true
		}
		// Preserve the current ctroot namespace's explicit-grant boundary:
		// "*.exec" must not confer host-root container execution.
		if strings.HasPrefix(g, "*.") && !strings.HasSuffix(g, ".*") && !strings.HasPrefix(verb, "ctroot.") && strings.HasSuffix(verb, g[1:]) {
			return true
		}
	}
	return false
}
