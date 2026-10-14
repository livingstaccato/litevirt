package corrosion

import (
	"context"
)

// StackFileWants reads, from a live stack's deployed compose YAML, whether
// it asks for the cluster default-deny and which backup repos it uses
// (compose.StoredStackWants). The data layer takes it from its caller rather
// than parsing compose files itself.
type StackFileWants func(composeYAML string) (defaultDeny bool, repos map[string]bool, err error)

// stackWants is what one other live stack's file asks for.
type stackWants struct {
	name        string
	defaultDeny bool
	repos       map[string]bool
}

// otherStackWants returns what every live stack other than stack asks for,
// in name order, for handing a row stack owns to another stack whose file
// asks for it too. A stack being deleted asks for nothing. unreadable names
// the stacks whose stored file cannot be read, which may ask for anything.
func otherStackWants(ctx context.Context, c *Client, stack string, read StackFileWants) (out []stackWants, unreadable []string, err error) {
	stacks, err := ListStacks(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	for _, st := range stacks {
		if st.Name == stack || st.State == "deleting" {
			continue
		}
		if read == nil {
			unreadable = append(unreadable, st.Name)
			continue
		}
		deny, repos, rerr := read(st.ComposeYAML)
		if rerr != nil {
			unreadable = append(unreadable, st.Name)
			continue
		}
		out = append(out, stackWants{name: st.Name, defaultDeny: deny, repos: repos})
	}
	return out, unreadable, nil
}
