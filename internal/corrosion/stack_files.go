package corrosion

import (
	"context"

	"github.com/litevirt/litevirt/internal/compose"
)

// stackFile is a live stack's last deployed compose file.
type stackFile struct {
	name string
	file *compose.File
}

// otherStackFiles returns the deployed files of every live stack other than
// stack, in name order, for handing a row stack owns to another stack whose
// file asks for it too. A stack being deleted asks for nothing. unreadable
// names the stacks whose stored file cannot be read, which may ask for
// anything.
func otherStackFiles(ctx context.Context, c *Client, stack string) (files []stackFile, unreadable []string, err error) {
	stacks, err := ListStacks(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	for _, st := range stacks {
		if st.Name == stack || st.State == "deleting" {
			continue
		}
		f, perr := compose.ParseStored([]byte(st.ComposeYAML))
		if perr != nil || f == nil {
			unreadable = append(unreadable, st.Name)
			continue
		}
		files = append(files, stackFile{name: st.Name, file: f})
	}
	return files, unreadable, nil
}
