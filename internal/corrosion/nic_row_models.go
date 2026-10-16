package corrosion

import "context"

// VMNICRowModels is the model of each live vm_nics row of vmName, keyed by
// its MAC. vm_interfaces rows are not read: they have no model column.
func VMNICRowModels(ctx context.Context, c *Client, vmName string) (map[string]string, error) {
	rows, err := GetVMNICsRaw(ctx, c, "vm_nics", vmName)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		if r.DeletedAt == "" {
			out[r.MAC] = r.Model
		}
	}
	return out, nil
}
