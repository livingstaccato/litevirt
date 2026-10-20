package compose

// StoredStackWants reads, from a stack's deployed compose YAML, what it asks
// for of the rows a stack can own and hand on: the cluster default-deny, and
// the backup repos it defines or its workloads back up to.
func StoredStackWants(composeYAML string) (defaultDeny bool, repos map[string]bool, err error) {
	f, err := ParseStored([]byte(composeYAML))
	if err != nil {
		return false, nil, err
	}
	repos = map[string]bool{}
	for name, d := range f.BackupRepos {
		if d.Path != "" {
			repos[name] = true
		}
	}
	for _, m := range []map[string]VMDef{f.VMs, f.Workloads} {
		for _, w := range m {
			if w.Backup != nil && w.Backup.Repo != "" {
				repos[w.Backup.Repo] = true
			}
		}
	}
	return f.FirewallDefaults != nil && f.FirewallDefaults.DefaultDeny, repos, nil
}

// DeclaresFirewall reports whether the file declares a firewall: security
// groups, ip sets or a firewall block. Each is global firewall state, so
// writing, replacing or removing it needs sg.write at the cluster root.
func (f *File) DeclaresFirewall() bool {
	return f != nil && (len(f.SecurityGroups) > 0 || len(f.IPSets) > 0 || f.FirewallDefaults != nil)
}
