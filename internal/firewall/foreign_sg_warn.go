package firewall

import "sync"

// warnedForeignSG remembers the (workload, group) bindings already reported as
// naming another project's security group, so each is said once.
var warnedForeignSG sync.Map
