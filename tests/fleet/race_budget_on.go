//go:build race

package fleet

// raceBudgetScale multiplies the fleet's fixed convergence budgets (New's
// own wait, convergeTimeout). Under the race detector on a loaded host, a
// fresh five-node fleet took up to 45.5 s to agree on its seeded hosts rows
// (310 fixtures at a load of 315-494; 111 needed more than 20 s, none stayed
// apart), against 0.31 s without it.
const raceBudgetScale = 4
