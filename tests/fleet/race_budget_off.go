//go:build !race

package fleet

// raceBudgetScale is 1 without the race detector: see race_budget_on.go.
const raceBudgetScale = 1
