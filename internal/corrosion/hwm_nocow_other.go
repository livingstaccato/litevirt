//go:build !linux

package corrosion

// setNoCOW is a no-op off Linux; see hwm_nocow_linux.go.
func setNoCOW(hwmFile) {}
