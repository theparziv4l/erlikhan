//go:build !windows

package main

import "fmt"

// Test-only stub: uptime off Windows reads /proc/uptime, but the symbol
// must resolve for `go test`. Never staged into builds (*_test.go).
func windowsTickCount() (uint64, error) {
	return 0, fmt.Errorf("uptime needs Windows tick count")
}
