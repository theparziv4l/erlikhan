//go:build !windows

package main

import "fmt"

// Test-only stub: the agent targets Windows, so off-Windows `go test`
// needs a runCoffInProcess. A _test.go file is ideal because the
// container builder never stages *_test.go into agent builds.
func runCoffInProcess(obj []byte, entry string, args []byte, timeoutSec int) (string, error) {
	return "", fmt.Errorf("execute_coff needs Windows")
}
