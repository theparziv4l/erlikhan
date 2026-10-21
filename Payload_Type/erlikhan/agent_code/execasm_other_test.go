//go:build !windows

package main

import "fmt"

// Test-only stub: the agent targets Windows, so off-Windows `go test`
// needs a runAssemblyInProcess. A _test.go file is ideal because the
// container builder never stages *_test.go into agent builds.
func runAssemblyInProcess(path string, argString string) (string, error) {
	return "", fmt.Errorf("execute_assembly needs Windows")
}
