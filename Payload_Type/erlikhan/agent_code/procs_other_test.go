//go:build !windows

package main

import "fmt"

// Test-only stub: the agent always targets Windows, so off-Windows `go
// test` needs a listProcesses. A _test.go file is ideal because the
// container builder never stages *_test.go into agent builds (and its
// file-list `go build` would ignore build tags on a normal source file).
func listProcesses() ([]ProcEntry, error) {
	return nil, fmt.Errorf("ps needs Windows")
}
