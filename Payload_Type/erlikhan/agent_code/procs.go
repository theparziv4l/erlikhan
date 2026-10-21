package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// ProcEntry is one listed process.
type ProcEntry struct {
	PID, PPID              int
	Name, Arch             string
	BinPath, User, CmdLine string
	IntegrityLevel         int
	StartTime              uint64
}

// listProcesses enumerates processes. Implemented per platform in
// procs_windows.go (ToolHelp snapshot) and procs_other.go (stub).

// agentArch maps the agent build to a process-browser architecture label.
func agentArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "386":
		return "x86"
	default:
		return runtime.GOARCH
	}
}

// processesPayload converts listed processes to Mythic wire entries.
func processesPayload(entries []ProcEntry) []ProcessEntry {
	out := make([]ProcessEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, ProcessEntry{
			ProcessID:       e.PID,
			ParentProcessID: e.PPID,
			Architecture:    e.Arch,
			BinPath:         e.BinPath,
			Name:            e.Name,
			User:            e.User,
			CommandLine:     e.CmdLine,
			IntegrityLevel:  e.IntegrityLevel,
			StartTime:       e.StartTime,
		})
	}
	return out
}

// psText renders a plain listing for CLI task output.
func psText(entries []ProcEntry) string {
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "%d %d %s\n", e.PID, e.PPID, e.Name)
	}
	return b.String()
}

// killProcess terminates one pid.
func killProcess(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("bad pid %d", pid)
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

func parseKillArg(arg string) (int, error) {
	pid, err := strconv.Atoi(strings.TrimSpace(arg))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("usage: kill <pid>")
	}
	return pid, nil
}
