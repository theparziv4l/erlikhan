//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// listProcesses snapshots the process table via ToolHelp32. Name, pid and
// ppid come from the snapshot; stdlib-only Go cannot query image paths,
// owners or command lines, so those stay empty here (the native C agent
// reports them).
func listProcesses() ([]ProcEntry, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snap)
	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []ProcEntry
	for err := syscall.Process32First(snap, &pe); err == nil; err = syscall.Process32Next(snap, &pe) {
		out = append(out, ProcEntry{
			PID:  int(pe.ProcessID),
			PPID: int(pe.ParentProcessID),
			Name: syscall.UTF16ToString(pe.ExeFile[:]),
			Arch: agentArch(),
		})
	}
	return out, nil
}
