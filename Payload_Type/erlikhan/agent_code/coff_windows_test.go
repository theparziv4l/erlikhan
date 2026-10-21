//go:build windows

package main

// Windows-only loader tests. Test-only; never linked into the agent.
//
// Run under wine (or Windows):
//
//	cd agent_code && GOOS=windows go test -c -o coffwin.test.exe . &&
//	wine coffwin.test.exe -test.run 'TestWindowsCoff|TestWindowsAsm' -test.v
//
// The BOF test executes the embedded fixture through the real loader
// (map, relocate, resolve Beacon/Win32 imports, run on a worker thread);
// the assembly test covers the CLR failure path with a non-assembly file
// (wine and Windows alike fail, naming the clr stage).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// coffFixtureArgs packs i32 42 plus "hi" the way the container would:
// u32LE total, raw LE int, LE-length-prefixed NUL-terminated string.
func coffFixtureArgs() []byte {
	return []byte{
		11, 0, 0, 0,
		42, 0, 0, 0,
		3, 0, 0, 0, 'h', 'i', 0,
	}
}

func TestWindowsCoffFixture(t *testing.T) {
	out, err := runCoffInProcess(bofFixture, "go", coffFixtureArgs(), 30)
	if err != nil {
		t.Fatal(err)
	}
	if out != "n=42 z=hi tail=7 end" {
		t.Fatalf("bof output = %q", out)
	}
}

func TestWindowsCoffBadEntry(t *testing.T) {
	if _, err := runCoffInProcess(bofFixture, "missing", coffFixtureArgs(), 5); err == nil {
		t.Fatal("missing entrypoint should fail")
	}
}

func TestWindowsAsmFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-asm.exe")
	if err := os.WriteFile(path, []byte("not-an-assembly"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := runAssemblyInProcess(path, "--ignored")
	if err == nil || !strings.Contains(err.Error(), "clr:") {
		t.Fatalf("non-assembly should fail at a clr stage, got %v", err)
	}
}
