package palace

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func needWine(t *testing.T) {
	t.Helper()
	needMingw(t)
	if _, err := exec.LookPath("wine"); err != nil {
		t.Skip("wine needed")
	}
}

// buildHarness compiles a testdata harness once per test.
func buildHarness(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "harness.exe")
	cmd := exec.Command("x86_64-w64-mingw32-gcc", "-O2", "-o", exe, filepath.Join("testdata", src))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("harness %s: %v\n%s", src, err, out)
	}
	return exe
}

func runWine(t *testing.T, exe, blob string, timeout time.Duration) string {
	t.Helper()
	// Capture to a file, not a pipe: the host-inject path leaves an
	// orphaned suspended notepad holding any inherited pipe open,
	// which would wedge CombinedOutput past the context deadline.
	logPath := filepath.Join(t.TempDir(), "wine.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wine", exe, blob)
	cmd.Stdout, cmd.Stderr = f, f
	runErr := cmd.Run()
	f.Close()
	out, _ := os.ReadFile(logPath)
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("wine run timed out after %s:\n%s", timeout, out)
	}
	if runErr != nil {
		t.Fatalf("wine run failed: %v\n%s", runErr, out)
	}
	return string(out)
}

// TestWineResolver runs the PEB/ROR13 resolver as a normal EXE and
// checks every API resolves into loaded-module space. It guards the
// addressing both blob modes depend on, without the blob around it.
func TestWineResolver(t *testing.T) {
	needWine(t)
	dir := t.TempDir()
	exe := filepath.Join(dir, "pebcheck.exe")
	cmd := exec.Command("x86_64-w64-mingw32-gcc", "-O2", "-I", "src",
		"-o", exe, filepath.Join("testdata", "pebcheck.c"), filepath.Join("src", "services.c"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pebcheck build: %v\n%s", err, out)
	}
	got := runWine(t, exe, "unused", 120*time.Second)
	if !strings.Contains(got, "RESOLVE_OK") {
		t.Fatalf("resolver failed:\n%s", got)
	}
	lazy := map[string]bool{
		// Hash defined but not eagerly resolved: unused
		// (NtOpenProcess), hook target names (LoadLibraryW,
		// ExitThread), or resolved on demand by cfg.c.
		"NtOpenProcess": true, "LoadLibraryW": true,
		"ExitThread": true, "SetProcessValidCallTargets": true,
	}
	for _, name := range APINames {
		if lazy[name] {
			continue
		}
		if !strings.Contains(got, name) {
			t.Errorf("no resolution line for %s", name)
		}
	}
}

// TestWineSelfRET executes the real blob under wine across the safe
// option set: PEB walk, ROR13, decrypt, RX, thread, join, PICO,
// cleanup. A crash or hang fails the test.
func TestWineSelfRET(t *testing.T) {
	needWine(t)
	harness := buildHarness(t, "harness.c")
	ret := []byte{0xC3}
	cases := map[string]func(*Options){
		"defaults":  func(o *Options) {},
		"no-ror13":  func(o *Options) { o.ROR13 = false },
		"rwx":       func(o *Options) { o.NoRWX = false },
		"cfg":       func(o *Options) { o.CFG = true },
		"pico-none": func(o *Options) { o.PICO = "none" },
		"no-xor":    func(o *Options) { o.XOR = false },
		"hooks":     func(o *Options) { o.Hooks = true },
		"spoof":     func(o *Options) { o.Spoof = true },
		"trio": func(o *Options) {
			o.Hooks, o.SleepMask, o.Spoof = true, true, true
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			out, o := linkReal(t, ret, mutate)
			blob := filepath.Join(o.ObjDir, "palace.bin")
			if err := os.WriteFile(blob, out, 0o644); err != nil {
				t.Fatal(err)
			}
			got := runWine(t, harness, blob, 120*time.Second)
			if !strings.Contains(got, "GO_RETURNED") {
				t.Fatalf("harness output missing GO_RETURNED:\n%s", got)
			}
		})
	}
}

// TestWineHostInject runs the sacrificial-host path: no preferred
// host exists under wine, so the loader spawns suspended notepad,
// injects the RET shellcode remotely, and exits cleanly.
func TestWineHostInject(t *testing.T) {
	needWine(t)
	harness := buildHarness(t, "harness.c")
	out, o := linkReal(t, []byte{0xC3}, func(o *Options) { o.Inject = "host" })
	blob := filepath.Join(o.ObjDir, "palace.bin")
	if err := os.WriteFile(blob, out, 0o644); err != nil {
		t.Fatal(err)
	}
	got := runWine(t, harness, blob, 180*time.Second)
	if !strings.Contains(got, "GO_RETURNED") {
		t.Fatalf("harness output missing GO_RETURNED:\n%s", got)
	}
}

// TestWineMaskLoop forces the sleep-mask path: a busy-loop payload
// that outlives the short test join timeout, so the loader must
// suspend, mask, sleep, unmask and resume at least once. The
// PALACE_TEST_COUNT build returns the round count in EAX.
func TestWineMaskLoop(t *testing.T) {
	needWine(t)
	harness := buildHarness(t, "harness_count.c")
	// mov ecx,0x08000000; pause; loop $-4; ret (~134M iters).
	busy := []byte{0xB9, 0x00, 0x00, 0x00, 0x08, 0xF3, 0x90, 0xE2, 0xFC, 0xC3}
	out, o := linkReal(t, busy, func(o *Options) {
		o.SleepMask = true
		o.ExtraDefs = []string{
			"-DPALACE_TEST_COUNT",
			"-DPALACE_JOIN_TIMEOUT_MS=100",
			"-DPALACE_MASK_SLEEP_MS=100",
		}
	})
	blob := filepath.Join(o.ObjDir, "palace.bin")
	if err := os.WriteFile(blob, out, 0o644); err != nil {
		t.Fatal(err)
	}
	got := runWine(t, harness, blob, 300*time.Second)
	var rounds int
	if _, err := fmt.Sscanf(got[strings.Index(got, "ROUNDS="):], "ROUNDS=%d", &rounds); err != nil {
		t.Fatalf("no ROUNDS count in output:\n%s", got)
	}
	if rounds < 1 {
		t.Fatalf("mask loop never engaged (rounds=%d)", rounds)
	}
	t.Logf("mask rounds: %d", rounds)
}
