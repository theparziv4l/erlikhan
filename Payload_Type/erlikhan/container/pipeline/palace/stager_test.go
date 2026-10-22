package palace

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func needGo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain needed")
	}
}

// TestBuildStager compiles a stager around a toy blob and checks the
// artifact shape. The console flag must not change that shape.
func TestBuildStager(t *testing.T) {
	needGo(t)
	for _, console := range []bool{false, true} {
		exe, err := BuildStager(t.TempDir(), []byte{0xC3}, console)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(exe)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) < 2 || raw[0] != 'M' || raw[1] != 'Z' {
			t.Fatal("stager is not a PE")
		}
	}
	if _, err := BuildStager(t.TempDir(), nil, false); err == nil {
		t.Fatal("empty blob accepted")
	}
}

// TestWineStagerRET executes a stager around a RET blob: the mapping
// and entry call work, and the process exits cleanly.
func TestWineStagerRET(t *testing.T) {
	needWine(t)
	needGo(t)
	exe, err := BuildStager(t.TempDir(), []byte{0xC3}, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wine", exe)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stager run failed: %v\n%s", err, out)
	}
}
