package agentfunctions

import "testing"

func TestCallbackSummary(t *testing.T) {
	if got := callbackSummary("http", 11); got != "erlikhan/http · 11 commands" {
		t.Fatalf("summary: %q", got)
	}
	if got := callbackSummary("", 0); got != "erlikhan/? · 0 commands" {
		t.Fatalf("empty: %q", got)
	}
}

func TestCallbackSleep(t *testing.T) {
	if got := callbackSleep(map[string]any{"callback_interval": float64(10), "callback_jitter": float64(23)}); got != "10s ±23%" {
		t.Fatalf("numbers: %q", got)
	}
	if got := callbackSleep(map[string]any{"callback_interval": "60", "callback_jitter": "10"}); got != "60s ±10%" {
		t.Fatalf("strings: %q", got)
	}
	if got := callbackSleep(map[string]any{}); got != "" {
		t.Fatalf("missing: %q", got)
	}
	if got := callbackSleep(nil); got != "" {
		t.Fatalf("nil: %q", got)
	}
}
