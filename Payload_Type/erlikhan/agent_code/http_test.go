package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPExchange(t *testing.T) {
	sealed := []byte(testUUID + `{"action":"checkin"}`)
	reply := []byte(testUUID + `{"action":"checkin","status":"success"}`)
	var gotPath, gotBody, gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotPath, gotBody, gotHeader = r.URL.Path, string(raw), r.Header.Get("X-Test")
		w.Write([]byte(base64.StdEncoding.EncodeToString(reply)))
	}))
	defer srv.Close()
	tr := &Transport{client: srv.Client(), url: srv.URL + "/data", headers: map[string]string{"X-Test": "v"}}
	out, err := tr.exchange(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(reply) {
		t.Fatalf("reply mismatch: %q", out)
	}
	if gotPath != "/data" || gotBody != base64.StdEncoding.EncodeToString(sealed) || gotHeader != "v" {
		t.Fatalf("request wrong: %q %q %q", gotPath, gotBody, gotHeader)
	}
}

func TestNewTransportDispatch(t *testing.T) {
	if _, err := newTransport(Config{Profile: "smoke"}); err == nil {
		t.Fatal("unknown profile accepted")
	}
	if _, err := newTransport(Config{}); err != nil {
		t.Fatalf("empty profile must mean http: %v", err)
	}
	// Each constructor must be reachable (all fail on empty required fields).
	for _, p := range []string{"mqtt", "dns", "msteams"} {
		if _, err := newTransport(Config{Profile: p}); err == nil {
			t.Fatalf("%s accepted empty config", p)
		}
	}
}
