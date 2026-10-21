package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockGraph mimics the token endpoint plus channel messages, newest first.
type mockGraph struct {
	t         *testing.T
	mu        sync.Mutex
	authCalls int
	nextID    int
	msgs      []teamsMessage
	webhooks  []string
	autoReply string
}

func (m *mockGraph) handler(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
		m.authCalls++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok123","expires_in":3600}`)
		return
	}
	if r.URL.Path == "/webhook" {
		raw, _ := io.ReadAll(r.Body)
		m.webhooks = append(m.webhooks, string(raw))
		// Webhook posts land in the channel like Graph posts.
		var payload struct {
			Attachments []struct {
				Content string `json:"content"`
			} `json:"attachments"`
		}
		if err := json.Unmarshal(raw, &payload); err == nil && len(payload.Attachments) > 0 {
			var card struct {
				Body []struct {
					Text string `json:"text"`
				} `json:"body"`
			}
			if err := json.Unmarshal([]byte(payload.Attachments[0].Content), &card); err == nil && len(card.Body) > 0 {
				m.nextID++
				var msg teamsMessage
				msg.ID, msg.Type, msg.Body.Content = fmt.Sprintf("wh-%d", m.nextID), "message", card.Body[0].Text
				m.msgs = append([]teamsMessage{msg}, m.msgs...)
			}
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/messages") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPost:
		var payload struct {
			Body struct {
				Content string `json:"content"`
			} `json:"body"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &payload); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		m.nextID++
		id := fmt.Sprintf("msg-%d", m.nextID)
		var msg teamsMessage
		msg.ID, msg.Type, msg.Body.Content = id, "message", payload.Body.Content
		m.msgs = append([]teamsMessage{msg}, m.msgs...)
		if m.autoReply != "" {
			m.nextID++
			var rep teamsMessage
			rep.ID, rep.Type, rep.Body.Content = fmt.Sprintf("msg-%d", m.nextID), "message", m.autoReply
			m.msgs = append([]teamsMessage{rep}, m.msgs...)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"id":%q}`, id)
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"value": m.msgs})
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func teamsTestSetup(autoReply []byte) (*mockGraph, *httptest.Server, Config) {
	m := &mockGraph{}
	if autoReply != nil {
		m.autoReply = base64.StdEncoding.EncodeToString(autoReply)
	}
	srv := httptest.NewServer(http.HandlerFunc(m.handler))
	teamsGraphBase = srv.URL + "/v1.0"
	teamsLoginBase = srv.URL
	cfg := Config{
		Profile: "msteams", TenantID: "ten", ClientID: "cid", ClientSecret: "sec",
		TeamID: "team", ChannelID: "chan", UserAgent: "agent-test",
	}
	return m, srv, cfg
}

func restoreTeamsBases() {
	teamsGraphBase = "https://graph.microsoft.com/v1.0"
	teamsLoginBase = "https://login.microsoftonline.com"
}

func TestTeamsExchange(t *testing.T) {
	sealed := []byte(testUUID + `{"action":"checkin"}`)
	reply := []byte(testUUID + `{"action":"checkin","status":"success"}`)
	m, srv, cfg := teamsTestSetup(reply)
	defer srv.Close()
	defer restoreTeamsBases()
	tr, err := newTeamsTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := tr.exchange(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(reply) {
		t.Fatalf("reply mismatch: %q", out)
	}
	// Second exchange reuses the cached token.
	if _, err := tr.exchange(sealed); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.authCalls != 1 {
		t.Fatalf("auth calls = %d, want 1 (cached)", m.authCalls)
	}
}

func TestTeamsWebhookSend(t *testing.T) {
	sealed := []byte(testUUID + `{"action":"checkin"}`)
	reply := []byte(testUUID + `{"action":"checkin","status":"success"}`)
	m, srv, cfg := teamsTestSetup(nil)
	defer srv.Close()
	defer restoreTeamsBases()
	cfg.WebhookURL = srv.URL + "/webhook"
	tr, err := newTeamsTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Server stand-in: once our webhook post lands, append the reply.
	replied := make(chan struct{})
	go func() {
		defer close(replied)
		for i := 0; i < 2000; i++ {
			m.mu.Lock()
			n := len(m.webhooks)
			m.mu.Unlock()
			if n > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		m.mu.Lock()
		var rep teamsMessage
		rep.ID, rep.Type, rep.Body.Content = "srv-1", "message", base64.StdEncoding.EncodeToString(reply)
		m.msgs = append([]teamsMessage{rep}, m.msgs...)
		m.mu.Unlock()
	}()
	out, err := tr.exchange(sealed)
	<-replied
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(reply) {
		t.Fatalf("reply mismatch: %q", out)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.webhooks) != 1 || !strings.Contains(m.webhooks[0], "AdaptiveCard") ||
		!strings.Contains(m.webhooks[0], base64.StdEncoding.EncodeToString(sealed)) {
		t.Fatalf("bad webhook payload: %v", m.webhooks)
	}
}

func TestTeamsRequiresFields(t *testing.T) {
	if _, err := newTeamsTransport(Config{Profile: "msteams"}); err == nil {
		t.Fatal("empty teams config accepted")
	}
}
