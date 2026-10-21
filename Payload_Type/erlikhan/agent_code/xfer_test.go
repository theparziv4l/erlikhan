package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDownloadMythic records download chunks and hands out a file id.
type fakeDownloadMythic struct {
	posts    []Response
	fileID   string
	failAt   int
	received []byte
}

func (f *fakeDownloadMythic) post(responses []Response) ([]PostReply, error) {
	f.posts = append(f.posts, responses...)
	r := responses[0]
	if r.Download == nil {
		return []PostReply{{TaskID: r.TaskID, Status: "success"}}, nil
	}
	if r.Download.ChunkNum == nil {
		// Registration-only (empty file).
		f.fileID = "file-1"
		return []PostReply{{TaskID: r.TaskID, Status: "success", FileID: f.fileID}}, nil
	}
	chunk := *r.Download.ChunkNum
	if f.failAt > 0 && chunk >= f.failAt {
		return []PostReply{{TaskID: r.TaskID, Status: "error", Error: "boom"}}, nil
	}
	if chunk == 1 {
		f.fileID = "file-1"
		if r.Download.TotalChunks == nil || r.Download.FullPath == nil || r.Download.FileName == nil {
			f.failAt = -1
		}
	} else if r.Download.FileID == nil || *r.Download.FileID != f.fileID {
		f.failAt = -1
	}
	if r.Download.ChunkData != nil {
		raw, err := base64.StdEncoding.DecodeString(*r.Download.ChunkData)
		if err != nil {
			f.failAt = -1
		}
		f.received = append(f.received, raw...)
	}
	return []PostReply{{TaskID: r.TaskID, Status: "success", FileID: f.fileID, ChunkNum: chunk}}, nil
}

func TestDownloadRoundtrip(t *testing.T) {
	content := []byte(strings.Repeat("0123456789abcdef", 500)) // 8000 bytes
	path := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &fakeDownloadMythic{}
	out, err := downloadToMythic("t1", path, 3000, fake.post)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "8000 bytes in 3 chunks") {
		t.Fatalf("summary: %q", out)
	}
	if string(fake.received) != string(content) {
		t.Fatal("chunks do not reassemble to the file")
	}
	if len(fake.posts) != 3 {
		t.Fatalf("%d posts, want 3", len(fake.posts))
	}
	for i, p := range fake.posts {
		if *p.Download.ChunkNum != i+1 {
			t.Fatalf("chunk numbering off at post %d", i)
		}
		if p.Completed != (i == 2) {
			t.Fatalf("post %d completed=%v", i, p.Completed)
		}
	}
	if fake.failAt == -1 {
		t.Fatal("registration/chunk protocol violation")
	}
}

func TestDownloadEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.bin")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &fakeDownloadMythic{}
	out, err := downloadToMythic("t1", path, 3000, fake.post)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "0 bytes") || len(fake.posts) != 1 {
		t.Fatalf("empty download: %q posts=%d", out, len(fake.posts))
	}
	if *fake.posts[0].Download.TotalChunks != 0 {
		t.Fatal("empty file must register total_chunks 0")
	}
}

func TestDownloadErrors(t *testing.T) {
	fake := &fakeDownloadMythic{}
	if _, err := downloadToMythic("t1", filepath.Join(t.TempDir(), "missing"), 100, fake.post); err == nil {
		t.Fatal("missing file should fail")
	}
	if _, err := downloadToMythic("t1", t.TempDir(), 100, fake.post); err == nil {
		t.Fatal("directory should fail")
	}
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, []byte("12345678"), 0o644); err != nil {
		t.Fatal(err)
	}
	failing := &fakeDownloadMythic{failAt: 2}
	if _, err := downloadToMythic("t1", path, 4, failing.post); err == nil {
		t.Fatal("mythic error mid-transfer should fail")
	}
}

// fakeUploadMythic serves content in 1-based chunks.
type fakeUploadMythic struct {
	content []byte
	wantID  string
	nums    []int
}

func (f *fakeUploadMythic) post(responses []Response) ([]PostReply, error) {
	r := responses[0]
	if r.Upload == nil {
		return []PostReply{{TaskID: r.TaskID, Status: "success"}}, nil
	}
	if r.Upload.FileID == nil || *r.Upload.FileID != f.wantID {
		return []PostReply{{TaskID: r.TaskID, Status: "error", Error: "bad file id"}}, nil
	}
	size := 512000
	if r.Upload.ChunkSize != nil {
		size = *r.Upload.ChunkSize
	}
	total := (len(f.content) + size - 1) / size
	start := (r.Upload.ChunkNum - 1) * size
	if r.Upload.ChunkNum < 1 || start >= len(f.content) {
		return []PostReply{{TaskID: r.TaskID, Status: "error", Error: "bad chunk num"}}, nil
	}
	end := start + size
	if end > len(f.content) {
		end = len(f.content)
	}
	f.nums = append(f.nums, r.Upload.ChunkNum)
	return []PostReply{{
		TaskID: r.TaskID, Status: "success", FileID: f.wantID,
		ChunkNum: r.Upload.ChunkNum, TotalChunks: total,
		ChunkData: base64.StdEncoding.EncodeToString(f.content[start:end]),
	}}, nil
}

func TestUploadRoundtrip(t *testing.T) {
	content := []byte(strings.Repeat("zyxwvuts", 1000)) // 8000 bytes
	fake := &fakeUploadMythic{content: content, wantID: "uuid-9"}
	dst := filepath.Join(t.TempDir(), "sub", "out.bin")
	out, err := uploadFromMythic("t2", "uuid-9", dst, 3000, fake.post)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "8000 bytes in 3 chunks") {
		t.Fatalf("summary: %q", out)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatal("written file differs")
	}
	for i, n := range fake.nums {
		if n != i+1 {
			t.Fatalf("chunk requests not sequential 1-based: %v", fake.nums)
		}
	}
}

func TestUploadErrors(t *testing.T) {
	fake := &fakeUploadMythic{content: []byte("x"), wantID: "uuid-9"}
	if _, err := uploadFromMythic("t2", "", "x", 100, fake.post); err == nil {
		t.Fatal("missing file id should fail")
	}
	if _, err := uploadFromMythic("t2", "uuid-9", "", 100, fake.post); err == nil {
		t.Fatal("missing remote path should fail")
	}
	if _, err := uploadFromMythic("t2", "wrong", filepath.Join(t.TempDir(), "x"), 100, fake.post); err == nil {
		t.Fatal("wrong file id should fail")
	}
}

func TestReplyFor(t *testing.T) {
	r, err := replyFor([]PostReply{{TaskID: "a", FileID: "f"}}, "a")
	if err != nil || r.FileID != "f" {
		t.Fatalf("reply: %+v %v", r, err)
	}
	if _, err := replyFor([]PostReply{{TaskID: "a", Status: "error", Error: "no"}}, "a"); err == nil {
		t.Fatal("error reply should fail")
	}
	if _, err := replyFor([]PostReply{{TaskID: "b"}}, "a"); err == nil {
		t.Fatal("missing task should fail")
	}
}

func TestChunkSizeFor(t *testing.T) {
	if chunkSizeFor("http") != 512000 || chunkSizeFor("mqtt") != 512000 {
		t.Fatal("default chunk size wrong")
	}
	if chunkSizeFor("dns") != 8192 || chunkSizeFor("msteams") != 8192 {
		t.Fatal("small chunk size wrong")
	}
}

func TestListDirShape(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	text, fb, err := listDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "a.txt") || fb == nil || fb.Files == nil || len(*fb.Files) != 2 {
		t.Fatalf("listing: %q %+v", text, fb)
	}
	if fb.Name == "" || fb.ParentPath == "" || fb.Success == nil || !*fb.Success {
		t.Fatalf("parent entry: %+v", fb)
	}
	for _, c := range *fb.Files {
		if c.Name == "a.txt" && (c.Size != 5 || !c.IsFile) {
			t.Fatalf("child a.txt: %+v", c)
		}
		if c.Name == "sub" && c.IsFile {
			t.Fatalf("child sub: %+v", c)
		}
	}
	if _, _, err := listDir(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing dir should fail")
	}
}

func TestRemoveAndMakeDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b")
	f := filepath.Join(nested, "f.txt")
	if out, err := makeDir(nested); err != nil || !strings.Contains(out, "created") {
		t.Fatalf("mkdir: %q %v", out, err)
	}
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	removed, out, err := removePath(filepath.Join(dir, "a"))
	if err != nil || !strings.Contains(out, "removed") {
		t.Fatalf("rm: %q %v", out, err)
	}
	if len(removed) != 1 || removed[0].Path == "" {
		t.Fatalf("removed entries: %+v", removed)
	}
	if _, err := os.Stat(filepath.Join(dir, "a")); !os.IsNotExist(err) {
		t.Fatal("tree should be gone")
	}
	if _, _, err := removePath(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing path should fail")
	}
	if _, err := makeDir(""); err == nil {
		t.Fatal("empty mkdir should fail")
	}
}

func TestDispatchDownloadViaFake(t *testing.T) {
	content := []byte(strings.Repeat("0123456789abcdef", 200))
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &fakeDownloadMythic{}
	a := &Agent{post: fake.post}
	resp, _ := a.dispatch(Task{Command: "download", Parameters: `{"arguments":` + quoteForTest(path) + `}`, ID: "t9"})
	if resp.Status != "success" {
		t.Fatalf("download: %+v", resp)
	}
	if string(fake.received) != string(content) {
		t.Fatal("chunks do not reassemble")
	}
	if resp.Artifacts == nil || (*resp.Artifacts)[0].BaseArtifact != "File Download" {
		t.Fatalf("artifacts: %+v", resp.Artifacts)
	}
}

func TestDispatchUploadViaFake(t *testing.T) {
	content := []byte(strings.Repeat("zyxwvuts", 200))
	fake := &fakeUploadMythic{content: content, wantID: "uuid-7"}
	dst := filepath.Join(t.TempDir(), "out.bin")
	a := &Agent{post: fake.post}
	resp, _ := a.dispatch(Task{
		Command:    "upload",
		Parameters: `{"file": "uuid-7", "remote_path": ` + quoteForTest(dst) + `}`,
		ID:         "t10",
	})
	if resp.Status != "success" {
		t.Fatalf("upload: %+v", resp)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != string(content) {
		t.Fatal("written file differs")
	}
	if resp.Artifacts == nil || (*resp.Artifacts)[0].BaseArtifact != "File Upload" {
		t.Fatalf("artifacts: %+v", resp.Artifacts)
	}
}

func TestTaskParam(t *testing.T) {
	if got := taskParam(`{"file": "u", "remote_path": "r"}`, "file"); got != "u" {
		t.Fatalf("file = %q", got)
	}
	if got := taskParam(`{"file": "u"}`, "remote_path"); got != "" {
		t.Fatalf("missing = %q", got)
	}
	if got := taskParam(`not json`, "file"); got != "" {
		t.Fatalf("bad json = %q", got)
	}
}
