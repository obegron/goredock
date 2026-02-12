package main

import (
	"encoding/binary"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"
	"testing"
)

func TestRewriteVersionedPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantPath string
		wantOK   bool
	}{
		{name: "versioned containers", input: "/v1.53/containers/json", wantPath: "/containers/json", wantOK: true},
		{name: "versioned ping", input: "/v1.41/_ping", wantPath: "/_ping", wantOK: true},
		{name: "unversioned path", input: "/version", wantPath: "", wantOK: false},
		{name: "invalid version text", input: "/v1.x/version", wantPath: "", wantOK: false},
		{name: "missing trailing path", input: "/v1.53", wantPath: "", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotOK := rewriteVersionedPath(tt.input)
			if gotPath != tt.wantPath || gotOK != tt.wantOK {
				t.Fatalf("rewriteVersionedPath(%q) = (%q, %v), want (%q, %v)", tt.input, gotPath, gotOK, tt.wantPath, tt.wantOK)
			}
		})
	}
}

func TestIsAPIVersion(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{input: "1.53", want: true},
		{input: "10.0", want: true},
		{input: "1", want: false},
		{input: "a.b", want: false},
		{input: "1.2.3", want: false},
		{input: "1.", want: false},
	}

	for _, tt := range tests {
		if got := isAPIVersion(tt.input); got != tt.want {
			t.Fatalf("isAPIVersion(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsImageAllowed(t *testing.T) {
	prefixes := []string{"postgres", "docker.io/library/redis"}
	tests := []struct {
		image string
		want  bool
	}{
		{image: "postgres:16", want: true},
		{image: "redis:7", want: true},
		{image: "docker.io/library/redis:7", want: true},
		{image: "ghcr.io/acme/postgres:1", want: false},
	}
	for _, tt := range tests {
		if got := isImageAllowed(tt.image, prefixes); got != tt.want {
			t.Fatalf("isImageAllowed(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestLoadAllowedImagePrefixes(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("allowed_images:\n  - redis\nimages:\n  - postgres\n"), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	got, err := loadAllowedImagePrefixes("ghcr.io/acme,", policyPath)
	if err != nil {
		t.Fatalf("loadAllowedImagePrefixes error: %v", err)
	}
	want := map[string]bool{
		"ghcr.io/acme": true,
		"redis":        true,
		"postgres":     true,
	}
	if len(got) != len(want) {
		t.Fatalf("prefix count = %d, want %d (%v)", len(got), len(want), got)
	}
	for _, p := range got {
		if !want[p] {
			t.Fatalf("unexpected prefix %q in %v", p, got)
		}
	}
}

func TestRequireUnprivilegedRuntime(t *testing.T) {
	if err := requireUnprivilegedRuntime(1000); err != nil {
		t.Fatalf("requireUnprivilegedRuntime(1000) returned unexpected error: %v", err)
	}
	if err := requireUnprivilegedRuntime(0); err == nil {
		t.Fatalf("requireUnprivilegedRuntime(0) expected error, got nil")
	}
}

func TestContainerLookupByNameAndShortID(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{
			"f1513654ce811a41bfe0292e": {
				ID:      "f1513654ce811a41bfe0292e",
				Name:    "t1",
				Image:   "alpine:3.20",
				Created: time.Now().UTC(),
			},
		},
	}

	if c, ok := store.get("t1"); !ok || c.ID != "f1513654ce811a41bfe0292e" {
		t.Fatalf("lookup by name failed: ok=%v c=%+v", ok, c)
	}
	if c, ok := store.get("/t1"); !ok || c.ID != "f1513654ce811a41bfe0292e" {
		t.Fatalf("lookup by slash-name failed: ok=%v c=%+v", ok, c)
	}
	if c, ok := store.get("f1513654"); !ok || c.ID != "f1513654ce811a41bfe0292e" {
		t.Fatalf("lookup by short id failed: ok=%v c=%+v", ok, c)
	}
}

func TestContainerDisplayName(t *testing.T) {
	withName := &Container{ID: "abc", Name: "db"}
	if got := containerDisplayName(withName); got != "/db" {
		t.Fatalf("containerDisplayName(withName) = %q, want %q", got, "/db")
	}
	withoutName := &Container{ID: "abc"}
	if got := containerDisplayName(withoutName); got != "/abc" {
		t.Fatalf("containerDisplayName(withoutName) = %q, want %q", got, "/abc")
	}
}

func TestToDockerPortSummaries(t *testing.T) {
	got := toDockerPortSummaries(map[int]int{5432: 32780})
	if len(got) != 1 {
		t.Fatalf("expected one port summary, got %d", len(got))
	}
	entry := got[0]
	if entry["PrivatePort"] != 5432 || entry["PublicPort"] != 32780 || entry["Type"] != "tcp" {
		t.Fatalf("unexpected port summary: %#v", entry)
	}
}

func TestFrameDockerRawStream(t *testing.T) {
	payload := []byte("hej\n")
	framed := frameDockerRawStream(1, payload)
	if len(framed) != 8+len(payload) {
		t.Fatalf("framed length = %d, want %d", len(framed), 8+len(payload))
	}
	if framed[0] != 1 {
		t.Fatalf("stream byte = %d, want 1", framed[0])
	}
	size := binary.BigEndian.Uint32(framed[4:8])
	if int(size) != len(payload) {
		t.Fatalf("size header = %d, want %d", size, len(payload))
	}
	if string(framed[8:]) != string(payload) {
		t.Fatalf("payload = %q, want %q", framed[8:], payload)
	}
}

func TestRewriteImageReference(t *testing.T) {
	rules := []imageMirrorRule{
		{FromPrefix: "docker.io/library/", ToPrefix: "registry.internal/library/"},
		{FromPrefix: "ghcr.io/", ToPrefix: "registry.internal/ghcr/"},
	}
	tests := []struct {
		in   string
		want string
	}{
		{in: "docker.io/library/postgres:16", want: "registry.internal/library/postgres:16"},
		{in: "postgres:16", want: "registry.internal/library/postgres:16"},
		{in: "ghcr.io/acme/api:1", want: "registry.internal/ghcr/acme/api:1"},
		{in: "quay.io/org/app:1", want: "quay.io/org/app:1"},
	}
	for _, tt := range tests {
		if got := rewriteImageReference(tt.in, rules); got != tt.want {
			t.Fatalf("rewriteImageReference(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLoadImageMirrorRules(t *testing.T) {
	dir := t.TempDir()
	mirrorPath := filepath.Join(dir, "mirrors.yaml")
	content := "image_mirrors:\n  - from: docker.io/library/\n    to: registry.internal/library/\n"
	if err := os.WriteFile(mirrorPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write mirror file: %v", err)
	}
	got, err := loadImageMirrorRules("ghcr.io/=registry.internal/ghcr/", mirrorPath)
	if err != nil {
		t.Fatalf("loadImageMirrorRules error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("mirror rule count = %d, want 2 (%v)", len(got), got)
	}
}

func TestListContainersIncludesCommand(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{
			"abc123": {
				ID:      "abc123",
				Image:   "alpine:3.20",
				Cmd:     []string{"echo", "hej"},
				Created: time.Now().UTC(),
			},
		},
	}
	list := store.listContainers()
	if len(list) != 1 {
		t.Fatalf("expected one container, got %d", len(list))
	}
	if list[0]["Command"] != "echo hej" {
		t.Fatalf("unexpected command field: %#v", list[0]["Command"])
	}
}

func TestParseMemTotal(t *testing.T) {
	data := []byte("MemTotal:       12345 kB\nMemFree:        12 kB\n")
	got := parseMemTotal(data)
	want := int64(12345 * 1024)
	if got != want {
		t.Fatalf("parseMemTotal = %d, want %d", got, want)
	}
}

func TestResolveCommandInRootfs(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "app"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "app", "ryuk"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := resolveCommandInRootfs(rootfs, []string{"/bin/ryuk"})
	if len(got) != 1 || got[0] != "/app/ryuk" {
		t.Fatalf("resolveCommandInRootfs returned %v, want [/app/ryuk]", got)
	}
}

func TestHandleJSONIncludesPausedState(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{
			"abc123": {
				ID:      "abc123",
				Image:   "alpine:3.20",
				Cmd:     []string{"echo", "hej"},
				Created: time.Now().UTC(),
			},
		},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.local", nil)
	handleJSON(rr, req, store, "abc123")
	body := rr.Body.String()
	if !strings.Contains(body, "\"Paused\":false") {
		t.Fatalf("inspect response missing Paused=false: %s", body)
	}
}

func TestNormalizeLayerPath(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{in: "/bin/ryuk", want: "bin/ryuk", ok: true},
		{in: "usr/local/bin/tool", want: "usr/local/bin/tool", ok: true},
		{in: "../../etc/passwd", want: "", ok: false},
	}
	for _, tt := range tests {
		got, ok := normalizeLayerPath(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("normalizeLayerPath(%q) = (%q,%v), want (%q,%v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}
