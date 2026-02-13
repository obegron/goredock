package main

import (
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	got := resolveCommandInRootfs(rootfs, nil, []string{"/bin/ryuk"})
	if len(got) != 1 || got[0] != "/app/ryuk" {
		t.Fatalf("resolveCommandInRootfs returned %v, want [/app/ryuk]", got)
	}
}

func TestResolveCommandInRootfsRewritesEnvShebang(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "usr", "local", "bin"), 0o755); err != nil {
		t.Fatalf("mkdir script dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(rootfs, "usr", "bin"), 0o755); err != nil {
		t.Fatalf("mkdir usr/bin: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(rootfs, "bin"), 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	if err := os.Symlink("/bin/busybox", filepath.Join(rootfs, "usr", "bin", "env")); err != nil {
		t.Fatalf("symlink env: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "bin", "bash"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write bash: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(rootfs, "usr", "local", "bin", "docker-entrypoint.sh"),
		[]byte("#!/usr/bin/env bash\nset -e\n"),
		0o755,
	); err != nil {
		t.Fatalf("write entrypoint: %v", err)
	}

	got := resolveCommandInRootfs(rootfs, nil, []string{"/usr/local/bin/docker-entrypoint.sh", "postgres"})
	want := []string{"/bin/bash", "/usr/local/bin/docker-entrypoint.sh", "postgres"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("resolveCommandInRootfs returned %v, want %v", got, want)
	}
}

func TestRewriteKnownEntrypointCompatMSSQL(t *testing.T) {
	got := rewriteKnownEntrypointCompat([]string{"/bin/bash", "/opt/mssql/bin/launch_sqlservr.sh", "/opt/mssql/bin/sqlservr"})
	want := []string{"/opt/mssql/bin/sqlservr"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("rewriteKnownEntrypointCompat returned %v, want %v", got, want)
	}
}

func TestNormalizeContainerHostname(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: " db_1 ", want: "db-1"},
		{in: "alpha.beta", want: "alpha.beta"},
		{in: "!!!", want: ""},
	}
	for _, tt := range tests {
		if got := normalizeContainerHostname(tt.in); got != tt.want {
			t.Fatalf("normalizeContainerHostname(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestWriteContainerIdentityFiles(t *testing.T) {
	rootfs := t.TempDir()
	if err := writeContainerIdentityFiles(rootfs, "tc-host"); err != nil {
		t.Fatalf("writeContainerIdentityFiles error: %v", err)
	}
	hostnameData, err := os.ReadFile(filepath.Join(rootfs, "etc", "hostname"))
	if err != nil {
		t.Fatalf("read hostname: %v", err)
	}
	if string(hostnameData) != "tc-host\n" {
		t.Fatalf("hostname content = %q, want %q", string(hostnameData), "tc-host\n")
	}
	hostsData, err := os.ReadFile(filepath.Join(rootfs, "etc", "hosts"))
	if err != nil {
		t.Fatalf("read hosts: %v", err)
	}
	hosts := string(hostsData)
	if !strings.Contains(hosts, "127.0.1.1\ttc-host") {
		t.Fatalf("hosts missing hostname mapping: %q", hosts)
	}
	if err := writeContainerIdentityFiles(rootfs, "tc-host"); err != nil {
		t.Fatalf("writeContainerIdentityFiles second call error: %v", err)
	}
	hostsData2, err := os.ReadFile(filepath.Join(rootfs, "etc", "hosts"))
	if err != nil {
		t.Fatalf("read hosts after second call: %v", err)
	}
	if strings.Count(string(hostsData2), "tc-host") != 1 {
		t.Fatalf("expected single hostname entry, got: %q", string(hostsData2))
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

func TestIsRyukImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{image: "testcontainers/ryuk:0.8.1", want: true},
		{image: "docker.io/testcontainers/ryuk:latest", want: true},
		{image: "postgres:16-alpine", want: false},
	}
	for _, tt := range tests {
		if got := isRyukImage(tt.image); got != tt.want {
			t.Fatalf("isRyukImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestDockerHostForInnerClients(t *testing.T) {
	tests := []struct {
		unixPath string
		host     string
		want     string
	}{
		{unixPath: "/tmp/sidewhale/docker.sock", host: "127.0.0.1:8080", want: "unix:///tmp/sidewhale/docker.sock"},
		{host: "127.0.0.1:8080", want: "tcp://127.0.0.1:8080"},
		{host: "", want: "tcp://127.0.0.1:23750"},
		{host: "tcp://10.0.0.5:2375", want: "tcp://10.0.0.5:2375"},
	}
	for _, tt := range tests {
		if got := dockerHostForInnerClients(tt.unixPath, tt.host); got != tt.want {
			t.Fatalf("dockerHostForInnerClients(%q,%q) = %q, want %q", tt.unixPath, tt.host, got, tt.want)
		}
	}
}

func TestRequestTimeoutFor(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
		want   time.Duration
	}{
		{name: "default", method: http.MethodGet, target: "/version", want: 30 * time.Second},
		{name: "images create", method: http.MethodPost, target: "/images/create?fromImage=redis", want: 10 * time.Minute},
		{name: "logs follow", method: http.MethodGet, target: "/containers/abc/logs?follow=true", want: 0},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.target, nil)
		if got := requestTimeoutFor(req); got != tt.want {
			t.Fatalf("%s: requestTimeoutFor(%s %s) = %s, want %s", tt.name, tt.method, tt.target, got, tt.want)
		}
	}
}

func TestMapArchiveDestinationPath(t *testing.T) {
	rootfs := filepath.Join("/tmp", "rootfs")
	c := &Container{Rootfs: rootfs}

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "rootfs tmp file redirected",
			in:   filepath.Join(rootfs, "tmp", "testcontainers_start.sh"),
			want: filepath.Join("/tmp", "tmp", "testcontainers_start.sh"),
		},
		{
			name: "rootfs tmp dir redirected",
			in:   filepath.Join(rootfs, "tmp"),
			want: filepath.Join("/tmp", "tmp"),
		},
		{
			name: "non tmp path unchanged",
			in:   filepath.Join(rootfs, "etc", "hosts"),
			want: filepath.Join(rootfs, "etc", "hosts"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapArchiveDestinationPath(c, tt.in)
			if got != tt.want {
				t.Fatalf("mapArchiveDestinationPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestResolveUnixSocketPath(t *testing.T) {
	stateDir := "/tmp/sw"
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: "/tmp/sw/docker.sock"},
		{in: "-", want: ""},
		{in: "off", want: ""},
		{in: "/run/user/1000/sw.sock", want: "/run/user/1000/sw.sock"},
	}
	for _, tt := range tests {
		if got := resolveUnixSocketPath(tt.in, stateDir); got != tt.want {
			t.Fatalf("resolveUnixSocketPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDockerSocketBindsForContainer(t *testing.T) {
	rootfs := t.TempDir()
	c := &Container{Rootfs: rootfs}
	binds, err := dockerSocketBindsForContainer(c, "/tmp/sidewhale/docker.sock")
	if err != nil {
		t.Fatalf("dockerSocketBindsForContainer error: %v", err)
	}
	if len(binds) != 3 {
		t.Fatalf("bind count = %d, want 3", len(binds))
	}
	if binds[0] != "/tmp/sidewhale/docker.sock:/tmp/sidewhale/docker.sock" {
		t.Fatalf("unexpected bind[0]: %q", binds[0])
	}
	if binds[1] != "/tmp/sidewhale/docker.sock:/var/run/docker.sock" {
		t.Fatalf("unexpected bind[1]: %q", binds[1])
	}
	if binds[2] != "/tmp/sidewhale/docker.sock:/run/docker.sock" {
		t.Fatalf("unexpected bind[2]: %q", binds[2])
	}
}

func TestUnixSocketPathFromContainerEnv(t *testing.T) {
	env := []string{"A=B", "DOCKER_HOST=unix:///tmp/sidewhale/docker.sock"}
	if got := unixSocketPathFromContainerEnv(env); got != "/tmp/sidewhale/docker.sock" {
		t.Fatalf("unixSocketPathFromContainerEnv = %q, want %q", got, "/tmp/sidewhale/docker.sock")
	}
}
