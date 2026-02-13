package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
				Name:    "test-db",
				Image:   "alpine:3.20",
				Cmd:     []string{"echo", "hej"},
				Created: time.Now().UTC(),
				Ports:   map[int]int{5432: 32768},
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
	var payload map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("inspect payload invalid json: %v", err)
	}
	if payload["Name"] != "/test-db" {
		t.Fatalf("inspect response Name = %#v, want /test-db", payload["Name"])
	}
	if _, ok := payload["HostConfig"]; !ok {
		t.Fatalf("inspect response missing HostConfig: %s", body)
	}
	config, ok := payload["Config"].(map[string]interface{})
	if !ok {
		t.Fatalf("inspect response Config missing or wrong type: %s", body)
	}
	if _, ok := config["ExposedPorts"]; !ok {
		t.Fatalf("inspect response missing Config.ExposedPorts: %s", body)
	}
}
