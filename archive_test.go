package main

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePathUnderRejectsEscape(t *testing.T) {
	base := t.TempDir()
	if _, err := resolvePathUnder(base, "../etc/passwd"); err == nil {
		t.Fatalf("resolvePathUnder should reject escaping path")
	}
	got, err := resolvePathUnder(base, "var/lib/data")
	if err != nil {
		t.Fatalf("resolvePathUnder valid path error: %v", err)
	}
	want := filepath.Join(base, "var", "lib", "data")
	if got != want {
		t.Fatalf("resolvePathUnder valid path = %q, want %q", got, want)
	}
}

func TestUntarToDirSkipsTraversalEntries(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	if err := tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0o644, Size: int64(len("bad"))}); err != nil {
		t.Fatalf("write escape header: %v", err)
	}
	if _, err := io.WriteString(tw, "bad"); err != nil {
		t.Fatalf("write escape body: %v", err)
	}

	if err := tw.WriteHeader(&tar.Header{Name: "ok/hello.txt", Mode: 0o644, Size: int64(len("good"))}); err != nil {
		t.Fatalf("write ok header: %v", err)
	}
	if _, err := io.WriteString(tw, "good"); err != nil {
		t.Fatalf("write ok body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}

	dst := t.TempDir()
	top, err := untarToDir(bytes.NewReader(buf.Bytes()), dst)
	if err != nil {
		t.Fatalf("untarToDir error: %v", err)
	}
	if len(top) != 1 || top[0] != "ok" {
		t.Fatalf("untarToDir top dirs = %v, want [ok]", top)
	}

	if _, err := os.Stat(filepath.Join(dst, "escape.txt")); err == nil {
		t.Fatalf("unexpected escape file extracted")
	}
	content, err := os.ReadFile(filepath.Join(dst, "ok", "hello.txt"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(content) != "good" {
		t.Fatalf("extracted content = %q, want %q", string(content), "good")
	}
}
