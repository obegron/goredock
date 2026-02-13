package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandleImagesCreateStreamsProgress(t *testing.T) {
	store := &containerStore{stateDir: t.TempDir()}
	cfg := appConfig{}
	ensureCalled := false
	ensure := func(_ context.Context, ref string, stateDir string, _ *metrics, _ bool) (string, imageMeta, error) {
		ensureCalled = true
		if ref != "redis:7-alpine" {
			t.Fatalf("ensure ref = %q, want redis:7-alpine", ref)
		}
		if stateDir != store.stateDir {
			t.Fatalf("ensure stateDir = %q, want %q", stateDir, store.stateDir)
		}
		return "/tmp/rootfs", imageMeta{Digest: "sha256:abc"}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/images/create?fromImage=redis:7-alpine", nil)
	rec := httptest.NewRecorder()
	handleImagesCreate(rec, req, store, &metrics{}, cfg, ensure)

	if !ensureCalled {
		t.Fatalf("ensure was not called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"status":"Pulling from redis:7-alpine"`) {
		t.Fatalf("missing pull status line: %s", body)
	}
	if !strings.Contains(body, `"status":"Digest: sha256:abc"`) {
		t.Fatalf("missing digest status line: %s", body)
	}
	if !strings.Contains(body, `"status":"Status: Downloaded newer image for redis:7-alpine"`) {
		t.Fatalf("missing completed status line: %s", body)
	}
}

func TestHandleImagesCreateStreamsError(t *testing.T) {
	store := &containerStore{stateDir: t.TempDir()}
	cfg := appConfig{}
	ensure := func(_ context.Context, _ string, _ string, _ *metrics, _ bool) (string, imageMeta, error) {
		return "", imageMeta{}, errors.New("image pull failed: timeout")
	}

	req := httptest.NewRequest(http.MethodPost, "/images/create?fromImage=redis:7-alpine", nil)
	rec := httptest.NewRecorder()
	handleImagesCreate(rec, req, store, &metrics{}, cfg, ensure)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"error":"image pull failed: timeout"`) {
		t.Fatalf("missing error line: %s", body)
	}
	if !strings.Contains(body, `"errorDetail":{"message":"image pull failed: timeout"}`) {
		t.Fatalf("missing errorDetail line: %s", body)
	}
}

func TestHandleImagesCreateDigestTagUsesAtSeparator(t *testing.T) {
	store := &containerStore{stateDir: t.TempDir()}
	cfg := appConfig{}
	ensure := func(_ context.Context, ref string, _ string, _ *metrics, _ bool) (string, imageMeta, error) {
		if ref != "alpine@sha256:1775bebec23e1f3ce486989bfc9ff3c4e951690df84aa9f926497d82f2ffca9d" {
			t.Fatalf("ensure ref = %q", ref)
		}
		return "/tmp/rootfs", imageMeta{Digest: "sha256:abc"}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/images/create?fromImage=alpine&tag=sha256:1775bebec23e1f3ce486989bfc9ff3c4e951690df84aa9f926497d82f2ffca9d", nil)
	rec := httptest.NewRecorder()
	handleImagesCreate(rec, req, store, &metrics{}, cfg, ensure)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestImageTagLooksLikeDigest(t *testing.T) {
	tests := []struct {
		tag  string
		want bool
	}{
		{tag: "sha256:abcd0123", want: true},
		{tag: "SHA256:abcd0123", want: true},
		{tag: "latest", want: false},
		{tag: "v1.2.3", want: false},
		{tag: "sha256:not-hex", want: false},
		{tag: "", want: false},
	}
	for _, tt := range tests {
		if got := imageTagLooksLikeDigest(tt.tag); got != tt.want {
			t.Fatalf("imageTagLooksLikeDigest(%q) = %v, want %v", tt.tag, got, tt.want)
		}
	}
}

func TestHandleImageInspectFindsMirroredReference(t *testing.T) {
	stateDir := t.TempDir()
	imageDir := filepath.Join(stateDir, "images", "sha256_deadbeef")
	if err := os.MkdirAll(imageDir, 0o755); err != nil {
		t.Fatalf("mkdir image dir: %v", err)
	}
	meta := imageMeta{
		Reference:   "127.0.0.1:5001/library/alpine:latest",
		Digest:      "sha256:deadbeef",
		ContentSize: 123,
		DiskUsage:   456,
	}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(imageDir, "image.json"), data, 0o644); err != nil {
		t.Fatalf("write image metadata: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/images/testcontainers%2Fhelloworld:latest/json", nil)
	rec := httptest.NewRecorder()
	handleImageInspect(rec, req, stateDir, []imageMirrorRule{
		{FromPrefix: "testcontainers/helloworld:latest", ToPrefix: "127.0.0.1:5001/library/alpine:latest"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if payload["Id"] != "sha256:deadbeef" {
		t.Fatalf("Id = %v, want sha256:deadbeef", payload["Id"])
	}
}
