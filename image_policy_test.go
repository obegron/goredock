package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
