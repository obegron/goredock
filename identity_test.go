package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureSyntheticUserIdentityNumericUID(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "group"), []byte("root:x:0:\n"), 0o644); err != nil {
		t.Fatalf("write group: %v", err)
	}

	if err := ensureSyntheticUserIdentity(rootfs, "65532"); err != nil {
		t.Fatalf("ensureSyntheticUserIdentity: %v", err)
	}
	passwdData, err := os.ReadFile(filepath.Join(rootfs, "etc", "passwd"))
	if err != nil {
		t.Fatalf("read passwd: %v", err)
	}
	if !strings.Contains(string(passwdData), ":65532:65532:") {
		t.Fatalf("passwd missing synthetic uid/gid entry: %s", string(passwdData))
	}
	groupData, err := os.ReadFile(filepath.Join(rootfs, "etc", "group"))
	if err != nil {
		t.Fatalf("read group: %v", err)
	}
	if !strings.Contains(string(groupData), ":65532:") {
		t.Fatalf("group missing synthetic gid entry: %s", string(groupData))
	}
}

func TestEnsureSyntheticUserIdentityIdempotent(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "passwd"), []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "group"), []byte("root:x:0:\n"), 0o644); err != nil {
		t.Fatalf("write group: %v", err)
	}

	if err := ensureSyntheticUserIdentity(rootfs, "65532:65532"); err != nil {
		t.Fatalf("first ensureSyntheticUserIdentity: %v", err)
	}
	if err := ensureSyntheticUserIdentity(rootfs, "65532:65532"); err != nil {
		t.Fatalf("second ensureSyntheticUserIdentity: %v", err)
	}

	passwdData, err := os.ReadFile(filepath.Join(rootfs, "etc", "passwd"))
	if err != nil {
		t.Fatalf("read passwd: %v", err)
	}
	if strings.Count(string(passwdData), "sidewhale-65532:x:65532:65532:") != 1 {
		t.Fatalf("expected one synthetic passwd entry, got: %s", string(passwdData))
	}
	groupData, err := os.ReadFile(filepath.Join(rootfs, "etc", "group"))
	if err != nil {
		t.Fatalf("read group: %v", err)
	}
	if strings.Count(string(groupData), "sidewhale-65532:x:65532:") != 1 {
		t.Fatalf("expected one synthetic group entry, got: %s", string(groupData))
	}
}

func TestResolveProotIdentityDefaultsToRoot(t *testing.T) {
	rootfs := t.TempDir()
	if got, ok := resolveProotIdentity(rootfs, ""); !ok || got != "0:0" {
		t.Fatalf("resolveProotIdentity(empty) = (%q,%v), want (%q,%v)", got, ok, "0:0", true)
	}
}

func TestResolveProotIdentityNumericUIDUsesPasswdGID(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	passwd := "app:x:65532:1234:app:/tmp:/sbin/nologin\n"
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "passwd"), []byte(passwd), 0o644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}
	if got, ok := resolveProotIdentity(rootfs, "65532"); !ok || got != "65532:1234" {
		t.Fatalf("resolveProotIdentity(65532) = (%q,%v), want (%q,%v)", got, ok, "65532:1234", true)
	}
}

func TestResolveProotIdentityNamedUserAndGroup(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	passwd := "app:x:1001:1002:app:/tmp:/sbin/nologin\n"
	group := "staff:x:1003:\n"
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "passwd"), []byte(passwd), 0o644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "group"), []byte(group), 0o644); err != nil {
		t.Fatalf("write group: %v", err)
	}
	if got, ok := resolveProotIdentity(rootfs, "app:staff"); !ok || got != "1001:1003" {
		t.Fatalf("resolveProotIdentity(app:staff) = (%q,%v), want (%q,%v)", got, ok, "1001:1003", true)
	}
}

func TestEnsureSyntheticUserIdentityHonorsExplicitGID(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	if err := ensureSyntheticUserIdentity(rootfs, "65532:1234"); err != nil {
		t.Fatalf("ensureSyntheticUserIdentity: %v", err)
	}
	passwdData, err := os.ReadFile(filepath.Join(rootfs, "etc", "passwd"))
	if err != nil {
		t.Fatalf("read passwd: %v", err)
	}
	if !strings.Contains(string(passwdData), ":65532:1234:") {
		t.Fatalf("passwd missing uid/gid mapping 65532:1234: %s", string(passwdData))
	}
	groupData, err := os.ReadFile(filepath.Join(rootfs, "etc", "group"))
	if err != nil {
		t.Fatalf("read group: %v", err)
	}
	if !strings.Contains(string(groupData), "sidewhale-1234:x:1234:") {
		t.Fatalf("group missing explicit gid entry: %s", string(groupData))
	}
}
