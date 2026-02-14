package main

import "testing"

func TestApplyRedisRuntimeCompatAddsBind(t *testing.T) {
	got := applyRedisRuntimeCompat([]string{"redis-server"}, "127.0.0.2")
	want := []string{"redis-server", "--bind", "127.0.0.2"}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg[%d] = %q, want %q (%v)", i, got[i], want[i], got)
		}
	}
}

func TestApplyRedisRuntimeCompatKeepsExistingBind(t *testing.T) {
	in := []string{"redis-server", "--bind", "127.0.0.9"}
	got := applyRedisRuntimeCompat(in, "127.0.0.2")
	if len(got) != len(in) {
		t.Fatalf("len(got) = %d, want %d (%v)", len(got), len(in), got)
	}
	for i := range in {
		if got[i] != in[i] {
			t.Fatalf("arg[%d] = %q, want %q (%v)", i, got[i], in[i], got)
		}
	}
}

func TestAllocateLoopbackIPSkipsUsed(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{
			"a": {LoopbackIP: "127.0.0.2"},
			"b": {LoopbackIP: "127.0.0.3"},
		},
	}
	ip, err := store.allocateLoopbackIP()
	if err != nil {
		t.Fatalf("allocateLoopbackIP error: %v", err)
	}
	if ip != "127.0.0.4" {
		t.Fatalf("allocateLoopbackIP = %q, want %q", ip, "127.0.0.4")
	}
}
