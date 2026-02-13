package main

import "testing"

func TestStopAllRunningMarksContainersStopped(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{
			"running": {ID: "running", Running: true, Pid: 0},
			"idle":    {ID: "idle", Running: false, Pid: 0},
		},
		execs:    map[string]*ExecInstance{},
		proxies:  map[string][]*portProxy{},
		stateDir: t.TempDir(),
	}

	stopped := store.stopAllRunning(0)
	if stopped != 1 {
		t.Fatalf("stopAllRunning() stopped = %d, want %d", stopped, 1)
	}
	if store.containers["running"].Running {
		t.Fatalf("running container still marked running")
	}
	if store.containers["idle"].Running {
		t.Fatalf("idle container changed unexpectedly")
	}
}
