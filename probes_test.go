package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeEndpoints(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{},
		execs:      map[string]*ExecInstance{},
		proxies:    map[string][]*portProxy{},
		stateDir:   t.TempDir(),
	}
	cfg := appConfig{stateDir: store.stateDir}
	probes := &probeState{}
	handler := timeoutMiddleware(apiVersionMiddleware(newRouter(store, &metrics{}, cfg, probes)))

	healthReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want %d", healthRec.Code, http.StatusOK)
	}

	readyReq := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	readyRec := httptest.NewRecorder()
	handler.ServeHTTP(readyRec, readyReq)
	if readyRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz (not ready) status = %d, want %d", readyRec.Code, http.StatusServiceUnavailable)
	}

	probes.setReady(true)
	readyRec2 := httptest.NewRecorder()
	handler.ServeHTTP(readyRec2, readyReq)
	if readyRec2.Code != http.StatusOK {
		t.Fatalf("GET /readyz (ready) status = %d, want %d", readyRec2.Code, http.StatusOK)
	}
}
