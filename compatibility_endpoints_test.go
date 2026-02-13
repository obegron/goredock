package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEventsEndpointReturnsEmptyArray(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{},
		execs:      map[string]*ExecInstance{},
		proxies:    map[string][]*portProxy{},
		stateDir:   t.TempDir(),
	}
	cfg := appConfig{stateDir: store.stateDir}
	handler := timeoutMiddleware(apiVersionMiddleware(newRouter(store, &metrics{}, cfg, &probeState{})))

	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /events status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); body != "[]" {
		t.Fatalf("GET /events body = %q, want []", body)
	}
}

func TestTopEndpointReturnsProcessShape(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{
			"abc123": {
				ID:      "abc123",
				Image:   "alpine:3.20",
				Cmd:     []string{"sleep", "10"},
				Created: time.Now().UTC(),
			},
		},
		execs:    map[string]*ExecInstance{},
		proxies:  map[string][]*portProxy{},
		stateDir: t.TempDir(),
	}
	cfg := appConfig{stateDir: store.stateDir}
	handler := timeoutMiddleware(apiVersionMiddleware(newRouter(store, &metrics{}, cfg, &probeState{})))

	req := httptest.NewRequest(http.MethodGet, "/containers/abc123/top", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /containers/{id}/top status = %d, want %d", rec.Code, http.StatusOK)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid top payload json: %v", err)
	}
	if _, ok := payload["Titles"]; !ok {
		t.Fatalf("top payload missing Titles: %s", rec.Body.String())
	}
	if _, ok := payload["Processes"]; !ok {
		t.Fatalf("top payload missing Processes: %s", rec.Body.String())
	}
}
