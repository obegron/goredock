package main

import "testing"

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
