package main

import "testing"

func TestApplyImageCompatAddsOracleHostname(t *testing.T) {
	env := applyImageCompat(nil, "db-host", "oracle/database:21", "oracle/database:21", "", "")
	if !envHasKey(env, "ORACLE_HOSTNAME") {
		t.Fatalf("expected ORACLE_HOSTNAME to be set")
	}
}

func TestApplyImageCompatSetsRyukDockerHost(t *testing.T) {
	env := applyImageCompat(nil, "tc", "testcontainers/ryuk:0.8.1", "testcontainers/ryuk:0.8.1", "/tmp/sidewhale/docker.sock", "127.0.0.1:23750")
	found := false
	for _, e := range env {
		if e == "DOCKER_HOST=unix:///tmp/sidewhale/docker.sock" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected DOCKER_HOST unix socket entry in env: %v", env)
	}
}

func TestApplyImageCompatKafkaTokenDedup(t *testing.T) {
	initial := []string{"KAFKA_OPTS=-Xmx256m -Dzookeeper.admin.enableServer=false"}
	env := applyImageCompat(initial, "kafka", "confluentinc/cp-kafka:7.6.1", "confluentinc/cp-kafka:7.6.1", "", "")
	val := ""
	for _, e := range env {
		if k, v := splitEnv(e); k == "KAFKA_OPTS" {
			val = v
			break
		}
	}
	if val == "" {
		t.Fatalf("expected KAFKA_OPTS in env")
	}
	if val != "-Xmx256m -Dzookeeper.admin.enableServer=false" {
		t.Fatalf("expected KAFKA_OPTS unchanged, got %q", val)
	}
}
