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

func TestApplyImageCompatAddsZookeeperJavaFlags(t *testing.T) {
	env := applyImageCompat(nil, "zk", "library/zookeeper:3.8.0", "library/zookeeper:3.8.0", "", "")
	jvmFlags := ""
	javaToolOptions := ""
	for _, e := range env {
		k, v := splitEnv(e)
		if k == "JVMFLAGS" {
			jvmFlags = v
		}
		if k == "JAVA_TOOL_OPTIONS" {
			javaToolOptions = v
		}
	}
	if jvmFlags == "" || javaToolOptions == "" {
		t.Fatalf("expected both JVMFLAGS and JAVA_TOOL_OPTIONS, got %v", env)
	}
	if jvmFlags != "-XX:-UseContainerSupport" {
		t.Fatalf("expected JVMFLAGS token, got %q", jvmFlags)
	}
	if javaToolOptions != "-XX:-UseContainerSupport" {
		t.Fatalf("expected JAVA_TOOL_OPTIONS token, got %q", javaToolOptions)
	}
}

func TestApplyImageCompatZookeeperTokenDedup(t *testing.T) {
	initial := []string{
		"JVMFLAGS=-Xmx256m -XX:-UseContainerSupport",
		"JAVA_TOOL_OPTIONS=-Dfoo=bar -XX:-UseContainerSupport",
	}
	env := applyImageCompat(initial, "zk", "confluentinc/cp-zookeeper:6.2.1", "confluentinc/cp-zookeeper:6.2.1", "", "")
	jvmFlags := ""
	javaToolOptions := ""
	for _, e := range env {
		k, v := splitEnv(e)
		if k == "JVMFLAGS" {
			jvmFlags = v
		}
		if k == "JAVA_TOOL_OPTIONS" {
			javaToolOptions = v
		}
	}
	if jvmFlags != "-Xmx256m -XX:-UseContainerSupport" {
		t.Fatalf("unexpected JVMFLAGS %q", jvmFlags)
	}
	if javaToolOptions != "-Dfoo=bar -XX:-UseContainerSupport" {
		t.Fatalf("unexpected JAVA_TOOL_OPTIONS %q", javaToolOptions)
	}
}
