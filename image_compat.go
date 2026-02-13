package main

import "strconv"

func applyImageCompat(env []string, hostname, resolvedImage, requestedImage, unixSocketPath, requestHost string) []string {
	if !envHasKey(env, "HOSTNAME") && hostname != "" {
		env = append(env, "HOSTNAME="+hostname)
	}
	if isOracleImage(resolvedImage) || isOracleImage(requestedImage) {
		if !envHasKey(env, "ORACLE_HOSTNAME") {
			env = append(env, "ORACLE_HOSTNAME="+hostname)
		}
	}
	if isRabbitMQImage(resolvedImage) || isRabbitMQImage(requestedImage) {
		if !envHasKey(env, "RABBITMQ_NODENAME") {
			env = append(env, "RABBITMQ_NODENAME=rabbit@"+hostname)
		}
		if !envHasKey(env, "ERL_EPMD_PORT") && isTCPPortInUse(4369) {
			if epmdPort, epmdErr := allocatePort(); epmdErr == nil {
				env = append(env, "ERL_EPMD_PORT="+strconv.Itoa(epmdPort))
			}
		}
		if !envHasKey(env, "RABBITMQ_DIST_PORT") && isTCPPortInUse(25672) {
			if distPort, distErr := allocatePort(); distErr == nil {
				env = append(env, "RABBITMQ_DIST_PORT="+strconv.Itoa(distPort))
			}
		}
	}
	if isConfluentKafkaImage(resolvedImage) || isConfluentKafkaImage(requestedImage) {
		if !envHasKey(env, "ZOOKEEPER_ADMIN_ENABLE_SERVER") {
			env = append(env, "ZOOKEEPER_ADMIN_ENABLE_SERVER=false")
		}
		env = ensureEnvContainsToken(env, "KAFKA_OPTS", "-Dzookeeper.admin.enableServer=false")
	}
	if isRyukImage(resolvedImage) || isRyukImage(requestedImage) {
		env = mergeEnv(env, []string{"DOCKER_HOST=" + dockerHostForInnerClients(unixSocketPath, requestHost)})
	}
	return env
}
