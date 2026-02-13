package io.sidewhale;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.net.Socket;

import static org.junit.jupiter.api.Assertions.assertTrue;

class RedisTest {

    @Test
    void redisContainerStartsAndExposesPort() throws Exception {
        try (GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379).waitingFor(Wait.forListeningPort())) {
            redis.start();
            try (Socket socket = new Socket(redis.getHost(), redis.getMappedPort(6379))) {
                assertTrue(socket.isConnected());
            }
        }
    }
}
