package com.jmna.auth.config;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class RedisStartupChecker {

    private final RedisConnectionFactory connectionFactory;

    @PostConstruct
    public void checkRedisConnection() {
        try (RedisConnection connection = connectionFactory.getConnection()) {
            connection.ping();
            log.info("Redis DB 연결에 성공했습니다.");
        } catch (Exception e) {
            throw new IllegalStateException("Redis DB 연결에 실패했습니다.", e);
        }
    }
}
