package com.certmgmt.controller;

import com.certmgmt.config.Env;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {

    private final JdbcTemplate jdbc;
    private final Env env;

    public HealthController(JdbcTemplate jdbc, Env env) {
        this.jdbc = jdbc;
        this.env = env;
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        try {
            jdbc.queryForObject("SELECT 1", Integer.class);
            return ResponseEntity.ok(Map.of("status", "up", "backend", env.backendName()));
        } catch (Exception e) {
            return ResponseEntity.status(503)
                    .body(Map.of("status", "down", "backend", env.backendName()));
        }
    }
}
