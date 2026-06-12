package com.certmgmt.repo;

import com.certmgmt.config.Env;
import com.certmgmt.web.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** Append-only audit trail (SPEC §8). The DB trigger forbids UPDATE/DELETE. */
@Repository
public class AuditRepository {

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final Env env;

    public AuditRepository(JdbcTemplate jdbc, ObjectMapper objectMapper, Env env) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.env = env;
    }

    public void insert(UUID keyId, String eventType, String actor, Object detail) {
        String json;
        try {
            json = detail == null ? null : objectMapper.writeValueAsString(detail);
        } catch (Exception e) {
            throw ApiException.internal("audit detail serialization failed");
        }
        jdbc.update("INSERT INTO key_audit_events (key_id, event_type, actor, backend, detail) "
                + "VALUES (?, ?, ?, ?, ?::jsonb)", keyId, eventType, actor, env.backendName(), json);
    }

    public List<Map<String, Object>> list(UUID keyId) {
        return jdbc.query("SELECT id, key_id, event_type, actor, backend, detail, occurred_at "
                        + "FROM key_audit_events WHERE key_id = ? ORDER BY occurred_at ASC, id ASC",
                (rs, rowNum) -> {
                    Map<String, Object> event = new LinkedHashMap<>();
                    event.put("id", rs.getLong("id"));
                    event.put("keyId", rs.getObject("key_id", UUID.class).toString());
                    event.put("eventType", rs.getString("event_type"));
                    event.put("actor", rs.getString("actor"));
                    event.put("backend", rs.getString("backend"));
                    String detail = rs.getString("detail");
                    event.put("detail", detail == null ? null : parseDetail(detail));
                    event.put("occurredAt", DateTimeFormatter.ISO_INSTANT
                            .format(rs.getObject("occurred_at", OffsetDateTime.class).toInstant()));
                    return event;
                }, keyId);
    }

    private Object parseDetail(String json) {
        try {
            return objectMapper.readValue(json, Object.class);
        } catch (Exception e) {
            return null;
        }
    }
}
