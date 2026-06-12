package com.certmgmt.repo;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class KeyRepository {

    private static final String COLUMNS =
            "id, name, algorithm, status, public_key_pem, private_key_enc, fingerprint_sha256, "
            + "certificate_chain_pem, cert_subject, cert_issuer, cert_serial, cert_not_before, "
            + "cert_not_after, compromised_reason, created_by, created_at, updated_at";

    private static final RowMapper<KeyRow> MAPPER = (rs, rowNum) -> new KeyRow(
            rs.getObject("id", UUID.class),
            rs.getString("name"),
            rs.getString("algorithm"),
            rs.getString("status"),
            rs.getString("public_key_pem"),
            rs.getString("private_key_enc"),
            rs.getString("fingerprint_sha256"),
            rs.getString("certificate_chain_pem"),
            rs.getString("cert_subject"),
            rs.getString("cert_issuer"),
            rs.getString("cert_serial"),
            rs.getObject("cert_not_before", OffsetDateTime.class),
            rs.getObject("cert_not_after", OffsetDateTime.class),
            rs.getString("compromised_reason"),
            rs.getString("created_by"),
            rs.getObject("created_at", OffsetDateTime.class),
            rs.getObject("updated_at", OffsetDateTime.class));

    private final JdbcTemplate jdbc;

    public KeyRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<KeyRow> find(UUID id) {
        List<KeyRow> rows = jdbc.query(
                "SELECT " + COLUMNS + " FROM ssl_keys WHERE id = ?", MAPPER, id);
        return rows.stream().findFirst();
    }

    public boolean exists(UUID id) {
        Integer n = jdbc.queryForObject("SELECT count(*) FROM ssl_keys WHERE id = ?", Integer.class, id);
        return n != null && n > 0;
    }

    public List<KeyRow> list(String status) {
        if (status != null) {
            return jdbc.query("SELECT " + COLUMNS + " FROM ssl_keys WHERE status = ? "
                    + "ORDER BY created_at DESC", MAPPER, status);
        }
        return jdbc.query("SELECT " + COLUMNS + " FROM ssl_keys ORDER BY created_at DESC", MAPPER);
    }

    public void insert(UUID id, String name, String algorithm, String publicKeyPem,
                       String privateKeyEnc, String fingerprintSha256, String createdBy) {
        jdbc.update("INSERT INTO ssl_keys (id, name, algorithm, status, public_key_pem, "
                        + "private_key_enc, fingerprint_sha256, created_by) "
                        + "VALUES (?, ?, ?, 'CREATED', ?, ?, ?, ?)",
                id, name, algorithm, publicKeyPem, privateKeyEnc, fingerprintSha256, createdBy);
    }

    /** Atomic CAS: CREATED|READY_TO_PUBLISH -> READY_TO_PUBLISH with the verified chain. */
    public int storeCertificate(UUID id, String chainPem, String subject, String issuer,
                                String serial, OffsetDateTime notBefore, OffsetDateTime notAfter) {
        return jdbc.update("UPDATE ssl_keys SET certificate_chain_pem = ?, cert_subject = ?, "
                        + "cert_issuer = ?, cert_serial = ?, cert_not_before = ?, cert_not_after = ?, "
                        + "status = 'READY_TO_PUBLISH', updated_at = now() "
                        + "WHERE id = ? AND status IN ('CREATED','READY_TO_PUBLISH')",
                chainPem, subject, issuer, serial, notBefore, notAfter, id);
    }

    /** Atomic CAS: READY_TO_PUBLISH -> ACTIVE. */
    public int activate(UUID id) {
        return jdbc.update("UPDATE ssl_keys SET status = 'ACTIVE', updated_at = now() "
                + "WHERE id = ? AND status = 'READY_TO_PUBLISH'", id);
    }

    /** Atomic CAS: CREATED|READY_TO_PUBLISH|ACTIVE -> COMPROMISED. */
    public int compromise(UUID id, String reason) {
        return jdbc.update("UPDATE ssl_keys SET status = 'COMPROMISED', compromised_reason = ?, "
                + "updated_at = now() "
                + "WHERE id = ? AND status IN ('CREATED','READY_TO_PUBLISH','ACTIVE')", reason, id);
    }

    /** Atomic CAS: CREATED|READY_TO_PUBLISH|ACTIVE -> DELETED, crypto-shredding the private key. */
    public int softDelete(UUID id) {
        return jdbc.update("UPDATE ssl_keys SET status = 'DELETED', private_key_enc = NULL, "
                + "updated_at = now() "
                + "WHERE id = ? AND status IN ('CREATED','READY_TO_PUBLISH','ACTIVE')", id);
    }
}
