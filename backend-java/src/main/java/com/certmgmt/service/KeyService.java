package com.certmgmt.service;

import com.certmgmt.repo.AuditRepository;
import com.certmgmt.repo.KeyRepository;
import com.certmgmt.repo.KeyRow;
import com.certmgmt.web.ApiException;
import com.certmgmt.web.dto.Requests.CsrRequest;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class KeyService {

    private static final Set<String> ALGORITHMS =
            Set.of("RSA_2048", "RSA_3072", "RSA_4096", "EC_P256", "EC_P384");
    private static final Set<String> STATUSES =
            Set.of("CREATED", "READY_TO_PUBLISH", "ACTIVE", "COMPROMISED", "DELETED");

    private final KeyRepository keys;
    private final AuditRepository audit;
    private final CryptoService crypto;
    private final CsrService csrService;
    private final ChainValidator chainValidator;
    private final TransactionTemplate tx;

    public KeyService(KeyRepository keys, AuditRepository audit, CryptoService crypto,
                      CsrService csrService, ChainValidator chainValidator, TransactionTemplate tx) {
        this.keys = keys;
        this.audit = audit;
        this.crypto = crypto;
        this.csrService = csrService;
        this.chainValidator = chainValidator;
        this.tx = tx;
    }

    // ------------------------------------------------------------------ create

    public Map<String, Object> create(String name, String algorithm, String actor) {
        if (name == null || name.isBlank()) {
            throw ApiException.invalidRequest("name is required");
        }
        if (algorithm == null || !ALGORITHMS.contains(algorithm)) {
            throw ApiException.invalidRequest("algorithm must be one of " + ALGORITHMS);
        }
        KeyPair keyPair = crypto.generateKeyPair(algorithm);
        byte[] spkiDer = keyPair.getPublic().getEncoded();
        String publicPem = crypto.pem("PUBLIC KEY", spkiDer);
        String privatePem = crypto.pem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
        String fingerprint = crypto.fingerprintSha256(spkiDer);

        // UUID is generated before encryption: the lowercase UUID string is the GCM AAD.
        UUID id = UUID.randomUUID();
        String encrypted = crypto.encryptPrivateKey(privatePem, id.toString());

        tx.executeWithoutResult(status -> {
            keys.insert(id, name, algorithm, publicPem, encrypted, fingerprint, actor);
            audit.insert(id, "KEY_GENERATED", actor, Map.of("algorithm", algorithm));
        });

        Map<String, Object> detail = toDetail(mustFind(id));
        detail.put("privateKeyPem", privatePem); // ONLY in the 201 response
        return detail;
    }

    // -------------------------------------------------------------------- read

    public Map<String, Object> list(String statusFilter) {
        if (statusFilter != null && !STATUSES.contains(statusFilter)) {
            throw ApiException.invalidRequest("status must be one of " + STATUSES);
        }
        List<Map<String, Object>> items = keys.list(statusFilter).stream()
                .map(KeyService::toSummary)
                .toList();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("items", items);
        out.put("total", items.size());
        return out;
    }

    public Map<String, Object> get(String idString) {
        return toDetail(mustFind(parseId(idString)));
    }

    public Map<String, Object> getPrivateKey(String idString, String actor) {
        UUID id = parseId(idString);
        KeyRow row = mustFind(id);
        if ("COMPROMISED".equals(row.status()) || "DELETED".equals(row.status())) {
            throw ApiException.invalidState("private key is not retrievable for a "
                    + row.status() + " key");
        }
        if (row.privateKeyEnc() == null) {
            throw ApiException.internal("private key material is missing");
        }
        String privatePem = crypto.decryptPrivateKey(row.privateKeyEnc(), id.toString());
        audit.insert(id, "PRIVATE_KEY_ACCESSED", actor, null);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", id.toString());
        out.put("privateKeyPem", privatePem);
        return out;
    }

    public Map<String, Object> auditTrail(String idString) {
        UUID id = parseId(idString);
        if (!keys.exists(id)) {
            throw ApiException.notFound();
        }
        return Map.of("items", audit.list(id));
    }

    // --------------------------------------------------------------------- csr

    public Map<String, Object> issueCsr(String idString, CsrRequest request, String actor) {
        UUID id = parseId(idString);
        KeyRow row = mustFind(id);
        if ("COMPROMISED".equals(row.status()) || "DELETED".equals(row.status())) {
            throw ApiException.invalidState("CSR generation is not allowed for a "
                    + row.status() + " key");
        }
        if (request == null || request.subject() == null
                || request.subject().commonName() == null
                || request.subject().commonName().isBlank()) {
            throw ApiException.invalidRequest("subject.commonName is required");
        }
        String privatePem = crypto.decryptPrivateKey(row.privateKeyEnc(), id.toString());
        CsrService.CsrResult result = csrService.generate(
                row.algorithm(),
                crypto.parsePkcs8PrivateKey(privatePem, row.algorithm()),
                crypto.parseSpkiPublicKey(row.publicKeyPem(), row.algorithm()),
                request.subject(),
                request.sans());

        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("subject", result.subjectString());
        if (request.sans() != null && !request.sans().isEmpty()) {
            detail.put("sans", request.sans());
        }
        audit.insert(id, "CSR_ISSUED", actor, detail);
        return Map.of("csrPem", result.csrPem());
    }

    // ------------------------------------------------------------- certificate

    public Map<String, Object> uploadCertificate(String idString, String chainPem, String actor) {
        UUID id = parseId(idString);
        KeyRow row = mustFind(id);

        // Step 1: state gate (404 already handled by mustFind).
        if (!"CREATED".equals(row.status()) && !"READY_TO_PUBLISH".equals(row.status())) {
            throw ApiException.invalidState("certificate upload requires status "
                    + "CREATED or READY_TO_PUBLISH, current status is " + row.status());
        }

        // Step 2: parse (INVALID_PEM failures are not audited per SPEC §4.4).
        List<X509Certificate> chain = chainValidator.parseChain(chainPem);

        // Steps 3-6: validation failures are audited as CERTIFICATE_REJECTED, then rethrown.
        byte[] storedSpki = crypto.pemToDer(row.publicKeyPem());
        try {
            chainValidator.validate(chain, storedSpki);
        } catch (ApiException e) {
            audit.insert(id, "CERTIFICATE_REJECTED", actor, Map.of("reason", e.code()));
            throw e;
        }

        X509Certificate leaf = chain.get(0);
        String subject = leaf.getSubjectX500Principal().getName(X500Principal.RFC2253);
        String issuer = leaf.getIssuerX500Principal().getName(X500Principal.RFC2253);
        String serial = leaf.getSerialNumber().toString();
        OffsetDateTime notBefore = OffsetDateTime.ofInstant(leaf.getNotBefore().toInstant(), ZoneOffset.UTC);
        OffsetDateTime notAfter = OffsetDateTime.ofInstant(leaf.getNotAfter().toInstant(), ZoneOffset.UTC);

        tx.executeWithoutResult(status -> {
            int updated = keys.storeCertificate(id, chainPem, subject, issuer, serial,
                    notBefore, notAfter);
            if (updated == 0) {
                throw keys.exists(id)
                        ? ApiException.invalidState("certificate upload requires status "
                                + "CREATED or READY_TO_PUBLISH")
                        : ApiException.notFound();
            }
            audit.insert(id, "CERTIFICATE_UPLOADED", actor,
                    Map.of("subject", subject, "serialNumber", serial));
        });
        return toDetail(mustFind(id));
    }

    // ------------------------------------------------------------- transitions

    public Map<String, Object> activate(String idString, String actor) {
        UUID id = parseId(idString);
        tx.executeWithoutResult(status -> {
            int updated = keys.activate(id);
            if (updated == 0) {
                throw keys.exists(id)
                        ? ApiException.invalidState("only a READY_TO_PUBLISH key can be activated")
                        : ApiException.notFound();
            }
            audit.insert(id, "ACTIVATED", actor, null);
        });
        return toDetail(mustFind(id));
    }

    public Map<String, Object> compromise(String idString, String reason, String actor) {
        UUID id = parseId(idString);
        tx.executeWithoutResult(status -> {
            int updated = keys.compromise(id, reason);
            if (updated == 0) {
                throw keys.exists(id)
                        ? ApiException.invalidState("key cannot be marked compromised in its current state")
                        : ApiException.notFound();
            }
            audit.insert(id, "COMPROMISED", actor, reason == null ? null : Map.of("reason", reason));
        });
        return toDetail(mustFind(id));
    }

    public void delete(String idString, String actor) {
        UUID id = parseId(idString);
        tx.executeWithoutResult(status -> {
            int updated = keys.softDelete(id);
            if (updated == 0) {
                throw keys.exists(id)
                        ? ApiException.invalidState("key cannot be deleted in its current state")
                        : ApiException.notFound();
            }
            audit.insert(id, "DELETED", actor, null);
        });
    }

    // ----------------------------------------------------------------- mapping

    private KeyRow mustFind(UUID id) {
        return keys.find(id).orElseThrow(ApiException::notFound);
    }

    private static UUID parseId(String idString) {
        try {
            return UUID.fromString(idString);
        } catch (IllegalArgumentException e) {
            throw ApiException.notFound(); // malformed UUID -> 404 per SPEC §6
        }
    }

    private static String iso(OffsetDateTime t) {
        return t == null ? null : DateTimeFormatter.ISO_INSTANT.format(t.toInstant());
    }

    static Map<String, Object> toSummary(KeyRow row) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", row.id().toString());
        m.put("name", row.name());
        m.put("algorithm", row.algorithm());
        m.put("status", row.status());
        m.put("fingerprintSha256", row.fingerprintSha256());
        m.put("hasCertificate", row.certificateChainPem() != null);
        m.put("certNotAfter", iso(row.certNotAfter()));
        m.put("createdAt", iso(row.createdAt()));
        m.put("updatedAt", iso(row.updatedAt()));
        return m;
    }

    static Map<String, Object> toDetail(KeyRow row) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", row.id().toString());
        m.put("name", row.name());
        m.put("algorithm", row.algorithm());
        m.put("status", row.status());
        m.put("publicKeyPem", row.publicKeyPem());
        m.put("fingerprintSha256", row.fingerprintSha256());
        m.put("hasCertificate", row.certificateChainPem() != null);
        m.put("certNotAfter", iso(row.certNotAfter()));
        m.put("certificateChainPem", row.certificateChainPem());
        Map<String, Object> cert = null;
        if (row.certSubject() != null) {
            cert = new LinkedHashMap<>();
            cert.put("subject", row.certSubject());
            cert.put("issuer", row.certIssuer());
            cert.put("serialNumber", row.certSerial());
            cert.put("notBefore", iso(row.certNotBefore()));
            cert.put("notAfter", iso(row.certNotAfter()));
        }
        m.put("certificate", cert);
        m.put("compromisedReason", row.compromisedReason());
        m.put("createdBy", row.createdBy());
        m.put("createdAt", iso(row.createdAt()));
        m.put("updatedAt", iso(row.updatedAt()));
        return m;
    }
}
