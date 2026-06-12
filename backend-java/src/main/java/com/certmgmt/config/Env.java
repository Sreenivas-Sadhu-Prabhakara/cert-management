package com.certmgmt.config;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Runtime configuration loaded from process environment variables (SPEC §1). */
public record Env(
        byte[] jwtSecret,
        String jwtIssuer,
        long jwtTtlSeconds,
        String authClientId,
        String authClientSecret,
        byte[] masterKey,
        String backendName) {

    public static Env fromSystem() {
        String jwtSecret = require("JWT_SECRET");
        String issuer = get("JWT_ISSUER", "cert-mgmt");
        long ttl = Long.parseLong(get("JWT_TTL_SECONDS", "900"));
        String clientId = get("AUTH_CLIENT_ID", "admin");
        String clientSecret = require("AUTH_CLIENT_SECRET");
        byte[] masterKey = Base64.getDecoder().decode(require("MASTER_KEY_B64"));
        if (masterKey.length != 32) {
            throw new IllegalStateException("MASTER_KEY_B64 must decode to exactly 32 bytes");
        }
        String backend = get("BACKEND_NAME", "java");
        return new Env(jwtSecret.getBytes(StandardCharsets.UTF_8), issuer, ttl,
                clientId, clientSecret, masterKey, backend);
    }

    private static String get(String name, String dflt) {
        String v = System.getenv(name);
        return (v == null || v.isBlank()) ? dflt : v;
    }

    private static String require(String name) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException("required environment variable " + name + " is not set");
        }
        return v;
    }
}
