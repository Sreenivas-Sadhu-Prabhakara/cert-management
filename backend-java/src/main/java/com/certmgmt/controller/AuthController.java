package com.certmgmt.controller;

import com.certmgmt.config.Env;
import com.certmgmt.web.ApiException;
import com.certmgmt.web.dto.Requests.TokenRequest;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final Env env;

    public AuthController(Env env) {
        this.env = env;
    }

    @PostMapping("/api/v1/auth/token")
    public Map<String, Object> token(@RequestBody(required = false) TokenRequest request) {
        boolean idOk = request != null && constantTimeEquals(request.clientId(), env.authClientId());
        boolean secretOk = request != null
                && constantTimeEquals(request.clientSecret(), env.authClientSecret());
        if (!(idOk & secretOk)) {
            throw ApiException.unauthorized("invalid client credentials");
        }

        Instant now = Instant.now();
        String jwt = Jwts.builder()
                .issuer(env.jwtIssuer())
                .subject(request.clientId())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(env.jwtTtlSeconds())))
                .claim("scope", "keys:admin")
                .signWith(Keys.hmacShaKeyFor(env.jwtSecret()), Jwts.SIG.HS256)
                .compact();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("accessToken", jwt);
        out.put("tokenType", "Bearer");
        out.put("expiresIn", env.jwtTtlSeconds());
        return out;
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
