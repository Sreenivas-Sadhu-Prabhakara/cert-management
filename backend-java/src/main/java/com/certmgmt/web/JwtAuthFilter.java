package com.certmgmt.web;

import com.certmgmt.config.Env;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * SPEC §2: every endpoint except GET /health and POST /api/v1/auth/token
 * (and OPTIONS, short-circuited by the CORS filter before this one) requires
 * a valid HS256 bearer token: signature, iss and exp are verified.
 */
public class JwtAuthFilter extends OncePerRequestFilter {

    public static final String ACTOR_ATTRIBUTE = "actor";

    private final JwtParser parser;
    private final ObjectMapper objectMapper;

    public JwtAuthFilter(Env env, ObjectMapper objectMapper) {
        this.parser = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(env.jwtSecret()))
                .requireIssuer(env.jwtIssuer())
                .build();
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String path = request.getRequestURI();
        boolean protectedPath = path.startsWith("/api/v1/") && !path.equals("/api/v1/auth/token");
        if (!protectedPath) {
            chain.doFilter(request, response);
            return;
        }

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            unauthorized(response, "missing bearer token");
            return;
        }
        try {
            Claims claims = parser.parseSignedClaims(header.substring("Bearer ".length()).trim())
                    .getPayload();
            request.setAttribute(ACTOR_ATTRIBUTE, claims.getSubject());
        } catch (Exception e) {
            unauthorized(response, "invalid or expired token");
            return;
        }
        chain.doFilter(request, response);
    }

    private void unauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(401);
        response.setContentType("application/json");
        objectMapper.writeValue(response.getOutputStream(),
                ApiExceptionHandler.envelope("UNAUTHORIZED", message));
    }
}
