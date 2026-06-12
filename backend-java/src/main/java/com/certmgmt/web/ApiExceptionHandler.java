package com.certmgmt.web;

import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> apiError(ApiException e) {
        return ResponseEntity.status(e.status()).body(envelope(e.code(), e.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> unreadable(HttpMessageNotReadableException e) {
        return ResponseEntity.status(400).body(envelope("INVALID_REQUEST", "malformed request body"));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<Map<String, Object>> noResource(NoResourceFoundException e) {
        return ResponseEntity.status(404).body(envelope("NOT_FOUND", "no such resource"));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> methodNotSupported(HttpRequestMethodNotSupportedException e) {
        return ResponseEntity.status(404).body(envelope("NOT_FOUND", "no such resource"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> unexpected(Exception e) {
        log.error("unexpected failure", e);
        return ResponseEntity.status(500).body(envelope("INTERNAL", "internal server error"));
    }

    static Map<String, Object> envelope(String code, String message) {
        return Map.of("error", Map.of("code", code, "message", message));
    }
}
