package com.certmgmt.web;

/** Carries the SPEC §7 error envelope: HTTP status + machine code + message. */
public class ApiException extends RuntimeException {

    private final int status;
    private final String code;

    public ApiException(int status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }

    public static ApiException unauthorized(String message) {
        return new ApiException(401, "UNAUTHORIZED", message);
    }

    public static ApiException notFound() {
        return new ApiException(404, "NOT_FOUND", "no such key");
    }

    public static ApiException invalidRequest(String message) {
        return new ApiException(400, "INVALID_REQUEST", message);
    }

    public static ApiException invalidPem(String message) {
        return new ApiException(400, "INVALID_PEM", message);
    }

    public static ApiException keyMismatch(String message) {
        return new ApiException(422, "KEY_MISMATCH", message);
    }

    public static ApiException chainBroken(String message) {
        return new ApiException(422, "CHAIN_BROKEN", message);
    }

    public static ApiException certNotValid(String message) {
        return new ApiException(422, "CERT_NOT_VALID", message);
    }

    public static ApiException invalidState(String message) {
        return new ApiException(409, "INVALID_STATE", message);
    }

    public static ApiException internal(String message) {
        return new ApiException(500, "INTERNAL", message);
    }
}
