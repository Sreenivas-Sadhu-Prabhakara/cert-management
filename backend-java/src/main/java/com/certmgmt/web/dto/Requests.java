package com.certmgmt.web.dto;

/** Request body records (Jackson binds records natively; unknown fields are ignored). */
public final class Requests {

    public record TokenRequest(String clientId, String clientSecret) {}

    public record CreateKeyRequest(String name, String algorithm) {}

    public record CsrRequest(SubjectDto subject, java.util.List<String> sans) {}

    public record CertificateUploadRequest(String certificateChainPem) {}

    public record CompromiseRequest(String reason) {}

    private Requests() {}
}
