package com.certmgmt.repo;

import java.time.OffsetDateTime;
import java.util.UUID;

public record KeyRow(
        UUID id,
        String name,
        String algorithm,
        String status,
        String publicKeyPem,
        String privateKeyEnc,
        String fingerprintSha256,
        String certificateChainPem,
        String certSubject,
        String certIssuer,
        String certSerial,
        OffsetDateTime certNotBefore,
        OffsetDateTime certNotAfter,
        String compromisedReason,
        String createdBy,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt) {}
