package com.certmgmt.service;

import com.certmgmt.web.ApiException;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;

/** SPEC §4.4: certificate-chain validation, in the exact specified order. */
@Service
public class ChainValidator {

    private static final Pattern CERT_BLOCK = Pattern.compile(
            "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL);

    /** Step 2: parse all PEM blocks as X.509; at least one, else 400 INVALID_PEM. */
    public List<X509Certificate> parseChain(String chainPem) {
        if (chainPem == null || chainPem.isBlank()) {
            throw ApiException.invalidPem("certificateChainPem contains no certificates");
        }
        List<X509Certificate> certs = new ArrayList<>();
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Matcher matcher = CERT_BLOCK.matcher(chainPem);
            while (matcher.find()) {
                byte[] der = Base64.getMimeDecoder().decode(matcher.group(1).replaceAll("\\s", ""));
                certs.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der)));
            }
        } catch (Exception e) {
            throw ApiException.invalidPem("certificate chain is not valid PEM/X.509");
        }
        if (certs.isEmpty()) {
            throw ApiException.invalidPem("certificateChainPem contains no certificates");
        }
        return certs;
    }

    /** Steps 3-6. Throws 422 KEY_MISMATCH / CHAIN_BROKEN / CERT_NOT_VALID, first failure wins. */
    public void validate(List<X509Certificate> chain, byte[] storedSpkiDer) {
        // Step 3: public-key binding — leaf SPKI must equal stored SPKI byte-for-byte.
        X509Certificate leaf = chain.get(0);
        if (!Arrays.equals(leaf.getPublicKey().getEncoded(), storedSpkiDer)) {
            throw ApiException.keyMismatch("leaf certificate public key does not match the stored key");
        }

        // Step 4: chain integrity — DN linkage and signature for every adjacent pair.
        for (int i = 0; i + 1 < chain.size(); i++) {
            X509Certificate cert = chain.get(i);
            X509Certificate issuer = chain.get(i + 1);
            if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                throw ApiException.chainBroken(
                        "certificate " + i + " issuer DN does not match certificate " + (i + 1) + " subject DN");
            }
            try {
                cert.verify(issuer.getPublicKey());
            } catch (Exception e) {
                throw ApiException.chainBroken(
                        "certificate " + i + " signature does not verify under certificate " + (i + 1));
            }
        }

        // Step 5: a trailing self-signed root must verify its own signature.
        X509Certificate last = chain.get(chain.size() - 1);
        if (last.getSubjectX500Principal().equals(last.getIssuerX500Principal())) {
            try {
                last.verify(last.getPublicKey());
            } catch (Exception e) {
                throw ApiException.chainBroken("self-signed root certificate signature does not verify");
            }
        }

        // Step 6: validity window of every certificate must include now.
        for (X509Certificate cert : chain) {
            try {
                cert.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                throw ApiException.certNotValid("certificate is outside its validity window");
            }
        }
    }
}
