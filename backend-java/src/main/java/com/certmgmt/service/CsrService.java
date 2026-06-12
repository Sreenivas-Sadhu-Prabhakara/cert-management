package com.certmgmt.service;

import com.certmgmt.web.ApiException;
import com.certmgmt.web.dto.SubjectDto;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.stereotype.Service;

/** SPEC §4.3: PKCS#10 CSR generation with optional DNS SANs. */
@Service
public class CsrService {

    public record CsrResult(String csrPem, String subjectString) {}

    private final CryptoService crypto;

    public CsrService(CryptoService crypto) {
        this.crypto = crypto;
    }

    public CsrResult generate(String algorithm, PrivateKey privateKey, PublicKey publicKey,
                              SubjectDto subject, List<String> sans) {
        try {
            X500Name x500Name = buildSubject(subject);
            PKCS10CertificationRequestBuilder builder =
                    new JcaPKCS10CertificationRequestBuilder(x500Name, publicKey);

            if (sans != null && !sans.isEmpty()) {
                GeneralName[] names = sans.stream()
                        .map(dns -> new GeneralName(GeneralName.dNSName, dns))
                        .toArray(GeneralName[]::new);
                ExtensionsGenerator extGen = new ExtensionsGenerator();
                extGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
                builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
            }

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm(algorithm))
                    .build(privateKey);
            PKCS10CertificationRequest csr = builder.build(signer);
            return new CsrResult(crypto.pem("CERTIFICATE REQUEST", csr.getEncoded()),
                    x500Name.toString());
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw ApiException.internal("CSR generation failed");
        }
    }

    private static String signatureAlgorithm(String algorithm) {
        if (algorithm.startsWith("RSA")) {
            return "SHA256withRSA";
        }
        if ("EC_P256".equals(algorithm)) {
            return "SHA256withECDSA";
        }
        if ("EC_P384".equals(algorithm)) {
            return "SHA384withECDSA";
        }
        throw ApiException.internal("unsupported algorithm: " + algorithm);
    }

    private static X500Name buildSubject(SubjectDto subject) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        if (notBlank(subject.country())) {
            builder.addRDN(BCStyle.C, subject.country());
        }
        if (notBlank(subject.state())) {
            builder.addRDN(BCStyle.ST, subject.state());
        }
        if (notBlank(subject.locality())) {
            builder.addRDN(BCStyle.L, subject.locality());
        }
        if (notBlank(subject.organization())) {
            builder.addRDN(BCStyle.O, subject.organization());
        }
        if (notBlank(subject.organizationalUnit())) {
            builder.addRDN(BCStyle.OU, subject.organizationalUnit());
        }
        builder.addRDN(BCStyle.CN, subject.commonName());
        return builder.build();
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }
}
