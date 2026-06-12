package com.certmgmt.service;

import com.certmgmt.config.Env;
import com.certmgmt.web.ApiException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

/** SPEC §4.1 key generation / fingerprints and §4.2 AES-256-GCM at-rest encryption. */
@Service
public class CryptoService {

    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;

    private final Env env;
    private final SecureRandom secureRandom = new SecureRandom();

    public CryptoService(Env env) {
        this.env = env;
    }

    public KeyPair generateKeyPair(String algorithm) {
        try {
            switch (algorithm) {
                case "RSA_2048":
                    return rsa(2048);
                case "RSA_3072":
                    return rsa(3072);
                case "RSA_4096":
                    return rsa(4096);
                case "EC_P256":
                    return ec("secp256r1");
                case "EC_P384":
                    return ec("secp384r1");
                default:
                    throw ApiException.invalidRequest("unsupported algorithm: " + algorithm);
            }
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw ApiException.internal("key generation failed");
        }
    }

    private KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(new RSAKeyGenParameterSpec(bits, RSAKeyGenParameterSpec.F4), secureRandom);
        return kpg.generateKeyPair();
    }

    private KeyPair ec(String curve) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(curve), secureRandom);
        return kpg.generateKeyPair();
    }

    /** Wrap DER bytes in a PEM block with 64-character base64 lines. */
    public String pem(String type, byte[] der) {
        Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII));
        return "-----BEGIN " + type + "-----\n"
                + encoder.encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

    /** Decode the base64 body of a single PEM block back into DER bytes. */
    public byte[] pemToDer(String pem) {
        String body = pem.replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    /** Lowercase hex SHA-256 over the DER-encoded SPKI. */
    public String fingerprintSha256(byte[] spkiDer) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(spkiDer));
        } catch (Exception e) {
            throw ApiException.internal("fingerprint computation failed");
        }
    }

    /** AES-256-GCM encrypt; AAD = lowercase UUID string; stored = base64(nonce||ct||tag). */
    public String encryptPrivateKey(String privateKeyPem, String lowercaseUuid) {
        try {
            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            secureRandom.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(env.masterKey(), "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(lowercaseUuid.getBytes(StandardCharsets.UTF_8));
            byte[] ctAndTag = cipher.doFinal(privateKeyPem.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[nonce.length + ctAndTag.length];
            System.arraycopy(nonce, 0, out, 0, nonce.length);
            System.arraycopy(ctAndTag, 0, out, nonce.length, ctAndTag.length);
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            throw ApiException.internal("private key encryption failed");
        }
    }

    public String decryptPrivateKey(String stored, String lowercaseUuid) {
        try {
            byte[] all = Base64.getDecoder().decode(stored);
            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            System.arraycopy(all, 0, nonce, 0, GCM_NONCE_LENGTH);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(env.masterKey(), "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(lowercaseUuid.getBytes(StandardCharsets.UTF_8));
            byte[] plaintext = cipher.doFinal(all, GCM_NONCE_LENGTH, all.length - GCM_NONCE_LENGTH);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw ApiException.internal("private key decryption failed");
        }
    }

    public PrivateKey parsePkcs8PrivateKey(String pem, String algorithm) {
        try {
            String alg = algorithm.startsWith("RSA") ? "RSA" : "EC";
            return KeyFactory.getInstance(alg).generatePrivate(new PKCS8EncodedKeySpec(pemToDer(pem)));
        } catch (Exception e) {
            throw ApiException.internal("stored private key is unreadable");
        }
    }

    public PublicKey parseSpkiPublicKey(String pem, String algorithm) {
        try {
            String alg = algorithm.startsWith("RSA") ? "RSA" : "EC";
            return KeyFactory.getInstance(alg).generatePublic(new X509EncodedKeySpec(pemToDer(pem)));
        } catch (Exception e) {
            throw ApiException.internal("stored public key is unreadable");
        }
    }
}
