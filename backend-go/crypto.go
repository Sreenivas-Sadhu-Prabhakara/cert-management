package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// generateKeyPair creates a key pair per SPEC §4.1: private key as PKCS#8 PEM,
// public key as SPKI PEM; spkiDER is the DER used for the SHA-256 fingerprint.
func generateKeyPair(algorithm string) (privPEM, pubPEM string, spkiDER []byte, err error) {
	var signer crypto.Signer
	switch algorithm {
	case "RSA_2048":
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	case "RSA_3072":
		signer, err = rsa.GenerateKey(rand.Reader, 3072)
	case "RSA_4096":
		signer, err = rsa.GenerateKey(rand.Reader, 4096)
	case "EC_P256":
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "EC_P384":
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		err = fmt.Errorf("unsupported algorithm %q", algorithm)
	}
	if err != nil {
		return "", "", nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return "", "", nil, err
	}
	spkiDER, err = x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", "", nil, err
	}
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiDER}))
	return privPEM, pubPEM, spkiDER, nil
}

// encryptPrivateKey implements SPEC §4.2: AES-256-GCM, 12-byte random nonce,
// AAD = lowercase UUID string, stored as base64(nonce || ciphertext || tag).
func encryptPrivateKey(masterKey []byte, keyID string, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, []byte(keyID)) // Seal appends the 16-byte tag
	return base64.StdEncoding.EncodeToString(append(nonce, sealed...)), nil
}

func decryptPrivateKey(masterKey []byte, keyID, stored string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("stored ciphertext too short")
	}
	return gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte(keyID))
}

type csrSubject struct {
	CommonName         string `json:"commonName"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalUnit"`
	Country            string `json:"country"`
	State              string `json:"state"`
	Locality           string `json:"locality"`
}

// buildCSR creates a PKCS#10 CSR per SPEC §4.3 and returns the PEM plus the
// RFC 2253-style subject string (for the audit detail).
func buildCSR(privPEM []byte, algorithm string, subj csrSubject, sans []string) (string, string, error) {
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return "", "", errors.New("stored private key PEM is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", "", err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return "", "", errors.New("private key does not implement crypto.Signer")
	}

	name := pkix.Name{CommonName: strings.TrimSpace(subj.CommonName)}
	set := func(dst *[]string, v string) {
		if s := strings.TrimSpace(v); s != "" {
			*dst = []string{s}
		}
	}
	set(&name.Organization, subj.Organization)
	set(&name.OrganizationalUnit, subj.OrganizationalUnit)
	set(&name.Country, subj.Country)
	set(&name.Province, subj.State)
	set(&name.Locality, subj.Locality)

	var sigAlg x509.SignatureAlgorithm
	switch algorithm {
	case "EC_P256":
		sigAlg = x509.ECDSAWithSHA256
	case "EC_P384":
		sigAlg = x509.ECDSAWithSHA384
	default: // RSA_2048 / RSA_3072 / RSA_4096
		sigAlg = x509.SHA256WithRSA
	}

	tmpl := &x509.CertificateRequest{
		Subject:            name,
		DNSNames:           sans,
		SignatureAlgorithm: sigAlg,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		return "", "", err
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	return csrPEM, name.String(), nil
}

// spkiFromPublicPEM returns the DER bytes inside a stored SPKI public-key PEM.
func spkiFromPublicPEM(pubPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("stored public key PEM is invalid")
	}
	return block.Bytes, nil
}

// validateChain performs SPEC §4.4 steps 2–6 in order (first failure wins).
// Step 1 (existence + status) is handled by the caller before this runs.
func validateChain(chainPEM string, storedSPKI []byte, now time.Time) ([]*x509.Certificate, *apiError) {
	var certs []*x509.Certificate
	rest := []byte(chainPEM)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, &apiError{400, "INVALID_PEM", "certificate chain contains an unparseable PEM block"}
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, &apiError{400, "INVALID_PEM", "no certificate PEM blocks found"}
	}

	// 3. Public-key binding: leaf SPKI DER must match the stored SPKI byte-for-byte.
	leaf := certs[0]
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, storedSPKI) {
		return nil, &apiError{422, "KEY_MISMATCH", "leaf certificate public key does not match the stored key"}
	}

	// 4. Chain integrity: issuer DN linkage + signature of each cert under its successor.
	for i := 0; i+1 < len(certs); i++ {
		child, parent := certs[i], certs[i+1]
		if !bytes.Equal(child.RawIssuer, parent.RawSubject) {
			return nil, &apiError{422, "CHAIN_BROKEN", fmt.Sprintf("certificate %d issuer does not match certificate %d subject", i, i+1)}
		}
		if err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature); err != nil {
			return nil, &apiError{422, "CHAIN_BROKEN", fmt.Sprintf("certificate %d signature does not verify under certificate %d", i, i+1)}
		}
	}

	// 5. Trailing self-signed certificate must verify its own signature.
	last := certs[len(certs)-1]
	if bytes.Equal(last.RawSubject, last.RawIssuer) {
		if err := last.CheckSignature(last.SignatureAlgorithm, last.RawTBSCertificate, last.Signature); err != nil {
			return nil, &apiError{422, "CHAIN_BROKEN", "self-signed root signature does not verify"}
		}
	}

	// 6. Validity window of every certificate must include now.
	for i, c := range certs {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return nil, &apiError{422, "CERT_NOT_VALID", fmt.Sprintf("certificate %d is outside its validity window", i)}
		}
	}
	return certs, nil
}
