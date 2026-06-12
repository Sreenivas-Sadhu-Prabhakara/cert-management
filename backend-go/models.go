package main

import (
	"encoding/json"
	"time"
)

// Database row of ssl_keys.
type keyRow struct {
	ID                string
	Name              string
	Algorithm         string
	Status            string
	PublicKeyPEM      string
	PrivateKeyEnc     *string
	Fingerprint       string
	CertChainPEM      *string
	CertSubject       *string
	CertIssuer        *string
	CertSerial        *string
	CertNotBefore     *time.Time
	CertNotAfter      *time.Time
	CompromisedReason *string
	CreatedBy         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// iso formats a timestamp as ISO-8601 UTC per SPEC §7 (e.g. 2026-06-12T08:30:00Z).
func iso(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func isoPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := iso(*t)
	return &s
}

// KeySummary — list items, no PEM material (SPEC §7).
type KeySummary struct {
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	Algorithm         string  `json:"algorithm"`
	Status            string  `json:"status"`
	FingerprintSha256 string  `json:"fingerprintSha256"`
	HasCertificate    bool    `json:"hasCertificate"`
	CertNotAfter      *string `json:"certNotAfter"`
	CreatedAt         string  `json:"createdAt"`
	UpdatedAt         string  `json:"updatedAt"`
}

// CertificateInfo — leaf-certificate metadata inside KeyDetail.
type CertificateInfo struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	SerialNumber string `json:"serialNumber"`
	NotBefore    string `json:"notBefore"`
	NotAfter     string `json:"notAfter"`
}

// KeyDetail (SPEC §7). PrivateKeyPem is set ONLY in the POST /keys 201 response.
type KeyDetail struct {
	ID                  string           `json:"id"`
	Name                string           `json:"name"`
	Algorithm           string           `json:"algorithm"`
	Status              string           `json:"status"`
	PublicKeyPem        string           `json:"publicKeyPem"`
	FingerprintSha256   string           `json:"fingerprintSha256"`
	HasCertificate      bool             `json:"hasCertificate"`
	CertNotAfter        *string          `json:"certNotAfter"`
	CertificateChainPem *string          `json:"certificateChainPem"`
	Certificate         *CertificateInfo `json:"certificate"`
	CompromisedReason   *string          `json:"compromisedReason"`
	CreatedBy           string           `json:"createdBy"`
	CreatedAt           string           `json:"createdAt"`
	UpdatedAt           string           `json:"updatedAt"`
	PrivateKeyPem       string           `json:"privateKeyPem,omitempty"`
}

// AuditEvent (SPEC §7).
type AuditEvent struct {
	ID         int64           `json:"id"`
	KeyID      string          `json:"keyId"`
	EventType  string          `json:"eventType"`
	Actor      string          `json:"actor"`
	Backend    string          `json:"backend"`
	Detail     json.RawMessage `json:"detail"`
	OccurredAt string          `json:"occurredAt"`
}

func (k *keyRow) summary() KeySummary {
	return KeySummary{
		ID:                k.ID,
		Name:              k.Name,
		Algorithm:         k.Algorithm,
		Status:            k.Status,
		FingerprintSha256: k.Fingerprint,
		HasCertificate:    k.CertChainPEM != nil,
		CertNotAfter:      isoPtr(k.CertNotAfter),
		CreatedAt:         iso(k.CreatedAt),
		UpdatedAt:         iso(k.UpdatedAt),
	}
}

func (k *keyRow) detail() KeyDetail {
	d := KeyDetail{
		ID:                  k.ID,
		Name:                k.Name,
		Algorithm:           k.Algorithm,
		Status:              k.Status,
		PublicKeyPem:        k.PublicKeyPEM,
		FingerprintSha256:   k.Fingerprint,
		HasCertificate:      k.CertChainPEM != nil,
		CertNotAfter:        isoPtr(k.CertNotAfter),
		CertificateChainPem: k.CertChainPEM,
		CompromisedReason:   k.CompromisedReason,
		CreatedBy:           k.CreatedBy,
		CreatedAt:           iso(k.CreatedAt),
		UpdatedAt:           iso(k.UpdatedAt),
	}
	if k.CertSubject != nil && k.CertIssuer != nil && k.CertSerial != nil &&
		k.CertNotBefore != nil && k.CertNotAfter != nil {
		d.Certificate = &CertificateInfo{
			Subject:      *k.CertSubject,
			Issuer:       *k.CertIssuer,
			SerialNumber: *k.CertSerial,
			NotBefore:    iso(*k.CertNotBefore),
			NotAfter:     iso(*k.CertNotAfter),
		}
	}
	return d
}
