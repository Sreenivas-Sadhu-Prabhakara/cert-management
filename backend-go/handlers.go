package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type server struct {
	pool *pgxpool.Pool
	cfg  config
}

type apiError struct {
	status int
	code   string
	msg    string
}

var validAlgorithms = map[string]bool{
	"RSA_2048": true, "RSA_3072": true, "RSA_4096": true, "EC_P256": true, "EC_P384": true,
}

var validStatuses = map[string]bool{
	"CREATED": true, "READY_TO_PUBLISH": true, "ACTIVE": true, "COMPROMISED": true, "DELETED": true,
}

// ---------------------------------------------------------------- responses

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func writeAPIError(w http.ResponseWriter, e *apiError) {
	writeError(w, e.status, e.code, e.msg)
}

func internalErr(err error) *apiError {
	log.Printf("internal error: %v", err)
	return &apiError{http.StatusInternalServerError, "INTERNAL", "unexpected internal error"}
}

// ---------------------------------------------------------------- auth

func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "malformed JSON body")
		return
	}
	idOK := subtle.ConstantTimeCompare([]byte(body.ClientID), []byte(s.cfg.authClientID))
	secOK := subtle.ConstantTimeCompare([]byte(body.ClientSecret), []byte(s.cfg.authSecret))
	if idOK&secOK != 1 {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid client credentials")
		return
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   s.cfg.jwtIssuer,
		"sub":   body.ClientID,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Duration(s.cfg.jwtTTL) * time.Second).Unix(),
		"scope": "keys:admin",
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.cfg.jwtSecret)
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken": tok, "tokenType": "Bearer", "expiresIn": s.cfg.jwtTTL,
	})
}

// auth wraps a handler with Bearer-JWT validation (signature, iss, exp) and
// passes the JWT subject through as the acting principal.
func (s *server) auth(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, prefix) {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing bearer token")
			return
		}
		tok, err := jwt.Parse(strings.TrimSpace(header[len(prefix):]),
			func(t *jwt.Token) (any, error) { return s.cfg.jwtSecret, nil },
			jwt.WithValidMethods([]string{"HS256"}),
			jwt.WithIssuer(s.cfg.jwtIssuer),
			jwt.WithExpirationRequired(),
		)
		if err != nil || !tok.Valid {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired token")
			return
		}
		sub, err := tok.Claims.GetSubject()
		if err != nil || sub == "" {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "token has no subject")
			return
		}
		next(w, r, sub)
	}
}

// ---------------------------------------------------------------- store

const keyColumns = `id::text, name, algorithm, status, public_key_pem, private_key_enc,
	fingerprint_sha256, certificate_chain_pem, cert_subject, cert_issuer, cert_serial,
	cert_not_before, cert_not_after, compromised_reason, created_by, created_at, updated_at`

func scanKey(row pgx.Row) (*keyRow, error) {
	var k keyRow
	err := row.Scan(&k.ID, &k.Name, &k.Algorithm, &k.Status, &k.PublicKeyPEM, &k.PrivateKeyEnc,
		&k.Fingerprint, &k.CertChainPEM, &k.CertSubject, &k.CertIssuer, &k.CertSerial,
		&k.CertNotBefore, &k.CertNotAfter, &k.CompromisedReason, &k.CreatedBy, &k.CreatedAt, &k.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// getKey returns (nil, nil) when the key does not exist.
func (s *server) getKey(ctx context.Context, id string) (*keyRow, error) {
	k, err := scanKey(s.pool.QueryRow(ctx, `SELECT `+keyColumns+` FROM ssl_keys WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return k, err
}

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func insertAudit(ctx context.Context, db execer, keyID, event, actor, backend string, detail []byte) error {
	var d any
	if detail != nil {
		d = detail
	}
	_, err := db.Exec(ctx,
		`INSERT INTO key_audit_events (key_id, event_type, actor, backend, detail) VALUES ($1, $2, $3, $4, $5)`,
		keyID, event, actor, backend, d)
	return err
}

// mutateKeyTx runs an INSERT/UPDATE ... RETURNING statement and the matching
// audit insert in one transaction (SPEC §8). A compare-and-set UPDATE that
// matches zero rows yields 404 (id absent) or 409 INVALID_STATE (id present).
func (s *server) mutateKeyTx(ctx context.Context, id, sqlText string, args []any, event, actor string, detail []byte) (*keyRow, *apiError) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, internalErr(err)
	}
	defer tx.Rollback(ctx)

	k, err := scanKey(tx.QueryRow(ctx, sqlText, args...))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			var exists bool
			if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ssl_keys WHERE id = $1)`, id).Scan(&exists); e != nil {
				return nil, internalErr(e)
			}
			if !exists {
				return nil, &apiError{http.StatusNotFound, "NOT_FOUND", "key not found"}
			}
			return nil, &apiError{http.StatusConflict, "INVALID_STATE", "operation not allowed in the key's current status"}
		}
		return nil, internalErr(err)
	}
	if err := insertAudit(ctx, tx, k.ID, event, actor, s.cfg.backendName, detail); err != nil {
		return nil, internalErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, internalErr(err)
	}
	return k, nil
}

// parseID 404s on malformed UUIDs per SPEC §6 and returns the canonical
// lowercase form (which is also the AES-GCM AAD).
func parseID(w http.ResponseWriter, r *http.Request) (string, bool) {
	u, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "key not found")
		return "", false
	}
	return u.String(), true
}

// ---------------------------------------------------------------- handlers

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	var one int
	if err := s.pool.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "down", "backend": s.cfg.backendName})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "up", "backend": s.cfg.backendName})
}

func (s *server) handleCreateKey(w http.ResponseWriter, r *http.Request, actor string) {
	var body struct {
		Name      string `json:"name"`
		Algorithm string `json:"algorithm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "malformed JSON body")
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "name is required")
		return
	}
	if !validAlgorithms[body.Algorithm] {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"algorithm must be one of RSA_2048, RSA_3072, RSA_4096, EC_P256, EC_P384")
		return
	}

	privPEM, pubPEM, spkiDER, err := generateKeyPair(body.Algorithm)
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	id := uuid.NewString() // generated before encryption: the lowercase UUID is the AAD
	enc, err := encryptPrivateKey(s.cfg.masterKey, id, []byte(privPEM))
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(spkiDER))
	detail, _ := json.Marshal(map[string]string{"algorithm": body.Algorithm})

	sqlText := `INSERT INTO ssl_keys
		(id, name, algorithm, status, public_key_pem, private_key_enc, fingerprint_sha256, created_by)
		VALUES ($1, $2, $3, 'CREATED', $4, $5, $6, $7) RETURNING ` + keyColumns
	k, aerr := s.mutateKeyTx(r.Context(), id, sqlText,
		[]any{id, body.Name, body.Algorithm, pubPEM, enc, fingerprint, actor},
		"KEY_GENERATED", actor, detail)
	if aerr != nil {
		writeAPIError(w, aerr)
		return
	}
	d := k.detail()
	d.PrivateKeyPem = privPEM // only the 201 response carries the private key
	writeJSON(w, http.StatusCreated, d)
}

func (s *server) handleListKeys(w http.ResponseWriter, r *http.Request, _ string) {
	status := r.URL.Query().Get("status")
	var (
		rows pgx.Rows
		err  error
	)
	if status != "" {
		if !validStatuses[status] {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "unknown status filter")
			return
		}
		rows, err = s.pool.Query(r.Context(),
			`SELECT `+keyColumns+` FROM ssl_keys WHERE status = $1 ORDER BY created_at DESC`, status)
	} else {
		rows, err = s.pool.Query(r.Context(),
			`SELECT `+keyColumns+` FROM ssl_keys ORDER BY created_at DESC`)
	}
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	defer rows.Close()

	items := []KeySummary{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			writeAPIError(w, internalErr(err))
			return
		}
		items = append(items, k.summary())
	}
	if err := rows.Err(); err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (s *server) handleGetKey(w http.ResponseWriter, r *http.Request, _ string) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	k, err := s.getKey(r.Context(), id)
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	if k == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "key not found")
		return
	}
	writeJSON(w, http.StatusOK, k.detail())
}

func (s *server) handleGetPrivate(w http.ResponseWriter, r *http.Request, actor string) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	k, err := s.getKey(r.Context(), id)
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	if k == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "key not found")
		return
	}
	switch k.Status {
	case "CREATED", "READY_TO_PUBLISH", "ACTIVE":
	default:
		writeError(w, http.StatusConflict, "INVALID_STATE", "private key is not retrievable for "+k.Status+" keys")
		return
	}
	if k.PrivateKeyEnc == nil {
		writeAPIError(w, internalErr(errors.New("private_key_enc unexpectedly NULL")))
		return
	}
	plain, err := decryptPrivateKey(s.cfg.masterKey, k.ID, *k.PrivateKeyEnc)
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	if err := insertAudit(r.Context(), s.pool, k.ID, "PRIVATE_KEY_ACCESSED", actor, s.cfg.backendName, nil); err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": k.ID, "privateKeyPem": string(plain)})
}

func (s *server) handleCSR(w http.ResponseWriter, r *http.Request, actor string) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	k, err := s.getKey(r.Context(), id)
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	if k == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "key not found")
		return
	}
	switch k.Status {
	case "CREATED", "READY_TO_PUBLISH", "ACTIVE":
	default:
		writeError(w, http.StatusConflict, "INVALID_STATE", "CSR generation is not allowed for "+k.Status+" keys")
		return
	}

	var body struct {
		Subject csrSubject `json:"subject"`
		Sans    []string   `json:"sans"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "malformed JSON body")
		return
	}
	if strings.TrimSpace(body.Subject.CommonName) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "subject.commonName is required")
		return
	}
	if k.PrivateKeyEnc == nil {
		writeAPIError(w, internalErr(errors.New("private_key_enc unexpectedly NULL")))
		return
	}
	privPEM, err := decryptPrivateKey(s.cfg.masterKey, k.ID, *k.PrivateKeyEnc)
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	csrPEM, subjectStr, err := buildCSR(privPEM, k.Algorithm, body.Subject, body.Sans)
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}

	detailMap := map[string]any{"subject": subjectStr}
	if len(body.Sans) > 0 {
		detailMap["sans"] = body.Sans
	}
	detail, _ := json.Marshal(detailMap)
	if err := insertAudit(r.Context(), s.pool, k.ID, "CSR_ISSUED", actor, s.cfg.backendName, detail); err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"csrPem": csrPEM})
}

func (s *server) handleUploadCertificate(w http.ResponseWriter, r *http.Request, actor string) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	k, err := s.getKey(r.Context(), id)
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	if k == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "key not found")
		return
	}
	// SPEC §4.4 step 1: status gate comes before any PEM inspection.
	if k.Status != "CREATED" && k.Status != "READY_TO_PUBLISH" {
		writeError(w, http.StatusConflict, "INVALID_STATE", "certificate upload is not allowed for "+k.Status+" keys")
		return
	}

	var body struct {
		CertificateChainPem string `json:"certificateChainPem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.CertificateChainPem) == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "certificateChainPem is required")
		return
	}
	storedSPKI, err := spkiFromPublicPEM(k.PublicKeyPEM)
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}

	certs, vErr := validateChain(body.CertificateChainPem, storedSPKI, time.Now())
	if vErr != nil {
		// SPEC §4.4: audit CERTIFICATE_REJECTED for validation failures (steps 3–6).
		if vErr.status == http.StatusUnprocessableEntity {
			detail, _ := json.Marshal(map[string]string{"reason": vErr.code})
			if err := insertAudit(r.Context(), s.pool, k.ID, "CERTIFICATE_REJECTED", actor, s.cfg.backendName, detail); err != nil {
				writeAPIError(w, internalErr(err))
				return
			}
		}
		writeAPIError(w, vErr)
		return
	}

	leaf := certs[0]
	subject := leaf.Subject.String()
	issuer := leaf.Issuer.String()
	serial := leaf.SerialNumber.String() // Go's canonical decimal representation
	detail, _ := json.Marshal(map[string]string{"subject": subject, "serialNumber": serial})

	sqlText := `UPDATE ssl_keys SET status = 'READY_TO_PUBLISH', certificate_chain_pem = $2,
		cert_subject = $3, cert_issuer = $4, cert_serial = $5,
		cert_not_before = $6, cert_not_after = $7, updated_at = now()
		WHERE id = $1 AND status IN ('CREATED', 'READY_TO_PUBLISH') RETURNING ` + keyColumns
	updated, aerr := s.mutateKeyTx(r.Context(), id, sqlText,
		[]any{id, body.CertificateChainPem, subject, issuer, serial, leaf.NotBefore, leaf.NotAfter},
		"CERTIFICATE_UPLOADED", actor, detail)
	if aerr != nil {
		writeAPIError(w, aerr)
		return
	}
	writeJSON(w, http.StatusOK, updated.detail())
}

func (s *server) handleActivate(w http.ResponseWriter, r *http.Request, actor string) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	sqlText := `UPDATE ssl_keys SET status = 'ACTIVE', updated_at = now()
		WHERE id = $1 AND status = 'READY_TO_PUBLISH' RETURNING ` + keyColumns
	k, aerr := s.mutateKeyTx(r.Context(), id, sqlText, []any{id}, "ACTIVATED", actor, nil)
	if aerr != nil {
		writeAPIError(w, aerr)
		return
	}
	writeJSON(w, http.StatusOK, k.detail())
}

func (s *server) handleCompromise(w http.ResponseWriter, r *http.Request, actor string) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	var reason *string
	if len(bytes.TrimSpace(raw)) > 0 {
		var body struct {
			Reason *string `json:"reason"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "malformed JSON body")
			return
		}
		reason = body.Reason
	}
	var detail []byte
	if reason != nil {
		detail, _ = json.Marshal(map[string]string{"reason": *reason})
	}
	sqlText := `UPDATE ssl_keys SET status = 'COMPROMISED', compromised_reason = $2, updated_at = now()
		WHERE id = $1 AND status IN ('CREATED', 'READY_TO_PUBLISH', 'ACTIVE') RETURNING ` + keyColumns
	k, aerr := s.mutateKeyTx(r.Context(), id, sqlText, []any{id, reason}, "COMPROMISED", actor, detail)
	if aerr != nil {
		writeAPIError(w, aerr)
		return
	}
	writeJSON(w, http.StatusOK, k.detail())
}

func (s *server) handleDeleteKey(w http.ResponseWriter, r *http.Request, actor string) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	sqlText := `UPDATE ssl_keys SET status = 'DELETED', private_key_enc = NULL, updated_at = now()
		WHERE id = $1 AND status IN ('CREATED', 'READY_TO_PUBLISH', 'ACTIVE') RETURNING ` + keyColumns
	if _, aerr := s.mutateKeyTx(r.Context(), id, sqlText, []any{id}, "DELETED", actor, nil); aerr != nil {
		writeAPIError(w, aerr)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleAudit(w http.ResponseWriter, r *http.Request, _ string) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	k, err := s.getKey(r.Context(), id)
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	if k == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "key not found")
		return
	}
	rows, err := s.pool.Query(r.Context(),
		`SELECT id, key_id::text, event_type, actor, backend, detail, occurred_at
		 FROM key_audit_events WHERE key_id = $1 ORDER BY occurred_at ASC, id ASC`, id)
	if err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	defer rows.Close()

	items := []AuditEvent{}
	for rows.Next() {
		var (
			ev         AuditEvent
			detail     []byte
			occurredAt time.Time
		)
		if err := rows.Scan(&ev.ID, &ev.KeyID, &ev.EventType, &ev.Actor, &ev.Backend, &detail, &occurredAt); err != nil {
			writeAPIError(w, internalErr(err))
			return
		}
		ev.Detail = detail // nil marshals as JSON null
		ev.OccurredAt = iso(occurredAt)
		items = append(items, ev)
	}
	if err := rows.Err(); err != nil {
		writeAPIError(w, internalErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
