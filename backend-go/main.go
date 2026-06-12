// Certificate Management Service — Go backend (port 8082).
// Implements SPEC.md exactly against the shared PostgreSQL schema.
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
)

type config struct {
	port         string
	jwtSecret    []byte
	jwtIssuer    string
	jwtTTL       int
	authClientID string
	authSecret   string
	masterKey    []byte
	backendName  string
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadConfig() (config, error) {
	cfg := config{
		port:         env("PORT", "8082"),
		jwtIssuer:    env("JWT_ISSUER", "cert-mgmt"),
		authClientID: env("AUTH_CLIENT_ID", "admin"),
		backendName:  env("BACKEND_NAME", "go"),
	}
	ttl, err := strconv.Atoi(env("JWT_TTL_SECONDS", "900"))
	if err != nil {
		return cfg, fmt.Errorf("JWT_TTL_SECONDS: %w", err)
	}
	cfg.jwtTTL = ttl
	secret := os.Getenv("JWT_SECRET")
	if len(secret) < 32 {
		return cfg, fmt.Errorf("JWT_SECRET is required (>=32 bytes)")
	}
	cfg.jwtSecret = []byte(secret)
	cfg.authSecret = os.Getenv("AUTH_CLIENT_SECRET")
	if cfg.authSecret == "" {
		return cfg, fmt.Errorf("AUTH_CLIENT_SECRET is required")
	}
	mk, err := base64.StdEncoding.DecodeString(os.Getenv("MASTER_KEY_B64"))
	if err != nil || len(mk) != 32 {
		return cfg, fmt.Errorf("MASTER_KEY_B64 must be base64 of exactly 32 bytes")
	}
	cfg.masterKey = mk
	return cfg, nil
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	dsn := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s",
		env("PGHOST", "localhost"), env("PGPORT", "5434"), env("PGDATABASE", "certmgr"),
		env("PGUSER", "certmgr"), env("PGPASSWORD", "certmgr"))
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()

	s := &server{pool: pool, cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /api/v1/auth/token", s.handleToken)
	mux.HandleFunc("POST /api/v1/keys", s.auth(s.handleCreateKey))
	mux.HandleFunc("GET /api/v1/keys", s.auth(s.handleListKeys))
	mux.HandleFunc("GET /api/v1/keys/{id}", s.auth(s.handleGetKey))
	mux.HandleFunc("DELETE /api/v1/keys/{id}", s.auth(s.handleDeleteKey))
	mux.HandleFunc("GET /api/v1/keys/{id}/private", s.auth(s.handleGetPrivate))
	mux.HandleFunc("POST /api/v1/keys/{id}/csr", s.auth(s.handleCSR))
	mux.HandleFunc("POST /api/v1/keys/{id}/certificate", s.auth(s.handleUploadCertificate))
	mux.HandleFunc("POST /api/v1/keys/{id}/activate", s.auth(s.handleActivate))
	mux.HandleFunc("POST /api/v1/keys/{id}/compromise", s.auth(s.handleCompromise))
	mux.HandleFunc("GET /api/v1/keys/{id}/audit", s.auth(s.handleAudit))

	addr := ":" + cfg.port
	log.Printf("cert-management backend %q listening on %s", cfg.backendName, addr)
	log.Fatal(http.ListenAndServe(addr, corsMiddleware(mux)))
}
