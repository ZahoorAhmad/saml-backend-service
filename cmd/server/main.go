package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"time"

	"saml-backend-service/internal/auth"
	"saml-backend-service/internal/config"
	"saml-backend-service/internal/db"
	"saml-backend-service/internal/handlers"
	"saml-backend-service/internal/models"
	"saml-backend-service/internal/repository"
	samlpkg "saml-backend-service/internal/saml"
)

func main() {
	cfg := config.Load()

	database, err := db.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer database.Close()

	repo := repository.NewSAMLRepository(database)
	userRepo := repository.NewUserRepository(database)
	if err := seedMockTenant(context.Background(), repo, cfg); err != nil {
		log.Printf("warning: failed to seed mock tenant: %v", err)
	}

	provider, err := samlpkg.NewProvider(cfg.BackendURL)
	if err != nil {
		log.Fatalf("failed to initialize SAML provider: %v", err)
	}

	tokenService := auth.NewTokenService(cfg.JWTSecret)
	h := handlers.New(cfg, repo, userRepo, provider, tokenService)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.Health)
	mux.HandleFunc("/api/saml/metadata/", h.Metadata)
	mux.HandleFunc("/api/saml/login/", h.Login)
	mux.HandleFunc("/api/saml/acs/", h.ACS)
	mux.HandleFunc("/api/saml/mock-idp/", h.MockIDP)
	mux.HandleFunc("/api/saml/lookup", h.LookupTenant)
	mux.HandleFunc("/api/v1/auth/discover", h.DiscoverTenant)
	mux.HandleFunc("/api/v1/auth/validate", h.ValidateToken)
	mux.HandleFunc("/api/saml/config", auth.AdminMiddleware(cfg.AdminAPIKey, h.SaveConfig))
	mux.HandleFunc("/api/saml/config/", auth.AdminMiddleware(cfg.AdminAPIKey, h.GetConfig))

	// v1 SSO route aliases (login + ACS per tenant slug)
	mux.HandleFunc("/api/v1/auth/sso/", h.SSOV1Router)

	// Legacy aliases for existing frontends
	mux.HandleFunc("/api/v1/saml/connections/lookup", h.LookupTenant)

	log.Printf("SAML backend listening on :%s", cfg.Port)
	log.Printf("Dukaan Pro callback: %s/auth/callback", cfg.DukanProFrontendURL)
	if err := http.ListenAndServe(":"+cfg.Port, handlers.CORSMiddleware(cfg, mux)); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func seedMockTenant(ctx context.Context, repo *repository.SAMLRepository, cfg config.Config) error {
	tenantID := cfg.MockTenantID
	if tenantID == "" {
		tenantID = "dev-tenant.com"
	}

	mockCert, err := generateMockIDPCert()
	if err != nil {
		return err
	}

	isActive := true
	_, err = repo.Upsert(ctx, models.SaveSAMLConfigRequest{
		TenantID:       tenantID,
		AllowedDomains: []string{tenantID},
		IdpEntryPoint:  cfg.BackendURL + "/api/saml/mock-idp/" + tenantID,
		IdpIssuer:      cfg.BackendURL + "/api/saml/mock-idp/" + tenantID,
		IdpCert:        mockCert,
		SPEntityID:     cfg.BackendURL + "/saml/" + tenantID,
		AttributeEmail: "email",
		AttributeRoles: "roles",
		IsActive:       &isActive,
	})
	if err != nil {
		return err
	}

	log.Printf("seeded SAML tenant %s", tenantID)
	return nil
}

func generateMockIDPCert() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
