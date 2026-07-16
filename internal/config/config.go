package config

import (
	"os"
	"strings"
)

type Config struct {
	Port                 string
	JWTSecret            string
	AdminAPIKey          string
	BackendURL           string
	DukanProFrontendURL  string
	FrontendURL          string
	AllowedOrigins       []string
	DatabaseURL          string
	MockTenantID         string
	MockTenantName       string
}

func Load() Config {
	frontendURL := getenv("FRONTEND_URL", "http://localhost:3000")
	allowed := []string{frontendURL}
	if extra := os.Getenv("ALLOWED_ORIGINS"); extra != "" {
		for _, origin := range strings.Split(extra, ",") {
			origin = strings.TrimSpace(origin)
			if origin != "" {
				allowed = append(allowed, origin)
			}
		}
	}

	dukanURL := getenv("DUKAN_PRO_FRONTEND_URL", getenv("DUKAN_PRO_URL", "http://localhost:3001"))
	if !contains(allowed, dukanURL) {
		allowed = append(allowed, dukanURL)
	}

	return Config{
		Port:                getenv("PORT", "8080"),
		JWTSecret:           getenv("JWT_SECRET", "super-secret-poc-signing-key-2026"),
		AdminAPIKey:         os.Getenv("ADMIN_API_KEY"),
		BackendURL:          strings.TrimRight(getenv("BACKEND_URL", "http://localhost:8080"), "/"),
		DukanProFrontendURL: strings.TrimRight(dukanURL, "/"),
		FrontendURL:         strings.TrimRight(frontendURL, "/"),
		AllowedOrigins:      allowed,
		DatabaseURL:         getenv("DATABASE_URL", "postgres://saml:saml@postgres:5432/saml?sslmode=disable"),
		MockTenantID:        os.Getenv("MOCK_TENANT_ID"),
		MockTenantName:      os.Getenv("MOCK_TENANT_NAME"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
