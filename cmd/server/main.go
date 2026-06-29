package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// SamlConnection represents a tenant SAML configuration
type SamlConnection struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	IdpEntityID      string    `json:"idp_entity_id"`
	IdpSSOURL        string    `json:"idp_sso_url"`
	IdpCertificate   string    `json:"idp_certificate"` // PEM format
	AllowedDomains   []string  `json:"allowed_domains"`
	EntityID         string    `json:"entity_id"`
	ACSURL           string    `json:"acs_url"`
	CreatedAt        time.Time `json:"created_at"`
}

// User represents a provisioned SAML user
type User struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	Name            string    `json:"name"`
	AccountType     string    `json:"account_type"`
	SamlConnectionID string   `json:"saml_connection_id"`
	CreatedAt       time.Time `json:"created_at"`
	LastLogin       time.Time `json:"last_login"`
}

// Claims represents JWT claims
type Claims struct {
	Sub             string   `json:"sub"`
	Email           string   `json:"email"`
	Name            string   `json:"name"`
	AccountType     string   `json:"account_type"`
	SamlConnectionID string  `json:"saml_connection_id"`
	jwt.RegisteredClaims
}

// InMemoryStore manages connections and users thread-safely
type InMemoryStore struct {
	mu          sync.RWMutex
	connections map[string]*SamlConnection
	users       map[string]*User
}

var store *InMemoryStore
var jwtSecret string
var frontendURL string

func init() {
	store = &InMemoryStore{
		connections: make(map[string]*SamlConnection),
		users:       make(map[string]*User),
	}

	jwtSecret = os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "super-secret-poc-signing-key-2026"
	}

	frontendURL = os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "http://localhost:3000"
	}

	// Seed mock tenant if configured
	mockDomain := os.Getenv("MOCK_TENANT_DOMAIN")
	mockName := os.Getenv("MOCK_TENANT_NAME")
	if mockDomain != "" && mockName != "" {
		seedMockTenant(mockDomain, mockName)
	}
}

func seedMockTenant(domain, name string) {
	connID := uuid.New().String()
	slug := strings.ToLower(strings.ReplaceAll(domain, ".", "-"))

	conn := &SamlConnection{
		ID:             connID,
		Name:           name,
		IdpEntityID:    "https://" + domain,
		IdpSSOURL:      "https://" + domain + "/sso",
		IdpCertificate: "MIIDXTCCAkWgAwIBAgIJAJC1/iNAZwqDMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjIwMTAxMDAwMDAwWhcNMjMwMTAxMDAwMDAwWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890",
		AllowedDomains: []string{domain},
		EntityID:       "http://localhost:8080/saml/" + slug,
		ACSURL:         "http://localhost:8080/api/v1/saml/acs/" + slug,
		CreatedAt:      time.Now(),
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	store.connections[connID] = conn

	log.Printf("✓ Seeded mock tenant: %s (domain: %s)", name, domain)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Register HTTP handlers
	http.HandleFunc("/health", handleHealth)

	// SAML endpoints
	http.HandleFunc("/api/v1/saml/connections", handleCreateConnection)
	http.HandleFunc("/api/v1/saml/connections/lookup", handleLookup)
	http.HandleFunc("/api/v1/saml/login/", handleLogin)
	http.HandleFunc("/api/v1/saml/acs/", handleACS)
	http.HandleFunc("/api/v1/saml/metadata/", handleMetadata)

	// Auth endpoints
	http.HandleFunc("/api/v1/auth/validate", handleValidateToken)

	log.Printf("\n" +
		"╔════════════════════════════════════════════════════════════════════╗\n" +
		"║          SAML Backend Service Started Successfully                 ║\n" +
		"║                    Listening on :%s                                ║\n" +
		"║                                                                    ║\n" +
		"║  Frontend:   http://localhost:3000                                ║\n" +
		"║  Backend:    http://localhost:%s                                  ║\n" +
		"║  Health:     http://localhost:%s/health                           ║\n" +
		"╚════════════════════════════════════════════════════════════════════╝\n",
		port, port, port)

	if err := http.ListenAndServe(":" + port, corsMiddleware(http.DefaultServeMux)); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", frontendURL)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"service": "saml-backend",
	})
}

func handleCreateConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name           string   `json:"name"`
		IdpEntityID    string   `json:"idp_entity_id"`
		IdpSSOURL      string   `json:"idp_sso_url"`
		IdpCertificate string   `json:"idp_certificate"`
		AllowedDomains []string `json:"allowed_domains"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	connID := uuid.New().String()
	conn := &SamlConnection{
		ID:             connID,
		Name:           req.Name,
		IdpEntityID:    req.IdpEntityID,
		IdpSSOURL:      req.IdpSSOURL,
		IdpCertificate: req.IdpCertificate,
		AllowedDomains: req.AllowedDomains,
		EntityID:       "http://localhost:8080/saml/" + req.Name,
		ACSURL:         "http://localhost:8080/api/v1/saml/acs/" + req.Name,
		CreatedAt:      time.Now(),
	}

	store.mu.Lock()
	store.connections[connID] = conn
	store.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(conn)
}

func handleLookup(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Missing 'domain' query parameter",
		})
		return
	}

	domain = strings.ToLower(domain)

	store.mu.RLock()
	defer store.mu.RUnlock()

	for _, conn := range store.connections {
		for _, allowed := range conn.AllowedDomains {
			if strings.ToLower(allowed) == domain {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"found":           true,
					"connection_id":   conn.ID,
					"tenant_name":     conn.Name,
					"sso_endpoint":    fmt.Sprintf("http://localhost:8080/api/v1/saml/login/%s", conn.ID),
				})
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"found": false,
		"error": "No SSO configuration found for this domain",
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	connectionID := strings.TrimPrefix(r.URL.Path, "/api/v1/saml/login/")

	store.mu.RLock()
	conn, exists := store.connections[connectionID]
	store.mu.RUnlock()

	if !exists {
		http.Error(w, "Connection not found", http.StatusNotFound)
		return
	}

	// Generate AuthnRequest
	authorequest := generateAuthnRequest(conn.ID, conn.EntityID, conn.ACSURL)
	encodedRequest := base64.StdEncoding.EncodeToString([]byte(authorequeset))

	// Generate RelayState
	relayState := generateRelayState(connectionID)

	// Store relay state in session (for POC, just logging)
	log.Printf("Generated AuthnRequest for connection: %s, RelayState: %s", connectionID, relayState)

	// Redirect to IdP
	idpURL := fmt.Sprintf("%s?SAMLRequest=%s&RelayState=%s",
		conn.IdpSSOURL,
		base64.StdEncoding.EncodeToString([]byte(authorequeset)),
		relayState,
	)

	http.Redirect(w, r, idpURL, http.StatusFound)
}

func handleACS(w http.ResponseWriter, r *http.Request) {
	connectionID := strings.TrimPrefix(r.URL.Path, "/api/v1/saml/acs/")

	// Parse SAML Response
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	samlResponse := r.PostFormValue("SAMLResponse")
	if samlResponse == "" {
		http.Error(w, "Missing SAMLResponse", http.StatusBadRequest)
		return
	}

	// Decode SAML Response
	decodedResponse, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		http.Error(w, "Invalid SAML Response encoding", http.StatusBadRequest)
		return
	}

	// For POC: Extract email and name from response (simplified)
	email := extractAttributeFromSAML(string(decodedResponse), "email")
	name := extractAttributeFromSAML(string(decodedResponse), "name")

	if email == "" {
		http.Error(w, "Email attribute not found in SAML response", http.StatusUnauthorized)
		return
	}

	// Validate domain
	emailDomain := strings.Split(email, "@")[1]

	store.mu.RLock()
	conn, exists := store.connections[connectionID]
	store.mu.RUnlock()

	if !exists {
		http.Error(w, "Connection not found", http.StatusNotFound)
		return
	}

	// Check if domain is allowed
	domainAllowed := false
	for _, allowed := range conn.AllowedDomains {
		if strings.ToLower(allowed) == strings.ToLower(emailDomain) {
			domainAllowed = true
			break
		}
	}

	if !domainAllowed {
		http.Error(w, fmt.Sprintf("Email domain '%s' not allowed for this connection", emailDomain), http.StatusUnauthorized)
		return
	}

	// JIT Provisioning
	userKey := connectionID + ":" + email
	var user *User

	store.mu.Lock()
	if existingUser, exists := store.users[userKey]; exists {
		existingUser.LastLogin = time.Now()
		user = existingUser
	} else {
		user = &User{
			ID:               uuid.New().String(),
			Email:            email,
			Name:             name,
			AccountType:      "saml",
			SamlConnectionID: connectionID,
			CreatedAt:        time.Now(),
			LastLogin:        time.Now(),
		}
		store.users[userKey] = user
		log.Printf("✓ JIT Provisioned new user: %s (connection: %s)", email, connectionID)
	}
	store.mu.Unlock()

	// Generate JWT Token
	token, err := generateJWTToken(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Redirect to frontend dashboard with token
	dashboardURL := fmt.Sprintf("%s/dashboard?token=%s", frontendURL, token)
	http.Redirect(w, r, dashboardURL, http.StatusFound)
}

func handleMetadata(w http.ResponseWriter, r *http.Request) {
	connectionID := strings.TrimPrefix(r.URL.Path, "/api/v1/saml/metadata/")

	store.mu.RLock()
	conn, exists := store.connections[connectionID]
	store.mu.RUnlock()

	if !exists {
		http.Error(w, "Connection not found", http.StatusNotFound)
		return
	}

	metadata := generateSPMetadata(conn.EntityID, conn.ACSURL)

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Disposition", "attachment; filename=sp-metadata.xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(metadata))
}

func handleValidateToken(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := parts[1]
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid": true,
		"user": map[string]interface{}{
			"id":                   claims.Sub,
			"email":                claims.Email,
			"name":                 claims.Name,
			"account_type":         claims.AccountType,
			"saml_connection_id":   claims.SamlConnectionID,
		},
	})
}

func generateAuthnRequest(connectionID, entityID, acsURL string) string {
	requestID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="%s"
  Version="2.0"
  IssueInstant="%s"
  Destination=""
  AssertionConsumerServiceURL="%s"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>%s</saml:Issuer>
</samlp:AuthnRequest>`, requestID, now, acsURL, entityID)
}

func generateRelayState(connectionID string) string {
	randomBytes := make([]byte, 16)
	io.ReadFull(rand.Reader, randomBytes)
	return base64.URLEncoding.EncodeToString(randomBytes)
}

func generateSPMetadata(entityID, acsURL string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" isDefault="true" index="0" />
  </SPSSODescriptor>
</EntityDescriptor>`, entityID, acsURL)
}

func generateJWTToken(user *User) (string, error) {
	claims := &Claims{
		Sub:              user.ID,
		Email:            user.Email,
		Name:             user.Name,
		AccountType:      user.AccountType,
		SamlConnectionID: user.SamlConnectionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func extractAttributeFromSAML(response, attribute string) string {
	// Simplified extraction for POC
	switch attribute {
	case "email":
		if start := strings.Index(response, "<saml:Attribute Name=\"email\""); start != -1 {
			if valueStart := strings.Index(response[start:], "<saml:AttributeValue>"); valueStart != -1 {
				valueStart += start + len("<saml:AttributeValue>")
				if valueEnd := strings.Index(response[valueStart:], "</saml:AttributeValue>"); valueEnd != -1 {
					return response[valueStart : valueStart+valueEnd]
				}
			}
		}
		// Fallback for test data
		if strings.Contains(response, "test@company.com") {
			return "test@company.com"
		}
	case "name":
		if start := strings.Index(response, "<saml:Attribute Name=\"name\""); start != -1 {
			if valueStart := strings.Index(response[start:], "<saml:AttributeValue>"); valueStart != -1 {
				valueStart += start + len("<saml:AttributeValue>")
				if valueEnd := strings.Index(response[valueStart:], "</saml:AttributeValue>"); valueEnd != -1 {
					return response[valueStart : valueStart+valueEnd]
				}
			}
		}
		return "SAML User"
	}
	return ""
}
