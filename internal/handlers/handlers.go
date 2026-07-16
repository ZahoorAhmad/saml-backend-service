package handlers

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"saml-backend-service/internal/auth"
	"saml-backend-service/internal/config"
	"saml-backend-service/internal/models"
	"saml-backend-service/internal/repository"
	samlpkg "saml-backend-service/internal/saml"
)

const (
	samlRequestCookiePrefix  = "saml_request_id_"
	samlLoginEmailCookiePref = "saml_login_email_"
)

type Handler struct {
	cfg        config.Config
	repo       *repository.SAMLRepository
	users      *repository.UserRepository
	saml       *samlpkg.Provider
	tokens     *auth.TokenService
}

func New(cfg config.Config, repo *repository.SAMLRepository, users *repository.UserRepository, provider *samlpkg.Provider, tokens *auth.TokenService) *Handler {
	return &Handler{
		cfg:    cfg,
		repo:   repo,
		users:  users,
		saml:   provider,
		tokens: tokens,
	}
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "saml-backend",
	})
}

func (h *Handler) Metadata(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantSlugFromPath(r.URL.Path)
	settings, err := h.loadActiveTenant(r, tenantID)
	if err != nil {
		writeError(w, err)
		return
	}

	metadata, err := h.saml.Metadata(settings)
	if err != nil {
		http.Error(w, "Failed to generate metadata", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Disposition", "attachment; filename=sp-metadata.xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(metadata)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantSlugFromPath(r.URL.Path)
	settings, err := h.loadActiveTenant(r, tenantID)
	if err != nil {
		writeError(w, err)
		return
	}

	// Optional: email entered at discovery. When present we bind ACS to this exact identity.
	requestedEmail := models.NormalizeEmail(r.URL.Query().Get("email"))
	if requestedEmail != "" {
		emailDomain, domainErr := models.EmailDomain(requestedEmail)
		if domainErr != nil || !models.DomainAllowed(emailDomain, settings.AllowedDomains) {
			http.Error(w, "Email domain is not authorized for this workspace", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     samlLoginEmailCookieName(tenantID),
			Value:    requestedEmail,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   300,
			SameSite: http.SameSiteLaxMode,
		})
	} else {
		clearSAMLLoginEmailCookie(w, tenantID)
	}

	relayState := strings.TrimSpace(r.URL.Query().Get("relay_state"))
	// Force re-auth when a specific email was requested so Okta cannot silently
	// reuse another user's existing IdP session for a different email attempt.
	forceAuthn := requestedEmail != ""
	loginURL, requestID, err := h.saml.LoginURL(settings, relayState, forceAuthn)
	if err != nil {
		http.Error(w, "Failed to initialize SAML login", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     samlRequestCookieName(tenantID),
		Value:    requestID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (h *Handler) ACS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantID := tenantSlugFromACSPath(r.URL.Path)
	settings, err := h.loadActiveTenant(r, tenantID)
	if err != nil {
		writeError(w, err)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse SAML response", http.StatusBadRequest)
		return
	}

	possibleRequestIDs := samlRequestIDsFromCookie(r, tenantID)
	requestedEmail := samlLoginEmailFromCookie(r, tenantID)
	clearSAMLRequestCookie(w, tenantID)
	clearSAMLLoginEmailCookie(w, tenantID)

	var email string
	var roles []string
	if strings.Contains(settings.IdpEntryPoint, "/api/saml/mock-idp/") {
		email, roles, err = samlpkg.ParseMockACS(settings, r)
	} else {
		email, roles, err = h.saml.ParseACS(settings, r, possibleRequestIDs)
	}
	if err != nil {
		logSAMLACSError(tenantID, err)
		http.Error(w, "SAML assertion validation failed", http.StatusUnauthorized)
		return
	}

	email = models.NormalizeEmail(email)
	emailDomain, domainErr := models.EmailDomain(email)
	if domainErr != nil || !models.DomainAllowed(emailDomain, settings.AllowedDomains) {
		log.Printf(
			"SAML ACS domain rejected: tenant_id=%s email=%s domain=%s allowed=%v",
			tenantID, email, emailDomain, settings.AllowedDomains,
		)
		http.Error(w, "Email domain is not authorized for this workspace", http.StatusUnauthorized)
		return
	}

	// Require Okta/IdP assertion email to match the email the user typed at discovery.
	// Prevents logging in as a different (or non-existent) address via an existing IdP session.
	if requestedEmail != "" && email != requestedEmail {
		log.Printf(
			"SAML ACS email mismatch: tenant_id=%s requested=%s asserted=%s",
			tenantID, requestedEmail, email,
		)
		http.Error(w, "Signed-in identity does not match the email you entered", http.StatusUnauthorized)
		return
	}

	log.Printf("SAML user decoded: tenant_id=%s email=%s domain=%s roles=%v", tenantID, email, emailDomain, roles)

	if xmlBody, xmlErr := samlpkg.SAMLResponseXML(r); xmlErr == nil {
		log.Printf("SAML response XML for tenant_id=%s:\n%s", tenantID, xmlBody)
	} else {
		log.Printf("SAML response XML unavailable for tenant_id=%s: %v", tenantID, xmlErr)
	}

	savedUser, err := h.users.UpsertLogin(r.Context(), tenantID, email, roles)
	if err != nil {
		log.Printf("failed to persist SAML user tenant_id=%s email=%s: %v", tenantID, email, err)
		http.Error(w, "Failed to persist authenticated user", http.StatusInternalServerError)
		return
	}
	log.Printf(
		"SAML user saved: id=%d tenant_id=%s email=%s roles=%v last_login_at=%s",
		savedUser.ID,
		savedUser.TenantID,
		savedUser.Email,
		savedUser.Roles,
		savedUser.LastLoginAt.Format(time.RFC3339),
	)

	token, err := h.tokens.Issue(email, roles, tenantID)
	if err != nil {
		http.Error(w, "Failed to issue session token", http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("%s/auth/callback?token=%s", h.cfg.DukanProFrontendURL, token)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *Handler) SaveConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req models.SaveSAMLConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" || strings.TrimSpace(req.IdpEntryPoint) == "" || strings.TrimSpace(req.IdpIssuer) == "" || strings.TrimSpace(req.IdpCert) == "" {
		http.Error(w, "tenant_id, idp_entry_point, idp_issuer, and idp_cert are required", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.SPEntityID) == "" {
		req.SPEntityID = h.cfg.BackendURL + "/saml/" + req.TenantID
	}

	req.AllowedDomains = models.NormalizeDomains(req.AllowedDomains)
	if len(req.AllowedDomains) == 0 {
		http.Error(w, "allowed_domains must include at least one corporate email domain", http.StatusBadRequest)
		return
	}

	settings, err := h.repo.Upsert(r.Context(), req)
	if err != nil {
		http.Error(w, "Failed to save SAML settings", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, settings.ToPublic(h.cfg.BackendURL))
}

func (h *Handler) GetConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantID := tenantFromPath(r.URL.Path, "/api/saml/config/")
	settings, err := h.repo.GetByTenantID(r.Context(), tenantID)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, settings.ToPublic(h.cfg.BackendURL))
}

func (h *Handler) DiscoverTenant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := models.NormalizeDomain(r.URL.Query().Get("domain"))
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing domain query parameter"})
		return
	}

	settings, err := h.repo.GetActiveByDomain(r.Context(), domain)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"found": false,
			"error": "No SSO configuration found for this domain",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"found":       true,
		"tenant_id":   settings.TenantID,
		"tenant_slug": settings.TenantID,
		"login_url":   h.cfg.BackendURL + "/api/v1/auth/sso/" + settings.TenantID + "/login",
	})
}

func (h *Handler) LookupTenant(w http.ResponseWriter, r *http.Request) {
	domain := models.NormalizeDomain(r.URL.Query().Get("domain"))
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing domain query parameter"})
		return
	}

	settings, err := h.repo.GetActiveByDomain(r.Context(), domain)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"found": false,
			"error": "No SSO configuration found for this domain",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"found":        true,
		"tenant_id":    settings.TenantID,
		"tenant_slug":  settings.TenantID,
		"tenant_name":  settings.TenantID,
		"sso_endpoint": h.cfg.BackendURL + "/api/v1/auth/sso/" + settings.TenantID + "/login",
		"metadata_url": h.cfg.BackendURL + "/api/saml/metadata/" + settings.TenantID,
	})
}

func (h *Handler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing bearer token", http.StatusUnauthorized)
		return
	}

	claims, err := h.tokens.Validate(strings.TrimPrefix(authHeader, "Bearer "))
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid": true,
		"user": map[string]interface{}{
			"email":    claims.Email,
			"roles":    claims.Roles,
			"tenantId": claims.TenantID,
		},
	})
}

func (h *Handler) loadActiveTenant(r *http.Request, tenantID string) (*models.SAMLSettings, error) {
	if tenantID == "" {
		return nil, repository.ErrNotFound
	}
	return h.repo.GetActiveByTenantID(r.Context(), tenantID)
}

// SSOV1Router dispatches v1 SSO paths: /api/v1/auth/sso/:tenant_slug/login|acs
func (h *Handler) SSOV1Router(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, "/login"):
		h.Login(w, r)
	case strings.HasSuffix(path, "/acs"):
		h.ACS(w, r)
	default:
		http.NotFound(w, r)
	}
}

func tenantFromPath(path, prefix string) string {
	return strings.Trim(strings.TrimPrefix(path, prefix), "/")
}

// tenantSlugFromPath resolves a tenant slug from legacy or v1 SSO login/metadata routes.
func tenantSlugFromPath(path string) string {
	for _, prefix := range []string{
		"/api/v1/auth/sso/",
		"/api/saml/login/",
		"/api/saml/metadata/",
	} {
		if strings.HasPrefix(path, prefix) {
			rest := strings.TrimPrefix(path, prefix)
			if strings.HasSuffix(rest, "/login") {
				return strings.TrimSuffix(rest, "/login")
			}
			if strings.HasSuffix(rest, "/metadata") {
				return strings.TrimSuffix(rest, "/metadata")
			}
			return strings.Trim(rest, "/")
		}
	}
	return ""
}

// tenantSlugFromACSPath resolves tenant slug from legacy or v1 ACS routes.
func tenantSlugFromACSPath(path string) string {
	if strings.HasPrefix(path, "/api/v1/auth/sso/") && strings.HasSuffix(path, "/acs") {
		rest := strings.TrimPrefix(path, "/api/v1/auth/sso/")
		return strings.TrimSuffix(rest, "/acs")
	}
	return tenantFromPath(path, "/api/saml/acs/")
}

func samlRequestCookieName(tenantID string) string {
	return samlRequestCookiePrefix + tenantID
}

func samlLoginEmailCookieName(tenantID string) string {
	return samlLoginEmailCookiePref + tenantID
}

func samlRequestIDsFromCookie(r *http.Request, tenantID string) []string {
	cookie, err := r.Cookie(samlRequestCookieName(tenantID))
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return nil
	}
	return []string{cookie.Value}
}

func samlLoginEmailFromCookie(r *http.Request, tenantID string) string {
	cookie, err := r.Cookie(samlLoginEmailCookieName(tenantID))
	if err != nil {
		return ""
	}
	return models.NormalizeEmail(cookie.Value)
}

func clearSAMLRequestCookie(w http.ResponseWriter, tenantID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     samlRequestCookieName(tenantID),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSAMLLoginEmailCookie(w http.ResponseWriter, tenantID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     samlLoginEmailCookieName(tenantID),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
}

func logSAMLACSError(tenantID string, err error) {
	var invalidResp *saml.InvalidResponseError
	if errors.As(err, &invalidResp) && invalidResp.PrivateErr != nil {
		log.Printf("SAML ACS validation failed for tenant %s: %v", tenantID, invalidResp.PrivateErr)
		return
	}
	log.Printf("SAML ACS validation failed for tenant %s: %v", tenantID, err)
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, err error) {
	if err == repository.ErrNotFound {
		http.Error(w, "Tenant SAML configuration not found", http.StatusNotFound)
		return
	}
	if err == repository.ErrInactive {
		http.Error(w, "Tenant SAML configuration is disabled. Enable SAML in admin settings.", http.StatusForbidden)
		return
	}
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

func CORSMiddleware(cfg config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowedOrigin := ""
		for _, candidate := range cfg.AllowedOrigins {
			if origin == candidate {
				allowedOrigin = origin
				break
			}
		}
		if allowedOrigin == "" && len(cfg.AllowedOrigins) > 0 {
			allowedOrigin = cfg.AllowedOrigins[0]
		}

		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Key, X-Admin-Role")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// MockIDP provides a local SAML IdP page for development tenants.
func (h *Handler) MockIDP(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromPath(r.URL.Path, "/api/saml/mock-idp/")
	settings, err := h.loadActiveTenant(r, tenantID)
	if err != nil {
		writeError(w, err)
		return
	}

	relayState := r.URL.Query().Get("RelayState")

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		email := strings.TrimSpace(r.FormValue("email"))
		if email == "" {
			email = "user@" + tenantID
		}
		roles := strings.TrimSpace(r.FormValue("roles"))
		if roles == "" {
			roles = "cashier,admin"
		}

		responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject><saml:NameID>%s</saml:NameID></saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="%s"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="%s"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`, xmlEscape(email), xmlEscape(settings.AttributeEmail), xmlEscape(email), xmlEscape(settings.AttributeRoles), xmlEscape(roles))

		encodedResponse := base64.StdEncoding.EncodeToString([]byte(responseXML))
		acsURL := h.cfg.BackendURL + "/api/saml/acs/" + tenantID
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(renderMockIdPAutoPostPage(acsURL, encodedResponse, relayState)))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(renderMockIdPLoginPage(tenantID)))
}

func xmlEscape(value string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}
