package models

import "time"

type SAMLSettings struct {
	TenantID       string    `json:"tenant_id"`
	AllowedDomains []string  `json:"allowed_domains"`
	IdpEntryPoint  string    `json:"idp_entry_point"`
	IdpIssuer      string    `json:"idp_issuer"`
	IdpCert        string    `json:"idp_cert,omitempty"`
	SPEntityID     string    `json:"sp_entity_id"`
	AttributeEmail string    `json:"attribute_email"`
	AttributeRoles string    `json:"attribute_roles"`
	IsActive       bool      `json:"is_active"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type SAMLSettingsPublic struct {
	TenantID       string    `json:"tenant_id"`
	AllowedDomains []string  `json:"allowed_domains"`
	IdpEntryPoint  string    `json:"idp_entry_point"`
	IdpIssuer      string    `json:"idp_issuer"`
	IdpCertMasked  string    `json:"idp_cert_masked"`
	SPEntityID     string    `json:"sp_entity_id"`
	AttributeEmail string    `json:"attribute_email"`
	AttributeRoles string    `json:"attribute_roles"`
	IsActive       bool      `json:"is_active"`
	UpdatedAt      time.Time `json:"updated_at"`
	ACSURL         string    `json:"acs_url"`
	MetadataURL    string    `json:"metadata_url"`
	LoginURL       string    `json:"login_url"`
}

type SaveSAMLConfigRequest struct {
	TenantID       string   `json:"tenant_id"`
	AllowedDomains []string `json:"allowed_domains"`
	IdpEntryPoint  string   `json:"idp_entry_point"`
	IdpIssuer      string   `json:"idp_issuer"`
	IdpCert        string   `json:"idp_cert"`
	SPEntityID     string   `json:"sp_entity_id"`
	AttributeEmail string   `json:"attribute_email"`
	AttributeRoles string   `json:"attribute_roles"`
	IsActive       *bool    `json:"is_active"`
}

func (s SAMLSettings) ToPublic(backendURL string) SAMLSettingsPublic {
	return SAMLSettingsPublic{
		TenantID:       s.TenantID,
		AllowedDomains: s.AllowedDomains,
		IdpEntryPoint:  s.IdpEntryPoint,
		IdpIssuer:      s.IdpIssuer,
		IdpCertMasked:  maskCertificate(s.IdpCert),
		SPEntityID:     s.SPEntityID,
		AttributeEmail: s.AttributeEmail,
		AttributeRoles: s.AttributeRoles,
		IsActive:       s.IsActive,
		UpdatedAt:      s.UpdatedAt,
		ACSURL:         backendURL + "/api/saml/acs/" + s.TenantID,
		MetadataURL:    backendURL + "/api/saml/metadata/" + s.TenantID,
		LoginURL:       backendURL + "/api/v1/auth/sso/" + s.TenantID + "/login",
	}
}

func maskCertificate(cert string) string {
	trimmed := cert
	if len(trimmed) <= 12 {
		return "****"
	}
	return "****" + trimmed[len(trimmed)-8:]
}
