package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
	"saml-backend-service/internal/db"
	"saml-backend-service/internal/models"
)

var (
	ErrNotFound = errors.New("saml settings not found")
	ErrInactive = errors.New("saml settings inactive")
)

type SAMLRepository struct {
	db *db.DB
}

func NewSAMLRepository(database *db.DB) *SAMLRepository {
	return &SAMLRepository{db: database}
}

func (r *SAMLRepository) GetByTenantID(ctx context.Context, tenantID string) (*models.SAMLSettings, error) {
	const query = `
		SELECT tenant_id, idp_entry_point, idp_issuer, idp_cert, sp_entity_id,
		       attribute_email, attribute_roles, is_active, updated_at, allowed_domains
		FROM saml_settings
		WHERE tenant_id = $1`

	row := r.db.QueryRowContext(ctx, query, tenantID)
	settings, err := scanSettings(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return settings, err
}

func (r *SAMLRepository) GetActiveByTenantID(ctx context.Context, tenantID string) (*models.SAMLSettings, error) {
	settings, err := r.GetByTenantID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !settings.IsActive {
		return nil, ErrInactive
	}
	return settings, nil
}

// GetActiveByDomain finds an active tenant whose AllowedDomains contains the email domain.
func (r *SAMLRepository) GetActiveByDomain(ctx context.Context, domain string) (*models.SAMLSettings, error) {
	domain = models.NormalizeDomain(domain)
	if domain == "" {
		return nil, ErrNotFound
	}

	const query = `
		SELECT tenant_id, idp_entry_point, idp_issuer, idp_cert, sp_entity_id,
		       attribute_email, attribute_roles, is_active, updated_at, allowed_domains
		FROM saml_settings
		WHERE is_active = TRUE AND $1 = ANY(allowed_domains)
		ORDER BY updated_at DESC
		LIMIT 1`

	row := r.db.QueryRowContext(ctx, query, domain)
	settings, err := scanSettings(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return settings, err
}

func (r *SAMLRepository) Upsert(ctx context.Context, req models.SaveSAMLConfigRequest) (*models.SAMLSettings, error) {
	attributeEmail := defaultString(req.AttributeEmail, "email")
	attributeRoles := defaultString(req.AttributeRoles, "roles")
	existing, existingErr := r.GetByTenantID(ctx, req.TenantID)

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	} else if existingErr == nil {
		isActive = existing.IsActive
	}

	idpCert := strings.TrimSpace(req.IdpCert)
	if idpCert == "" && existingErr == nil {
		idpCert = existing.IdpCert
	}

	allowedDomains := models.NormalizeDomains(req.AllowedDomains)
	if len(allowedDomains) == 0 && existingErr == nil {
		allowedDomains = existing.AllowedDomains
	}
	if len(allowedDomains) == 0 {
		allowedDomains = []string{models.NormalizeDomain(req.TenantID)}
	}

	const query = `
		INSERT INTO saml_settings (
			tenant_id, idp_entry_point, idp_issuer, idp_cert, sp_entity_id,
			attribute_email, attribute_roles, is_active, allowed_domains, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
		ON CONFLICT (tenant_id) DO UPDATE SET
			idp_entry_point = EXCLUDED.idp_entry_point,
			idp_issuer = EXCLUDED.idp_issuer,
			idp_cert = EXCLUDED.idp_cert,
			sp_entity_id = EXCLUDED.sp_entity_id,
			attribute_email = EXCLUDED.attribute_email,
			attribute_roles = EXCLUDED.attribute_roles,
			is_active = EXCLUDED.is_active,
			allowed_domains = EXCLUDED.allowed_domains,
			updated_at = CURRENT_TIMESTAMP
		RETURNING tenant_id, idp_entry_point, idp_issuer, idp_cert, sp_entity_id,
		          attribute_email, attribute_roles, is_active, updated_at, allowed_domains`

	row := r.db.QueryRowContext(
		ctx,
		query,
		req.TenantID,
		req.IdpEntryPoint,
		req.IdpIssuer,
		idpCert,
		req.SPEntityID,
		attributeEmail,
		attributeRoles,
		isActive,
		pq.Array(allowedDomains),
	)

	return scanSettings(row)
}

func scanSettings(row interface {
	Scan(dest ...any) error
}) (*models.SAMLSettings, error) {
	var settings models.SAMLSettings
	var allowed pq.StringArray
	err := row.Scan(
		&settings.TenantID,
		&settings.IdpEntryPoint,
		&settings.IdpIssuer,
		&settings.IdpCert,
		&settings.SPEntityID,
		&settings.AttributeEmail,
		&settings.AttributeRoles,
		&settings.IsActive,
		&settings.UpdatedAt,
		&allowed,
	)
	if err != nil {
		return nil, fmt.Errorf("scan saml settings: %w", err)
	}
	settings.AllowedDomains = []string(allowed)
	return &settings, nil
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
