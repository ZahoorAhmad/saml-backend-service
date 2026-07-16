package repository

import (
	"context"
	"fmt"
	"strings"

	"saml-backend-service/internal/db"
	"saml-backend-service/internal/models"
)

type UserRepository struct {
	db *db.DB
}

func NewUserRepository(database *db.DB) *UserRepository {
	return &UserRepository{db: database}
}

func (r *UserRepository) UpsertLogin(ctx context.Context, tenantID, email string, roles []string) (*models.SAMLUser, error) {
	tenantID = strings.TrimSpace(tenantID)
	email = strings.TrimSpace(email)
	if tenantID == "" || email == "" {
		return nil, fmt.Errorf("tenant_id and email are required")
	}

	const query = `
		INSERT INTO saml_users (tenant_id, email, roles, last_login_at, created_at)
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT (tenant_id, email) DO UPDATE SET
			roles = EXCLUDED.roles,
			last_login_at = CURRENT_TIMESTAMP
		RETURNING id, tenant_id, email, roles, last_login_at, created_at`

	row := r.db.QueryRowContext(ctx, query, tenantID, email, models.RolesToStorage(roles))
	return scanSAMLUser(row)
}

func scanSAMLUser(row interface {
	Scan(dest ...any) error
}) (*models.SAMLUser, error) {
	var user models.SAMLUser
	var rolesRaw string
	err := row.Scan(
		&user.ID,
		&user.TenantID,
		&user.Email,
		&rolesRaw,
		&user.LastLoginAt,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan saml user: %w", err)
	}
	user.Roles = models.RolesFromStorage(rolesRaw)
	return &user, nil
}
