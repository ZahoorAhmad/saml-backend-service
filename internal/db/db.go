package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

const migrationSQL = `
CREATE TABLE IF NOT EXISTS saml_settings (
    tenant_id VARCHAR(255) PRIMARY KEY,
    idp_entry_point TEXT NOT NULL,
    idp_issuer TEXT NOT NULL,
    idp_cert TEXT NOT NULL,
    sp_entity_id TEXT NOT NULL,
    attribute_email VARCHAR(100) DEFAULT 'email',
    attribute_roles VARCHAR(100) DEFAULT 'roles',
    is_active BOOLEAN DEFAULT TRUE,
    allowed_domains TEXT[] NOT NULL DEFAULT '{}',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS saml_users (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    roles TEXT NOT NULL DEFAULT '',
    last_login_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, email)
);

CREATE INDEX IF NOT EXISTS idx_saml_users_tenant_id ON saml_users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_saml_users_email ON saml_users (email);

ALTER TABLE saml_settings
    ADD COLUMN IF NOT EXISTS allowed_domains TEXT[] NOT NULL DEFAULT '{}';

UPDATE saml_settings
SET allowed_domains = ARRAY[tenant_id]
WHERE cardinality(allowed_domains) = 0;
`

type DB struct {
	*sql.DB
}

func Connect(databaseURL string) (*DB, error) {
	conn, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	conn.SetMaxOpenConns(10)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	for i := 0; i < 30; i++ {
		if err := conn.PingContext(ctx); err == nil {
			break
		}
		time.Sleep(time.Second)
		if i == 29 {
			return nil, fmt.Errorf("ping database: %w", err)
		}
	}

	if _, err := conn.ExecContext(ctx, migrationSQL); err != nil {
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	return &DB{DB: conn}, nil
}
