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
