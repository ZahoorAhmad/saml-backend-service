CREATE TABLE IF NOT EXISTS saml_settings (
    tenant_id VARCHAR(255) PRIMARY KEY,
    idp_entry_point TEXT NOT NULL,
    idp_issuer TEXT NOT NULL,
    idp_cert TEXT NOT NULL,
    sp_entity_id TEXT NOT NULL,
    attribute_email VARCHAR(100) DEFAULT 'email',
    attribute_roles VARCHAR(100) DEFAULT 'roles',
    is_active BOOLEAN DEFAULT TRUE,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
