ALTER TABLE saml_settings
    ADD COLUMN IF NOT EXISTS allowed_domains TEXT[] NOT NULL DEFAULT '{}';

UPDATE saml_settings
SET allowed_domains = ARRAY[tenant_id]
WHERE cardinality(allowed_domains) = 0;
