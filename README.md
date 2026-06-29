# SAML 2.0 Multi-Tenant POC with Docker Compose

A production-ready Proof of Concept demonstrating **Domain Discovery (Email Routing)** and **Just-In-Time (JIT) User Provisioning** using a multi-container SAML 2.0 architecture.

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    SAML POC Architecture                     │
└─────────────────────────────────────────────────────────────┘

        USER BROWSER
              │
              ▼
     ┌────────────────┐
     │  Frontend App  │  (React/Vite + Nginx)
     │  :3000         │
     └────────┬───────┘
              │
              │ 1. Enter email: user@company.com
              │
              ▼
     ┌────────────────────────────────────────┐
     │  Backend Service                       │  (Go + Chi)
     │  :8080                                 │  :8080
     │                                        │
     │  GET /api/v1/saml/connections/lookup   │
     │      ?domain=company.com               │  2. Domain Discovery
     │         ↓                              │
     │  Returns: connection_id                │
     │         ↓                              │
     │  GET /api/v1/auth/sso/{id}/login       │  3. Initiate SSO
     │         ↓                              │
     │  Generates AuthnRequest                │
     │         ↓                              │
     │  Redirects to IdP                      │  4. Redirect to IdP
     └────────┬───────────────────────────────┘
              │
              ▼
     ┌────────────────────────┐
     │   External IdP         │
     │   (Okta/Azure/Okta)    │  5. User Authenticates
     │                        │
     │   SAML Response ──────┐│
     │                       ││
     └───────────────────────┘│
                              │
              6. POST SAML Response
              ▼
     ┌────────────────────────────────────────┐
     │  Backend Service                       │
     │  POST /api/v1/auth/sso/{id}/acs        │
     │      ↓                                 │
     │  Validate SAML Response                │
     │      ↓                                 │
     │  Extract: email, name, attributes     │  7. Extract Attributes
     │      ↓                                 │
     │  Domain Validation                     │  8. Validate Domain in
     │  (Check allowed_domains)               │     AllowedDomains
     │      ↓                                 │
     │  JIT Provisioning:                     │  9. Create/Update User
     │  Create or Update User                 │
     │      ↓                                 │
     │  Generate JWT Token                    │  10. Issue JWT
     │      ↓                                 │
     │  Redirect with Token:                  │
     │  /dashboard?token={JWT}                │
     └────────┬───────────────────────────────┘
              │
              ▼
     ┌────────────────────┐
     │  Frontend App      │
     │  /dashboard        │  11. User Authenticated
     │  (Token Stored)    │      Dashboard Ready
     └────────────────────┘
```

## 🚀 Quick Start with Docker Compose

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- Git

### Clone and Run

```bash
# Clone the main repository
git clone https://github.com/ZahoorAhmad/saml-poc-root.git
cd saml-poc-root

# Start both services
docker-compose up --build
```

The system will be ready at:
- **Frontend**: http://localhost:3000
- **Backend**: http://localhost:8080

## 📋 Service Configuration

### Environment Variables (docker-compose.yml)

**Backend Service:**
```yaml
PORT: "8080"
DATABASE_URL: "sqlite:///./saml_tenants.db"
JWT_SECRET: "super-secret-poc-signing-key-2026"
BASE_URL: "http://localhost:8080"
FRONTEND_URL: "http://localhost:3000"
MOCK_TENANT_DOMAIN: "dev-tenant.com"
MOCK_TENANT_NAME: "Default Workspace"
```

**Frontend Service:**
```yaml
VITE_API_BASE_URL: "http://localhost:8080"
VITE_FRONTEND_URL: "http://localhost:3000"
```

## 🔍 Domain Discovery Flow

### 1. User Enters Email
```
User enters: john@company.com
```

### 2. Frontend Extracts Domain
```javascript
const domain = email.split('@')[1]  // "company.com"
```

### 3. Call Domain Discovery Endpoint
```bash
GET /api/v1/saml/connections/lookup?domain=company.com

Response:
{
  "found": true,
  "connection_id": "acme-tenant-uuid",
  "tenant_name": "Acme Inc",
  "sso_endpoint": "http://localhost:8080/api/v1/auth/sso/acme/login"
}
```

### 4. Redirect to SSO Login
```javascript
window.location.href = response.data.sso_endpoint
```

## 🔐 SAML Response Validation Flow

### Backend ACS Endpoint Processing

```
1. POST /api/v1/auth/sso/{connection_id}/acs
   │
   ├─ Parse Form Data: SAMLResponse
   ├─ Base64 Decode SAML Response
   ├─ XML Parse & Signature Validation
   │   └─ Verify using tenant's x509 certificate
   ├─ Extract Attributes:
   │   ├─ Email (urn:oid:0.9.2342.19200300.100.1.3)
   │   ├─ Name (urn:oid:2.5.4.3)
   │   └─ Other custom attributes
   ├─ Extract Email Domain
   ├─ Domain Validation:
   │   ├─ Check if domain in AllowedDomains[]
   │   └─ Reject if not allowed
   ├─ JIT Provisioning:
   │   ├─ Check if user exists in memory
   │   ├─ If not: Create new user record
   │   └─ If yes: Update last_login timestamp
   ├─ Generate JWT Token:
   │   ├─ Claim: sub (user_id)
   │   ├─ Claim: email
   │   ├─ Claim: name
   │   ├─ Claim: roles (extracted from SAML)
   │   ├─ Claim: tenant_id
   │   └─ Signing: HS256 with JWT_SECRET
   └─ Redirect: /dashboard?token={JWT}
```

## 📊 Just-In-Time (JIT) Provisioning

### User Record Structure

```go
type ProvisionedUser struct {
    ID                  string                   // UUID
    Email               string                   // john@company.com
    Name                string                   // John Doe
    AccountType         string                   // "saml"
    SAMLConnectionID    string                   // Connection UUID
    Attributes          map[string][]string     // SAML attributes
    CreatedAt           time.Time                // First login
    LastLogin           time.Time                // Most recent login
    LastAttributeUpdate time.Time                // Last attribute sync
}
```

### Provisioning Logic

```
IF user NOT EXISTS WITH (email, connection_id):
    └─ CREATE new user record
        ├─ ID: Generate UUID
        ├─ Email: Extract from SAML
        ├─ Name: Extract from SAML
        ├─ CreatedAt: NOW()
        └─ LastLogin: NOW()
ELSE:
    └─ UPDATE existing user
        ├─ Name: Refresh from SAML
        ├─ Attributes: Refresh from SAML
        ├─ LastLogin: NOW()
        └─ LastAttributeUpdate: NOW()
```

## 🔑 API Endpoints

### Domain Discovery

```bash
GET /api/v1/saml/connections/lookup?domain=company.com

Response:
{
  "found": true,
  "connection_id": "tenant-uuid",
  "tenant_name": "Company Name",
  "sso_endpoint": "http://localhost:8080/api/v1/auth/sso/tenant-slug/login"
}
```

### SAML Metadata (for IdP Configuration)

```bash
GET /api/v1/auth/sso/{tenant_slug}/metadata

Returns: XML ServiceProvider Metadata
```

### Initiate SSO

```bash
GET /api/v1/auth/sso/{tenant_slug}/login

Action: Generates AuthnRequest and redirects to IdP
```

### Handle SAML Response (ACS)

```bash
POST /api/v1/auth/sso/{tenant_slug}/acs
Content-Type: application/x-www-form-urlencoded

Payload:
- SAMLResponse: [base64-encoded-xml]
- RelayState: [relay-state-value]

Action: Validates, provisions user, issues JWT
Redirect: /dashboard?token={JWT}
```

### Validate Token

```bash
GET /api/v1/auth/validate
Authorization: Bearer {jwt_token}

Response:
{
  "valid": true,
  "user": {
    "id": "user-uuid",
    "email": "john@company.com",
    "name": "John Doe",
    "roles": ["user"],
    "tenant_id": "connection-uuid"
  }
}
```

## 🧪 Testing Setup

### Option 1: Okta Free Developer Account

1. **Create Account**
   - Go to https://developer.okta.com
   - Sign up for free developer account
   - Verify email

2. **Create SAML App**
   - Navigate to: Applications → Applications → Create App
   - Choose: SAML 2.0
   - Configure:
     - **Single sign-on URL**: `http://localhost:8080/api/v1/auth/sso/okta-test/acs`
     - **Audience URI**: `http://localhost:8080/api/v1/auth/sso/okta-test`

3. **Configure Attributes** (Okta → Sign On → Edit SAML Configuration)
   - Attribute Statements:
     - `email` = `user.email`
     - `name` = `user.firstName + " " + user.lastName`

4. **Get IdP Metadata**
   - Find the metadata URL or download XML
   - Format: `https://{your-okta-domain}/app/{app-id}/sso/saml/metadata`

5. **Create Backend Tenant**
   ```bash
   curl -X POST http://localhost:8080/api/v1/tenants \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Okta Test",
       "slug": "okta-test",
       "idp_metadata_url": "https://your-okta-domain/app/xxx/sso/saml/metadata",
       "idp_entity_id": "https://your-okta-domain",
       "target_redirect_url": "http://localhost:3000/dashboard"
     }'
   ```

6. **Test Login**
   - Visit http://localhost:3000
   - Enter email: `{your-okta-user}@{your-okta-domain}`
   - You'll be redirected to Okta login
   - After authentication, JWT will be issued

### Option 2: MockSAML.com

1. **Download SP Metadata**
   ```bash
   curl http://localhost:8080/api/v1/auth/sso/test/metadata > sp-metadata.xml
   ```

2. **Upload to MockSAML**
   - Go to https://www.mocksaml.com
   - Click "Upload Metadata"
   - Upload the `sp-metadata.xml` file
   - MockSAML will generate IdP metadata

3. **Configure Backend**
   - Get IdP metadata URL from MockSAML (usually shows on upload page)
   - Create tenant with this metadata

4. **Test Login**
   - Visit http://localhost:3000
   - Enter any email: `test@company.com`
   - Follow SAML flow through MockSAML
   - Receive JWT on successful auth

## 📁 Project Structure

```
saml-poc-root/
├── docker-compose.yml              # Central orchestration
├── README.md                       # This file
│
├── saml-backend-service/           # Go Backend
│   ├── Dockerfile
│   ├── cmd/
│   │   └── server/
│   │       └── main.go
│   ├── internal/
│   │   ├── config/
│   │   │   └── config.go
│   │   ├── db/
│   │   │   ├── db.go
│   │   │   ├── models.go
│   │   │   ├── tenant.go
│   │   │   └── user.go
│   │   ├── handler/
│   │   │   ├── tenant.go
│   │   │   ├── saml.go
│   │   │   ├── auth.go
│   │   │   ├── discovery.go
│   │   │   └── middleware.go
│   │   ├── saml/
│   │   │   ├── sp.go
│   │   │   ├── validator.go
│   │   │   ├── metadata.go
│   │   │   ├── domain.go
│   │   │   └── jit.go
│   │   └── jwt/
│   │       └── token.go
│   ├── go.mod
│   ├── go.sum
│   └── README.md
│
└── saml-frontend-app/              # React Frontend
    ├── Dockerfile
    ├── nginx.conf
    ├── src/
    │   ├── components/
    │   │   ├── TenantLogin.tsx
    │   │   ├── AdminDashboard.tsx
    │   │   ├── AppDashboard.tsx
    │   │   ├── ProtectedRoute.tsx
    │   │   └── Layout.tsx
    │   ├── context/
    │   │   └── AuthContext.tsx
    │   ├── services/
    │   │   └── api.ts
    │   ├── utils/
    │   │   └── jwt.ts
    │   ├── App.tsx
    │   ├── index.css
    │   └── main.tsx
    ├── package.json
    ├── vite.config.ts
    ├── tsconfig.json
    └── README.md
```

## 🛑 Troubleshooting

### Backend Won't Start

```bash
# Check logs
docker-compose logs backend

# Common issues:
# 1. Port 8080 already in use
#    Solution: Change PORT env var in docker-compose.yml
# 2. Database permission error
#    Solution: Remove ./saml_tenants.db and restart
```

### Frontend Can't Connect to Backend

```bash
# Check CORS
# Ensure VITE_API_BASE_URL matches backend URL
docker-compose logs frontend

# Test connectivity
curl http://localhost:8080/health
```

### SAML Response Validation Fails

```
Issues:
1. IdP certificate mismatch
   → Verify certificate in tenant config
2. Domain not in allowed list
   → Add domain to tenant configuration
3. Clock skew > 2 minutes
   → Sync container clocks
```

## 🔒 Security Considerations

✅ **Implemented:**
- SAML signature validation
- JWT token expiration (1 hour)
- HttpOnly cookies
- CORS protection
- Domain-based validation

⚠️ **Production Checklist:**
- [ ] Use HTTPS/TLS (not HTTP)
- [ ] Rotate JWT_SECRET regularly
- [ ] Enable SAML assertion encryption
- [ ] Store secrets in secure vault (AWS Secrets Manager, etc.)
- [ ] Implement rate limiting
- [ ] Add audit logging
- [ ] Enable CSRF tokens
- [ ] Use persistent database (PostgreSQL)

## 📝 License

MIT

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Submit pull request

## 📧 Support

For issues or questions:
- Open GitHub Issue
- Check troubleshooting section above
- Review endpoint documentation
