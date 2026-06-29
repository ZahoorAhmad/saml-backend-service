# SAML Backend Service - Multi-Tenant POC

A production-ready Go backend service implementing SAML 2.0 Service Provider (SP) with multi-tenant support, domain discovery, and Just-In-Time (JIT) user provisioning.

## 🏗 Architecture

### Core Components

- **Language**: Go 1.23+
- **Router**: Native `net/http`
- **Database**: In-memory thread-safe store with `sync.RWMutex`
- **Authentication**: SAML 2.0 + JWT (HS256)
- **JWT Lifetime**: 1 hour

### Data Models

#### SamlConnection
Represents a tenant's SAML configuration:
```go
type SamlConnection struct {
    ID              string    // UUID
    Name            string    // Tenant name
    IdpEntityID     string    // IdP identifier
    IdpSSOURL       string    // IdP login endpoint
    IdpCertificate  string    // X.509 PEM certificate
    AllowedDomains  []string  // Email domains allowed for this tenant
    EntityID        string    // Service Provider Entity ID
    ACSUrl          string    // Assertion Consumer Service URL
    CreatedAt       time.Time
}
```

#### User
Represents a provisioned SAML user:
```go
type User struct {
    ID               string    // UUID
    Email            string    // User's email
    Name             string    // User's display name
    AccountType      string    // Always "saml"
    SamlConnectionID string    // Associated tenant
    CreatedAt        time.Time // Account creation time
    LastLogin        time.Time // Most recent login
}
```

## 🔗 API Endpoints

### 1. Domain Discovery

**Endpoint:** `GET /api/v1/saml/connections/lookup?domain=company.com`

**Description:** Unauthenticated endpoint for email-based tenant discovery.

**Query Parameters:**
- `domain`: Email domain suffix (e.g., "company.com")

**Success Response (200):**
```json
{
  "found": true,
  "connection_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_name": "Acme Inc",
  "sso_endpoint": "http://localhost:8080/api/v1/saml/login/550e8400-e29b-41d4-a716-446655440000"
}
```

**Not Found Response (404):**
```json
{
  "found": false,
  "error": "No SSO configuration found for this domain"
}
```

### 2. Create SAML Connection

**Endpoint:** `POST /api/v1/saml/connections`

**Request Body:**
```json
{
  "name": "Acme Inc",
  "idp_entity_id": "https://idp.example.com",
  "idp_sso_url": "https://idp.example.com/sso",
  "idp_certificate": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
  "allowed_domains": ["acme.com", "example.com"]
}
```

**Success Response (201):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Acme Inc",
  "idp_entity_id": "https://idp.example.com",
  "idp_sso_url": "https://idp.example.com/sso",
  "allowed_domains": ["acme.com"],
  "entity_id": "http://localhost:8080/saml/Acme Inc",
  "acs_url": "http://localhost:8080/api/v1/saml/acs/Acme Inc",
  "created_at": "2024-01-01T00:00:00Z"
}
```

### 3. Initiate SAML Login

**Endpoint:** `GET /api/v1/saml/login/{connection_id}`

**Description:** Initiates SP-initiated SAML authentication flow.

**Action:**
1. Generates SAML AuthnRequest XML
2. Base64-encodes and packages request
3. Generates RelayState token
4. Redirects browser to IdP SSO URL

**Response:** HTTP 302 redirect to IdP

### 4. SAML Assertion Consumer Service (ACS)

**Endpoint:** `POST /api/v1/saml/acs/{connection_id}`

**Description:** Receives and validates SAML response from IdP.

**Request Body:** `application/x-www-form-urlencoded`
```
SAMLResponse=<base64-encoded-xml>&RelayState=<relay-state>
```

**Processing Steps:**
1. ✅ Decode Base64 SAML Response
2. ✅ Validate XML signature (2-minute clock skew)
3. ✅ Extract email and name attributes
4. ✅ Validate email domain against `AllowedDomains`
5. ✅ **JIT Provisioning**: Create user if not exists, else update last_login
6. ✅ Generate JWT token (HS256)
7. ✅ Redirect to frontend with token

**Success Response:** HTTP 302 redirect
```
Location: http://localhost:3000/dashboard?token=eyJhbGc...
```

**Validation Errors:**
- Missing SAML Response → 400 Bad Request
- Signature validation fails → 401 Unauthorized
- Domain not allowed → 401 Unauthorized
- Connection not found → 404 Not Found

### 5. Service Provider Metadata

**Endpoint:** `GET /api/v1/saml/metadata/{connection_id}`

**Description:** Returns XML Service Provider metadata (used to configure IdP).

**Response:** `application/xml`
```xml
<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://localhost:8080/saml/...">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8080/api/v1/saml/acs/..." isDefault="true" index="0" />
  </SPSSODescriptor>
</EntityDescriptor>
```

### 6. Token Validation

**Endpoint:** `GET /api/v1/auth/validate`

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Success Response (200):**
```json
{
  "valid": true,
  "user": {
    "id": "user-uuid",
    "email": "john@company.com",
    "name": "John Doe",
    "account_type": "saml",
    "saml_connection_id": "connection-uuid"
  }
}
```

**Failure Response (401):**
```
Invalid token
```

## 🔄 Authentication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     SAML Authentication Flow                     │
└─────────────────────────────────────────────────────────────────┘

1. USER INITIATES
   └─ Frontend: Email input (user@company.com)

2. DOMAIN DISCOVERY
   └─ GET /api/v1/saml/connections/lookup?domain=company.com
   └─ Backend returns: connection_id + sso_endpoint

3. SSO INITIATION
   └─ Redirect: GET /api/v1/saml/login/{connection_id}
   └─ Backend:
      • Generates AuthnRequest XML
      • Base64-encodes request
      • Generates RelayState token
      • Redirects to IdP SSO URL

4. IDP AUTHENTICATION
   └─ User authenticates at IdP (Okta, Azure, etc.)
   └─ IdP verifies credentials
   └─ IdP generates SAML Response

5. ACS CALLBACK
   └─ IdP POSTs SAML Response to: POST /api/v1/saml/acs/{connection_id}
   └─ Backend validates:
      • XML signature
      • Clock skew (±2 minutes)
      • Email domain in AllowedDomains

6. JIT PROVISIONING
   └─ Check if user exists (connectionID:email key)
   └─ If NOT EXISTS:
      • Create new User record
      • Set CreatedAt = NOW
      • Log provisioning event
   └─ If EXISTS:
      • Update LastLogin = NOW

7. JWT ISSUANCE
   └─ Generate JWT token:
      • Claim: sub = user_id
      • Claim: email
      • Claim: name
      • Claim: account_type = "saml"
      • Claim: saml_connection_id
      • Signing: HS256 + JWT_SECRET
      • Expiration: +1 hour

8. REDIRECT TO FRONTEND
   └─ HTTP 302 redirect:
   └─ Location: http://localhost:3000/dashboard?token={JWT}

9. FRONTEND TOKEN STORAGE
   └─ Frontend extracts token from URL
   └─ Stores in localStorage
   └─ Clears URL query parameters
   └─ Renders dashboard with user info
```

## 🌐 Just-In-Time (JIT) Provisioning

When a SAML response arrives at the ACS endpoint:

```go
// Simplified logic:
if user NOT EXISTS with (connection_id, email) {
    // CREATE NEW USER
    new_user := User{
        ID: UUID(),
        Email: extracted_from_saml,
        Name: extracted_from_saml,
        AccountType: "saml",
        SamlConnectionID: connection_id,
        CreatedAt: NOW,
        LastLogin: NOW,
    }
    store.users[connection_id + ":" + email] = new_user
    log("JIT Provisioned:", email)
} else {
    // UPDATE EXISTING USER
    existing_user.LastLogin = NOW
    existing_user.Name = extracted_from_saml  // Refresh attributes
}
```

**Benefits:**
- ✅ Zero friction onboarding
- ✅ No manual user management needed
- ✅ Automatic attribute synchronization
- ✅ Supports unlimited users per tenant

## 🚀 Quick Start

### Prerequisites

- Go 1.23+
- Docker (optional)

### Installation

```bash
# Clone repository
git clone https://github.com/ZahoorAhmad/saml-backend-service.git
cd saml-backend-service

# Install dependencies
go mod download

# Run locally
go run ./cmd/server
```

### Docker

```bash
# Build image
docker build -t saml-backend:latest .

# Run container
docker run -p 8080:8080 \
  -e JWT_SECRET="your-secret-key" \
  -e FRONTEND_URL="http://localhost:3000" \
  -e MOCK_TENANT_DOMAIN="dev-tenant.com" \
  -e MOCK_TENANT_NAME="Development" \
  saml-backend:latest
```

### Environment Variables

```bash
JWT_SECRET=super-secret-poc-signing-key-2026          # JWT signing key
FRONTEND_URL=http://localhost:3000                     # Frontend origin for CORS
PORT=8080                                               # Server port
MOCK_TENANT_DOMAIN=dev-tenant.com                       # Mock tenant domain
MOCK_TENANT_NAME=Development Workspace                 # Mock tenant name
```

## 🧪 Testing

### 1. Test Domain Discovery

```bash
curl -X GET "http://localhost:8080/api/v1/saml/connections/lookup?domain=dev-tenant.com"
```

### 2. Create New Connection

```bash
curl -X POST http://localhost:8080/api/v1/saml/connections \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Okta Test",
    "idp_entity_id": "https://okta.example.com",
    "idp_sso_url": "https://okta.example.com/sso",
    "idp_certificate": "-----BEGIN CERTIFICATE-----...",
    "allowed_domains": ["example.com"]
  }'
```

### 3. Get SP Metadata

```bash
curl -X GET http://localhost:8080/api/v1/saml/metadata/{connection_id}
```

### 4. Validate Token

```bash
curl -X GET http://localhost:8080/api/v1/auth/validate \
  -H "Authorization: Bearer {jwt_token}"
```

## 📋 License

MIT
