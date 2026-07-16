package samlpkg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"saml-backend-service/internal/models"
)

type Provider struct {
	backendURL string
	key        *rsa.PrivateKey
	cert       *x509.Certificate
}

func NewProvider(backendURL string) (*Provider, error) {
	key, cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}

	return &Provider{
		backendURL: strings.TrimRight(backendURL, "/"),
		key:        key,
		cert:       cert,
	}, nil
}

func (p *Provider) Metadata(settings *models.SAMLSettings) ([]byte, error) {
	sp, err := p.serviceProvider(settings, settings.SPEntityID)
	if err != nil {
		return nil, err
	}
	return xml.MarshalIndent(sp.Metadata(), "", "  ")
}

func (p *Provider) LoginURL(settings *models.SAMLSettings, relayState string, forceAuthn bool) (string, string, error) {
	sp, err := p.serviceProvider(settings, settings.SPEntityID)
	if err != nil {
		return "", "", err
	}
	if forceAuthn {
		force := true
		sp.ForceAuthn = &force
	}

	authnRequest, err := sp.MakeAuthenticationRequest(
		settings.IdpEntryPoint,
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return "", "", fmt.Errorf("create authn request: %w", err)
	}

	redirectURL, err := authnRequest.Redirect(relayState, sp)
	if err != nil {
		return "", "", fmt.Errorf("redirect authn request: %w", err)
	}
	return redirectURL.String(), authnRequest.ID, nil
}

func (p *Provider) ParseACS(settings *models.SAMLSettings, r *http.Request, possibleRequestIDs []string) (email string, roles []string, err error) {
	var lastErr error
	for _, audience := range p.allowedAudiences(settings) {
		sp, err := p.serviceProvider(settings, audience)
		if err != nil {
			return "", nil, err
		}

		assertion, err := sp.ParseResponse(r, possibleRequestIDs)
		if err == nil {
			return extractAssertionIdentity(assertion, settings)
		}

		lastErr = err
		if !isAudienceRestrictionError(err) {
			return "", nil, fmt.Errorf("parse saml response: %w", err)
		}
	}

	if lastErr != nil {
		log.Printf(
			"SAML audience mismatch for tenant %s: expected one of %v, assertion audiences=%v",
			settings.TenantID,
			p.allowedAudiences(settings),
			audiencesFromRequest(r),
		)
		return "", nil, fmt.Errorf("parse saml response: %w", lastErr)
	}

	return "", nil, fmt.Errorf("parse saml response: no valid audience configured")
}

func extractAssertionIdentity(assertion *saml.Assertion, settings *models.SAMLSettings) (string, []string, error) {
	emailAttr := defaultString(settings.AttributeEmail, "email")
	rolesAttr := defaultString(settings.AttributeRoles, "roles")

	email := firstAttribute(assertion, emailAttr)
	if email == "" {
		email = assertion.Subject.NameID.Value
	}
	if email == "" {
		return "", nil, fmt.Errorf("email attribute not found")
	}

	roles := attributeValues(assertion, rolesAttr)
	return email, roles, nil
}

func (p *Provider) allowedAudiences(settings *models.SAMLSettings) []string {
	tenantID := settings.TenantID
	candidates := []string{
		settings.SPEntityID,
		p.backendURL + "/api/saml/metadata/" + tenantID,
		p.backendURL + "/saml/" + tenantID,
		p.backendURL + "/api/saml/acs/" + tenantID,
	}

	seen := make(map[string]struct{}, len(candidates))
	audiences := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		audiences = append(audiences, candidate)
	}
	return audiences
}

func isAudienceRestrictionError(err error) bool {
	var invalid *saml.InvalidResponseError
	if errors.As(err, &invalid) && invalid.PrivateErr != nil {
		return strings.Contains(invalid.PrivateErr.Error(), "AudienceRestriction")
	}
	return strings.Contains(err.Error(), "AudienceRestriction")
}

var audienceValuePattern = regexp.MustCompile(`<(?:saml:)?Audience[^>]*>([^<]+)</(?:saml:)?Audience>`)

func audiencesFromRequest(r *http.Request) []string {
	rawResponse := r.PostFormValue("SAMLResponse")
	if rawResponse == "" {
		return nil
	}

	decoded, err := base64.StdEncoding.DecodeString(rawResponse)
	if err != nil {
		return nil
	}

	matches := audienceValuePattern.FindAllStringSubmatch(string(decoded), -1)
	audiences := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		value := strings.TrimSpace(match[1])
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		audiences = append(audiences, value)
	}
	return audiences
}

func (p *Provider) serviceProvider(settings *models.SAMLSettings, entityID string) (*saml.ServiceProvider, error) {
	acsURL, err := url.Parse(p.backendURL + "/api/saml/acs/" + settings.TenantID)
	if err != nil {
		return nil, err
	}

	metadataURL, err := url.Parse(p.backendURL + "/api/saml/metadata/" + settings.TenantID)
	if err != nil {
		return nil, err
	}

	entityID = strings.TrimSpace(entityID)
	if entityID == "" {
		entityID = settings.SPEntityID
	}

	idpCert, err := parseCertificate(settings.IdpCert)
	if err != nil {
		return nil, err
	}

	idpMetadata := &saml.EntityDescriptor{
		EntityID: settings.IdpIssuer,
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []saml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{Data: base64.StdEncoding.EncodeToString(idpCert.Raw)},
										},
									},
								},
							},
						},
					},
				},
				SingleSignOnServices: []saml.Endpoint{
					{Binding: saml.HTTPRedirectBinding, Location: settings.IdpEntryPoint},
					{Binding: saml.HTTPPostBinding, Location: settings.IdpEntryPoint},
				},
			},
		},
	}

	return &saml.ServiceProvider{
		EntityID:          entityID,
		Key:               p.key,
		Certificate:       p.cert,
		MetadataURL:       *metadataURL,
		AcsURL:            *acsURL,
		AuthnNameIDFormat: saml.EmailAddressNameIDFormat,
		SignatureMethod:   dsig.RSASHA256SignatureMethod,
		AllowIDPInitiated: true,
		IDPMetadata:       idpMetadata,
	}, nil
}

func firstAttribute(assertion *saml.Assertion, name string) string {
	values := attributeValues(assertion, name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func attributeValues(assertion *saml.Assertion, name string) []string {
	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			if !attributeMatches(attr, name) {
				continue
			}
			values := make([]string, 0, len(attr.Values))
			for _, value := range attr.Values {
				if value.Value != "" {
					values = append(values, value.Value)
				}
			}
			return values
		}
	}
	return nil
}

func attributeMatches(attr saml.Attribute, name string) bool {
	if attr.Name == name || attr.FriendlyName == name {
		return true
	}
	return strings.HasSuffix(attr.Name, ":"+name)
}

func parseCertificate(pemOrBase64 string) (*x509.Certificate, error) {
	trimmed := strings.TrimSpace(pemOrBase64)
	if !strings.Contains(trimmed, "BEGIN CERTIFICATE") {
		trimmed = wrapPEM(trimmed)
	}

	block, _ := pem.Decode([]byte(trimmed))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func wrapPEM(raw string) string {
	raw = strings.ReplaceAll(raw, " ", "")
	raw = strings.ReplaceAll(raw, "\n", "")
	return "-----BEGIN CERTIFICATE-----\n" + raw + "\n-----END CERTIFICATE-----\n"
}

func generateSelfSignedCert() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"SAML Backend Service"},
			CommonName:   "saml-backend-sp",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
