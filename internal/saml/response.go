package samlpkg

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

// SAMLResponseXML returns the decoded SAMLResponse POST body as XML text.
func SAMLResponseXML(r *http.Request) (string, error) {
	raw := r.PostFormValue("SamlResponse")
	if raw == "" {
		raw = r.PostFormValue("SAMLResponse")
	}
	if raw == "" {
		return "", fmt.Errorf("missing SAMLResponse")
	}

	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("decode saml response: %w", err)
	}

	return string(decoded), nil
}
