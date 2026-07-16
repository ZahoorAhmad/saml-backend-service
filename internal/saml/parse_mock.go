package samlpkg

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"saml-backend-service/internal/models"
)

func ParseMockResponse(r *http.Request, settings *models.SAMLSettings) (string, []string, error) {
	samlResponse := r.PostFormValue("SAMLResponse")
	if samlResponse == "" {
		return "", nil, fmt.Errorf("missing SAMLResponse")
	}

	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return "", nil, fmt.Errorf("decode saml response: %w", err)
	}

	response := string(decoded)
	email := extractAttribute(response, settings.AttributeEmail)
	if email == "" {
		email = extractNameID(response)
	}
	if email == "" {
		return "", nil, fmt.Errorf("email not found in mock assertion")
	}

	roles := extractAttributeValues(response, settings.AttributeRoles)
	return email, roles, nil
}

func extractNameID(response string) string {
	start := strings.Index(response, "<saml:NameID>")
	if start == -1 {
		return ""
	}
	start += len("<saml:NameID>")
	end := strings.Index(response[start:], "</saml:NameID>")
	if end == -1 {
		return ""
	}
	return response[start : start+end]
}

func extractAttribute(response, name string) string {
	values := extractAttributeValues(response, name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func extractAttributeValues(response, name string) []string {
	marker := fmt.Sprintf(`Name="%s"`, name)
	start := strings.Index(response, marker)
	if start == -1 {
		return nil
	}

	segment := response[start:]
	values := make([]string, 0)
	searchFrom := 0
	for {
		valueStart := strings.Index(segment[searchFrom:], "<saml:AttributeValue>")
		if valueStart == -1 {
			break
		}
		valueStart += searchFrom + len("<saml:AttributeValue>")
		valueEnd := strings.Index(segment[valueStart:], "</saml:AttributeValue>")
		if valueEnd == -1 {
			break
		}
		values = append(values, segment[valueStart:valueStart+valueEnd])
		searchFrom = valueStart + valueEnd
	}
	return values
}
