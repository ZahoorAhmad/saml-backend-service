package samlpkg

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"saml-backend-service/internal/models"
)

func ParseMockACS(settings *models.SAMLSettings, r *http.Request) (string, []string, error) {
	if err := r.ParseForm(); err != nil {
		return "", nil, err
	}

	rawResponse := r.PostFormValue("SAMLResponse")
	if rawResponse == "" {
		return "", nil, fmt.Errorf("missing SAMLResponse")
	}

	decoded, err := base64.StdEncoding.DecodeString(rawResponse)
	if err != nil {
		return "", nil, fmt.Errorf("decode saml response: %w", err)
	}

	emailAttr := defaultString(settings.AttributeEmail, "email")
	rolesAttr := defaultString(settings.AttributeRoles, "roles")

	email := extractXMLAttribute(string(decoded), emailAttr)
	if email == "" {
		email = extractXMLValue(string(decoded), "NameID")
	}
	if email == "" {
		return "", nil, fmt.Errorf("email not found in mock assertion")
	}

	rolesRaw := extractXMLAttribute(string(decoded), rolesAttr)
	roles := strings.FieldsFunc(rolesRaw, func(r rune) bool {
		return r == ',' || r == ';'
	})

	return email, roles, nil
}

func extractXMLAttribute(xmlBody, name string) string {
	patterns := []string{
		fmt.Sprintf(`Name="%s"`, name),
		fmt.Sprintf(`Name="%s"`, strings.ToLower(name)),
	}
	for _, pattern := range patterns {
		idx := strings.Index(xmlBody, pattern)
		if idx == -1 {
			continue
		}
		fragment := xmlBody[idx:]
		start := strings.Index(fragment, "<saml:AttributeValue>")
		if start == -1 {
			start = strings.Index(fragment, "<AttributeValue>")
		}
		if start == -1 {
			continue
		}
		fragment = fragment[start:]
		fragment = strings.TrimPrefix(fragment, "<saml:AttributeValue>")
		fragment = strings.TrimPrefix(fragment, "<AttributeValue>")
		fragment = strings.TrimPrefix(fragment, ">")
		end := strings.Index(fragment, "</")
		if end == -1 {
			continue
		}
		return strings.TrimSpace(fragment[:end])
	}
	return ""
}

func extractXMLValue(xmlBody, tag string) string {
	decoder := xml.NewDecoder(strings.NewReader(xmlBody))
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if start, ok := token.(xml.StartElement); ok {
			if strings.HasSuffix(start.Name.Local, tag) {
				var value string
				_ = decoder.DecodeElement(&value, &start)
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}
