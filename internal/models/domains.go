package models

import (
	"fmt"
	"strings"
)

// NormalizeEmail lowercases and trims an email for exact identity matching.
func NormalizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}

// NormalizeDomain lowercases and trims a domain for consistent matching.
func NormalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimPrefix(domain, "@")
	return domain
}

// NormalizeDomains cleans and deduplicates a list of domains.
func NormalizeDomains(domains []string) []string {
	seen := make(map[string]struct{}, len(domains))
	out := make([]string, 0, len(domains))
	for _, raw := range domains {
		d := NormalizeDomain(raw)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

// EmailDomain extracts and normalizes the domain portion of an email address.
func EmailDomain(email string) (string, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return "", fmt.Errorf("invalid email address")
	}
	return NormalizeDomain(email[at+1:]), nil
}

// DomainAllowed reports whether emailDomain is listed in allowedDomains (case-insensitive).
func DomainAllowed(emailDomain string, allowedDomains []string) bool {
	emailDomain = NormalizeDomain(emailDomain)
	if emailDomain == "" {
		return false
	}
	for _, allowed := range allowedDomains {
		if NormalizeDomain(allowed) == emailDomain {
			return true
		}
	}
	return false
}
