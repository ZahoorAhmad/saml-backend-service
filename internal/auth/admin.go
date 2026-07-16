package auth

import (
	"net/http"
	"strings"
)

func AdminMiddleware(adminAPIKey string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if adminAPIKey == "" {
			http.Error(w, "Admin API is not configured", http.StatusServiceUnavailable)
			return
		}

		if !hasAdminRole(r, adminAPIKey) {
			http.Error(w, "Admin role required", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

func hasAdminRole(r *http.Request, adminAPIKey string) bool {
	if key := strings.TrimSpace(r.Header.Get("X-Admin-Key")); key != "" && key == adminAPIKey {
		return true
	}

	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		return token == adminAPIKey
	}

	role := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Admin-Role")))
	return role == "admin" && strings.TrimSpace(r.Header.Get("X-Admin-Key")) == adminAPIKey
}
