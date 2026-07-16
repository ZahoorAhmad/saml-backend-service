package models

import (
	"strings"
	"time"
)

type SAMLUser struct {
	ID          int64     `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Email       string    `json:"email"`
	Roles       []string  `json:"roles"`
	LastLoginAt time.Time `json:"last_login_at"`
	CreatedAt   time.Time `json:"created_at"`
}

func RolesToStorage(roles []string) string {
	return strings.Join(roles, ",")
}

func RolesFromStorage(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	roles := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			roles = append(roles, part)
		}
	}
	return roles
}
