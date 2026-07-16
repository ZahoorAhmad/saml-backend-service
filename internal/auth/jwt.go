package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenClaims struct {
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	TenantID string   `json:"tenantId"`
	jwt.RegisteredClaims
}

type TokenService struct {
	secret []byte
	ttl    time.Duration
}

func NewTokenService(secret string) *TokenService {
	return &TokenService{
		secret: []byte(secret),
		ttl:    time.Hour,
	}
}

func (s *TokenService) Issue(email string, roles []string, tenantID string) (string, error) {
	now := time.Now()
	claims := TokenClaims{
		Email:    email,
		Roles:    roles,
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

func (s *TokenService) Validate(tokenString string) (*TokenClaims, error) {
	claims := &TokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.secret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func ParseRoles(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}

	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';'
	})

	roles := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			roles = append(roles, part)
		}
	}
	return roles
}
