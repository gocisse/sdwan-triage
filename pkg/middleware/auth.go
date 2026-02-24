// Package middleware provides Gin middleware for JWT-based authentication.
// Tokens are HMAC-SHA256 signed with a per-instance secret generated at startup.

package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/pkg/database"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// TokenExpiry is the default JWT lifetime.
	TokenExpiry = 24 * time.Hour

	// ContextKeyUser is the Gin context key for the authenticated user.
	ContextKeyUser = "auth_user"

	// ContextKeyUserID is the Gin context key for the user ID.
	ContextKeyUserID = "auth_user_id"

	// ContextKeyRole is the Gin context key for the user role.
	ContextKeyRole = "auth_role"
)

// Claims defines the JWT payload.
type Claims struct {
	UserID   int64             `json:"uid"`
	Username string            `json:"sub"`
	Role     database.UserRole `json:"role"`
	jwt.RegisteredClaims
}

// AuthConfig holds the authentication configuration.
type AuthConfig struct {
	Secret []byte
	DB     *database.DB
}

// NewAuthConfig creates a new auth config with a cryptographically random secret.
func NewAuthConfig(db *database.DB) *AuthConfig {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		// Fallback — should never happen
		secret = []byte("sdwan-triage-fallback-secret-change-me")
	}
	return &AuthConfig{
		Secret: secret,
		DB:     db,
	}
}

// GenerateToken creates a signed JWT for the given user.
func (ac *AuthConfig) GenerateToken(user *database.User) (string, time.Time, error) {
	expiresAt := time.Now().Add(TokenExpiry)

	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.Username,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Issuer:    "sdwan-triage",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(ac.Secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}
	return signed, expiresAt, nil
}

// ValidateToken parses and validates a JWT string.
func (ac *AuthConfig) ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return ac.Secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// RequireAuth returns a Gin middleware that validates JWT tokens.
// Requests without a valid token receive 401 Unauthorized.
func (ac *AuthConfig) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenStr string

		// 1. Try Authorization header first
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
				tokenStr = parts[1]
			}
		}

		// 2. Fall back to ?token= query param (required for WebSocket — browsers
		//    cannot send custom headers on the WS upgrade request)
		if tokenStr == "" {
			tokenStr = c.Query("token")
		}

		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			return
		}

		claims, err := ac.ValidateToken(tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			return
		}

		// Verify user still exists and is active
		user, err := ac.DB.GetUserByID(claims.UserID)
		if err != nil || !user.IsActive {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "User account is disabled or deleted",
			})
			return
		}

		// Store user info in context for downstream handlers
		c.Set(ContextKeyUser, user.Username)
		c.Set(ContextKeyUserID, user.ID)
		c.Set(ContextKeyRole, string(user.Role))

		c.Next()
	}
}

// RequireRole returns middleware that checks the user has one of the allowed roles.
// Must be used after RequireAuth.
func RequireRole(allowed ...database.UserRole) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleStr, exists := c.Get(ContextKeyRole)
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Access denied",
			})
			return
		}

		role := database.UserRole(roleStr.(string))
		for _, a := range allowed {
			if role == a {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "Insufficient permissions",
		})
	}
}

// GenerateSecretHex returns a hex-encoded random secret (utility for config files).
func GenerateSecretHex() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
