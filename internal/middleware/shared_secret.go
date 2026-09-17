package middleware

import (
	"armss-gateway/backend/internal/shared"

	"github.com/gin-gonic/gin"
)

// RequireHeaderSecret is a simple shared-secret check — a deterrent against
// random internet traffic, not a cryptographic boundary (the secret ships
// inside the mis_desktop app/installer, same tradeoff as TrustAppClient).
// Used by both the installer OTP gate and the portal-admin endpoints, each
// with their own secret value.
func RequireHeaderSecret(header, expected string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader(header) != expected {
			shared.SendUnauthorized(c, "invalid or missing "+header)
			c.Abort()
			return
		}
		c.Next()
	}
}
