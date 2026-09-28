package middleware

import (
	"fmt"

	"armss-gateway/backend/internal/database"
	"armss-gateway/backend/internal/models"
	"armss-gateway/backend/internal/shared"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type PortalClaims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// RequirePortalToken gates routes that need a logged-in portal user (e.g.
// GET /me). Enforces single active session per user account.
func RequirePortalToken(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("X-Portal-Token")
		if tokenString == "" {
			shared.SendUnauthorized(c, "missing X-Portal-Token")
			c.Abort()
			return
		}

		claims := &PortalClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			shared.SendUnauthorized(c, "invalid or expired portal token")
			c.Abort()
			return
		}

		// Enforce single active session: reject if another device or session has logged in since
		var activeToken string
		if err := database.DB.Model(&models.PortalUser{}).Select("active_session_token").Where("id = ?", claims.UserID).Scan(&activeToken).Error; err == nil {
			if activeToken != "" && activeToken != tokenString {
				shared.SendUnauthorized(c, "Session expired or active on another device. Only one active session is allowed.")
				c.Abort()
				return
			}
		}

		c.Set("portal_user_id", claims.UserID)
		c.Next()
	}
}
