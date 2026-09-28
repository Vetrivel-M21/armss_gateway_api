package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"armss-gateway/backend/internal/appupdate"
	"armss-gateway/backend/internal/config"
	"armss-gateway/backend/internal/database"
	"armss-gateway/backend/internal/devicetoken"
	"armss-gateway/backend/internal/devicetokenadmin"
	"armss-gateway/backend/internal/installer"
	"armss-gateway/backend/internal/middleware"
	"armss-gateway/backend/internal/portaladmin"
	"armss-gateway/backend/internal/portalauth"
	"armss-gateway/backend/internal/shared"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	log.Info().Msg("Starting ARMSS Gateway Backend Server...")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	if _, err := database.InitDB(cfg); err != nil {
		log.Fatal().Err(err).Msg("Database initialization failed")
	}

	if cfg.AppEnv == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	allowedOrigins := []string{}
	for _, origin := range strings.Split(cfg.CORSAllowedOrigins, ",") {
		trimmed := strings.TrimSpace(origin)
		if trimmed != "" {
			allowedOrigins = append(allowedOrigins, trimmed)
		}
	}
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{cfg.FrontendURL}
	}

	r.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With", "X-Device-Token", "X-Installer-Secret", "X-Admin-Secret"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	r.Static("/uploads", "./uploads")

	api := r.Group("/api/v1")
	{
		api.GET("/health", func(c *gin.Context) {
			shared.SendSuccess(c, 200, gin.H{"status": "healthy", "system": "ARMSS Gateway API Backend"})
		})

		deviceTokenHandler := devicetoken.NewHandler(cfg)
		updateHandler := appupdate.NewHandler(cfg)
		deviceAdminHandler := devicetokenadmin.NewHandler()
		api.GET("/app/update", updateHandler.Manifest)
		api.GET("/app/update-check", updateHandler.Manifest)
		api.GET("/app/download", updateHandler.Download)
		api.GET("/app/mobile-update", updateHandler.MobileManifest)
		api.GET("/app/mobile-download", updateHandler.MobileDownload)

		// Installer OTP & verification gate — the ARMSS Gateway Windows installer
		// calls these during setup. Shared-secret protected.
		installerHandler := installer.NewHandler(cfg)
		installerRoutes := api.Group("/installer", middleware.RequireHeaderSecret("X-Installer-Secret", cfg.InstallerAPISecret))
		{
			installerRoutes.POST("/request-otp", installerHandler.RequestOtp)
			installerRoutes.POST("/verify-otp", installerHandler.VerifyOtp)
			installerRoutes.POST("/verify-password", deviceTokenHandler.VerifyPassword)
			installerRoutes.POST("/devices/register", deviceTokenHandler.RegisterDevice)
		}

		// Device registration endpoint (direct access with installer secret)
		api.POST("/devices/register", middleware.RequireHeaderSecret("X-Installer-Secret", cfg.InstallerAPISecret), deviceTokenHandler.RegisterDevice)

		// Client auth & device token validation routes
		authRoutes := api.Group("/auth")
		{
			authRoutes.POST("/verify-password", deviceTokenHandler.VerifyPassword)
			authRoutes.POST("/validate-token", deviceTokenHandler.ValidateToken)
			authRoutes.POST("/request-activation", deviceTokenHandler.RequestActivation)
			authRoutes.GET("/check-activation", deviceTokenHandler.CheckActivation)
			authRoutes.POST("/monthly-reverify/request-otp", deviceTokenHandler.RequestMonthlyOtp)
			authRoutes.POST("/monthly-reverify/verify-otp", deviceTokenHandler.VerifyMonthlyOtp)
			authRoutes.POST("/monthly-reverify", deviceTokenHandler.VerifyMonthlyOtp)
		}

		// Portal user self-service: register (admin-approved, no OTP)/login/
		// forgot-password.
		authHandler := portalauth.NewHandler(cfg)
		api.GET("/portal/links", portaladmin.NewHandler(cfg).ListLinks)
		api.POST("/portal/register", authHandler.Register)
		api.POST("/portal/login", authHandler.Login)
		api.POST("/portal/forgot-password/request", authHandler.ForgotPasswordRequest)
		api.POST("/portal/forgot-password/reset", authHandler.ForgotPasswordReset)
		api.GET("/portal/me", middleware.RequirePortalToken(cfg.JWTSecret), authHandler.Me)
		api.PUT("/portal/me", middleware.RequirePortalToken(cfg.JWTSecret), authHandler.UpdateProfile)
		api.POST("/portal/change-password", middleware.RequirePortalToken(cfg.JWTSecret), authHandler.ChangePassword)

		// Admin-only: approve registered accounts and manage per-link grants.
		adminHandler := portaladmin.NewHandler(cfg)
		adminRoutes := api.Group("/portal/admin", middleware.RequireHeaderSecret("X-Admin-Secret", cfg.AdminAPISecret))
		{
			adminRoutes.GET("/links", adminHandler.ListLinks)
			adminRoutes.POST("/links", adminHandler.SaveLink)
			adminRoutes.DELETE("/links/:key", adminHandler.DeleteLink)
			adminRoutes.POST("/links/:key/image", adminHandler.UploadLinkImage)
			adminRoutes.GET("/users", adminHandler.ListUsers)
			adminRoutes.POST("/users/:id/approve", adminHandler.SetActive)
			adminRoutes.POST("/users/:id/role", adminHandler.SetRole)
			adminRoutes.GET("/users/:id/password", adminHandler.RevealPassword)
			adminRoutes.POST("/users/:id/password", adminHandler.SetPassword)
			adminRoutes.POST("/users/:id/grants", adminHandler.SetGrants)
			adminRoutes.POST("/users/:id/release-device", adminHandler.ReleaseDeviceLock)
			adminRoutes.DELETE("/users/:id", adminHandler.DeleteUser)

			// Also expose device management under /portal/admin
			adminRoutes.GET("/devices", deviceAdminHandler.ListDevices)
			adminRoutes.POST("/devices/:device_id/revoke", deviceAdminHandler.RevokeDevice)
			adminRoutes.GET("/requests", deviceAdminHandler.ListRequests)
			adminRoutes.POST("/requests/:request_id/approve", deviceAdminHandler.ApproveRequest)
			adminRoutes.POST("/requests/:request_id/reject", deviceAdminHandler.RejectRequest)
			adminRoutes.GET("/audit-logs", deviceAdminHandler.ListAuditLogs)

			// Installer password management
			// Installer password & OTP management
			adminRoutes.GET("/installer-password", adminHandler.GetInstallerPassword)
			adminRoutes.POST("/installer-password", adminHandler.SetInstallerPassword)
			adminRoutes.GET("/installer-email", adminHandler.GetInstallerAdminEmail)
			adminRoutes.POST("/installer-email", adminHandler.SetInstallerAdminEmail)
			adminRoutes.GET("/admin-password", adminHandler.GetAdminPassword)
			adminRoutes.POST("/admin-password", adminHandler.SetAdminPassword)
			adminRoutes.GET("/token-restriction", adminHandler.GetTokenRestriction)
			adminRoutes.POST("/token-restriction", adminHandler.SetTokenRestriction)
			adminRoutes.GET("/installer-otp", adminHandler.GetActiveInstallerOtp)
		}

		// Admin-only: direct /admin/... routes (matching requirement specifications)
		coreAdminRoutes := api.Group("/admin", middleware.RequireHeaderSecret("X-Admin-Secret", cfg.AdminAPISecret))
		{
			coreAdminRoutes.POST("/users/:id/release-device", adminHandler.ReleaseDeviceLock)
			coreAdminRoutes.DELETE("/users/:id", adminHandler.DeleteUser)
			coreAdminRoutes.GET("/devices", deviceAdminHandler.ListDevices)
			coreAdminRoutes.POST("/devices/:device_id/revoke", deviceAdminHandler.RevokeDevice)
			coreAdminRoutes.GET("/requests", deviceAdminHandler.ListRequests)
			coreAdminRoutes.POST("/requests/:request_id/approve", deviceAdminHandler.ApproveRequest)
			coreAdminRoutes.POST("/requests/:request_id/reject", deviceAdminHandler.RejectRequest)
			coreAdminRoutes.GET("/audit-logs", deviceAdminHandler.ListAuditLogs)

			// Installer password management
			// Installer password & OTP management
			coreAdminRoutes.GET("/installer-password", adminHandler.GetInstallerPassword)
			coreAdminRoutes.POST("/installer-password", adminHandler.SetInstallerPassword)
			coreAdminRoutes.GET("/installer-email", adminHandler.GetInstallerAdminEmail)
			coreAdminRoutes.POST("/installer-email", adminHandler.SetInstallerAdminEmail)
			coreAdminRoutes.GET("/admin-password", adminHandler.GetAdminPassword)
			coreAdminRoutes.POST("/admin-password", adminHandler.SetAdminPassword)
			coreAdminRoutes.GET("/installer-otp", adminHandler.GetActiveInstallerOtp)
		}
	}

	serverAddr := fmt.Sprintf(":%s", cfg.Port)
	log.Info().Msgf("ARMSS Gateway Backend listening on %s (Environment: %s)", serverAddr, cfg.AppEnv)
	if err := r.Run(serverAddr); err != nil {
		log.Fatal().Err(err).Msg("Server crashed")
	}
}
