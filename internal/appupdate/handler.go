package appupdate

import (
	"net/http"
	"os"

	"armss-gateway/backend/internal/config"
	"armss-gateway/backend/internal/shared"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	cfg *config.Config
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{cfg: cfg}
}

func (h *Handler) Manifest(c *gin.Context) {
	platform := c.Query("platform")
	if platform == "android" || platform == "mobile" {
		h.MobileManifest(c)
		return
	}

	if h.cfg.UpdateVersion == "" || h.cfg.UpdateURL == "" {
		shared.SendSuccess(c, http.StatusOK, gin.H{"available": false})
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{
		"available": true,
		"version":   h.cfg.UpdateVersion,
		"url":       h.cfg.UpdateURL,
		"sha256":    h.cfg.UpdateSHA256,
	})
}

func (h *Handler) Download(c *gin.Context) {
	if h.cfg.UpdateFile == "" {
		c.Status(http.StatusNotFound)
		return
	}
	if _, err := os.Stat(h.cfg.UpdateFile); err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.FileAttachment(h.cfg.UpdateFile, "ARMSS_Gateway_Setup.exe")
}

func (h *Handler) MobileManifest(c *gin.Context) {
	if h.cfg.MobileUpdateVersion == "" || h.cfg.MobileUpdateURL == "" {
		shared.SendSuccess(c, http.StatusOK, gin.H{"available": false})
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{
		"available": true,
		"version":   h.cfg.MobileUpdateVersion,
		"url":       h.cfg.MobileUpdateURL,
		"sha256":    h.cfg.MobileUpdateSHA256,
	})
}

func (h *Handler) MobileDownload(c *gin.Context) {
	if h.cfg.MobileUpdateFile == "" {
		c.Status(http.StatusNotFound)
		return
	}
	if _, err := os.Stat(h.cfg.MobileUpdateFile); err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.FileAttachment(h.cfg.MobileUpdateFile, "ARMSS_Gateway.apk")
}

