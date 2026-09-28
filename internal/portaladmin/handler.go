package portaladmin

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"armss-gateway/backend/internal/config"
	"armss-gateway/backend/internal/dto"
	"armss-gateway/backend/internal/shared"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
	cfg     *config.Config
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{service: NewService(), cfg: cfg}
}

func (h *Handler) ListUsers(c *gin.Context) {
	users, err := h.service.ListUsers()
	if err != nil {
		shared.SendInternalError(c, "unable to list users")
		return
	}
	shared.SendSuccess(c, http.StatusOK, users)
}

func (h *Handler) ListLinks(c *gin.Context) {
	links, err := h.service.ListLinks(c.Query("include_inactive") == "true")
	if err != nil {
		shared.SendInternalError(c, "unable to list portal links")
		return
	}
	shared.SendSuccess(c, http.StatusOK, links)
}

func (h *Handler) SaveLink(c *gin.Context) {
	var req dto.PortalLinkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "tab_name, name and url are required")
		return
	}
	link, err := h.service.SaveLink(req)
	if err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", err.Error())
		return
	}
	shared.SendSuccess(c, http.StatusOK, link)
}

func (h *Handler) DeleteLink(c *gin.Context) {
	if err := h.service.DeleteLink(c.Param("key")); err != nil {
		shared.SendInternalError(c, "unable to deactivate portal link")
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"saved": true})
}

func (h *Handler) UploadLinkImage(c *gin.Context) {
	key := c.Param("key")
	file, err := c.FormFile("image")
	if err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "image is required")
		return
	}
	ext := strings.ToLower(filepath.Ext(file.Filename))
	if ext != ".png" && ext != ".jpg" && ext != ".jpeg" && ext != ".webp" {
		shared.SendBadRequest(c, "INVALID_REQUEST", "image must be png, jpg, jpeg or webp")
		return
	}
	if file.Size > 5*1024*1024 {
		shared.SendBadRequest(c, "INVALID_REQUEST", "image must be 5 MB or smaller")
		return
	}
	dir := filepath.Join("uploads", "portal-links")
	if err := os.MkdirAll(dir, 0755); err != nil {
		shared.SendInternalError(c, "unable to create image directory")
		return
	}
	filename := fmt.Sprintf("%d-%s%s", time.Now().UnixNano(), strings.ReplaceAll(key, "/", "-"), ext)
	path := filepath.Join(dir, filename)
	if err := c.SaveUploadedFile(file, path); err != nil {
		shared.SendInternalError(c, "unable to save image")
		return
	}
	publicPath := "/uploads/portal-links/" + filename
	if err := h.service.SetLinkImage(key, publicPath); err != nil {
		shared.SendInternalError(c, "unable to update portal link image")
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"image_path": publicPath})
}

func (h *Handler) SetActive(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "invalid user id")
		return
	}

	var req dto.SetActiveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "is_active is required")
		return
	}

	if err := h.service.SetActive(uint(userID), req.IsActive); err != nil {
		shared.SendInternalError(c, "unable to update account status")
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"saved": true})
}

func (h *Handler) SetRole(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "invalid user id")
		return
	}

	var req dto.SetRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "role is required")
		return
	}

	if err := h.service.SetRole(uint(userID), req.Role); err != nil {
		shared.SendInternalError(c, "unable to update user role: "+err.Error())
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"saved": true})
}

func (h *Handler) ReleaseDeviceLock(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "invalid user id")
		return
	}

	if err := h.service.ReleaseDeviceLock(uint(userID)); err != nil {
		shared.SendInternalError(c, "unable to release device lock: "+err.Error())
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"released": true})
}

func (h *Handler) RevealPassword(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "invalid user id")
		return
	}

	password, err := h.service.GetPassword(uint(userID))
	if err != nil {
		shared.SendInternalError(c, "unable to load password")
		return
	}
	shared.SendSuccess(c, http.StatusOK, dto.RevealPasswordResponse{Password: password})
}

func (h *Handler) SetPassword(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "invalid user id")
		return
	}

	var req dto.SetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "new_password is required")
		return
	}

	if err := h.service.SetPassword(uint(userID), req.NewPassword); err != nil {
		shared.SendInternalError(c, "unable to update password")
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"saved": true})
}

func (h *Handler) SetGrants(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "invalid user id")
		return
	}

	var req dto.SetGrantsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "link_keys is required")
		return
	}

	if err := h.service.SetGrants(uint(userID), req.LinkKeys); err != nil {
		shared.SendInternalError(c, "unable to save grants")
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"saved": true})
}

func (h *Handler) DeleteUser(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "invalid user id")
		return
	}

	if err := h.service.DeleteUser(uint(userID)); err != nil {
		shared.SendInternalError(c, "unable to delete user")
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"deleted": true})
}

func (h *Handler) GetInstallerPassword(c *gin.Context) {
	fallback := ""
	if h.cfg != nil {
		fallback = h.cfg.InstallerPassword
	}
	if fallback == "" {
		fallback = "Armss@Installer2026"
	}
	pwd, err := h.service.GetInstallerPassword(fallback)
	if err != nil {
		shared.SendInternalError(c, "unable to load installer password")
		return
	}
	shared.SendSuccess(c, http.StatusOK, dto.InstallerPasswordResponse{Password: pwd})
}

func (h *Handler) SetInstallerPassword(c *gin.Context) {
	var req dto.SetInstallerPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Password) == "" {
		shared.SendBadRequest(c, "INVALID_REQUEST", "password is required")
		return
	}

	actor := c.GetString("portal_admin_email")
	if actor == "" {
		actor = "admin"
	}

	if err := h.service.SetInstallerPassword(strings.TrimSpace(req.Password), actor); err != nil {
		shared.SendInternalError(c, "unable to update installer password")
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"saved": true, "message": "Installer password updated successfully"})
}

func (h *Handler) GetInstallerAdminEmail(c *gin.Context) {
	fallback := ""
	if h.cfg != nil {
		fallback = h.cfg.InstallerAdminEmail
	}
	email, err := h.service.GetInstallerAdminEmail(fallback)
	if err != nil {
		shared.SendInternalError(c, "unable to load installer admin email")
		return
	}
	shared.SendSuccess(c, http.StatusOK, dto.InstallerAdminEmailResponse{Email: email})
}

func (h *Handler) SetInstallerAdminEmail(c *gin.Context) {
	var req dto.SetInstallerAdminEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Email) == "" {
		shared.SendBadRequest(c, "INVALID_REQUEST", "email is required")
		return
	}

	cleanEmail := strings.TrimSpace(req.Email)
	if !strings.Contains(cleanEmail, "@") || !strings.Contains(cleanEmail, ".") {
		shared.SendBadRequest(c, "INVALID_REQUEST", "please provide a valid email address")
		return
	}

	actor := c.GetString("portal_admin_email")
	if actor == "" {
		actor = "admin"
	}

	if err := h.service.SetInstallerAdminEmail(cleanEmail, actor); err != nil {
		shared.SendInternalError(c, "unable to update installer admin email")
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"saved": true, "email": cleanEmail, "message": "Installer admin email updated successfully"})
}

func (h *Handler) GetTokenRestriction(c *gin.Context) {
	enabled, err := h.service.GetTokenRestrictionEnabled()
	if err != nil {
		shared.SendInternalError(c, "unable to load token restriction")
		return
	}
	shared.SendSuccess(c, http.StatusOK, dto.TokenRestrictionResponse{Enabled: enabled})
}

func (h *Handler) SetTokenRestriction(c *gin.Context) {
	var req dto.SetTokenRestrictionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "enabled is required")
		return
	}
	actor := c.GetString("portal_admin_email")
	if actor == "" {
		actor = "admin"
	}
	if err := h.service.SetTokenRestrictionEnabled(req.Enabled, actor); err != nil {
		shared.SendInternalError(c, "unable to update token restriction")
		return
	}
	shared.SendSuccess(c, http.StatusOK, dto.TokenRestrictionResponse{Enabled: req.Enabled})
}

func (h *Handler) GetActiveInstallerOtp(c *gin.Context) {
	data, err := h.service.GetActiveInstallerOtp()
	if err != nil {
		shared.SendInternalError(c, "unable to load active installer otp")
		return
	}
	shared.SendSuccess(c, http.StatusOK, data)
}

func (h *Handler) GetAdminPassword(c *gin.Context) {
	fallback := "admin123"
	pwd, err := h.service.GetAdminPassword(fallback)
	if err != nil {
		shared.SendInternalError(c, "unable to load admin password")
		return
	}
	shared.SendSuccess(c, http.StatusOK, dto.AdminPasswordResponse{Password: pwd})
}

func (h *Handler) SetAdminPassword(c *gin.Context) {
	var req dto.SetAdminPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Password) == "" {
		shared.SendBadRequest(c, "INVALID_REQUEST", "password is required")
		return
	}

	actor := c.GetString("portal_admin_email")
	if actor == "" {
		actor = "admin"
	}

	if err := h.service.SetAdminPassword(strings.TrimSpace(req.Password), actor); err != nil {
		shared.SendInternalError(c, "unable to update admin password")
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"saved": true, "message": "Admin password updated successfully"})
}
