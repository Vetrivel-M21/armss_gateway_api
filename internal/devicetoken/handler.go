package devicetoken

import (
	"net/http"
	"strings"

	"armss-gateway/backend/internal/config"
	"armss-gateway/backend/internal/dto"
	"armss-gateway/backend/internal/shared"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{service: NewService(cfg)}
}

// VerifyPassword verifies user credentials during install or login.
func (h *Handler) VerifyPassword(c *gin.Context) {
	var req dto.VerifyPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "password is required")
		return
	}

	user, err := h.service.VerifyPassword(req.Identifier, req.Password)
	if err != nil {
		shared.SendSuccess(c, http.StatusOK, dto.VerifyPasswordResponse{
			Valid:   false,
			Message: "Invalid password",
		})
		return
	}

	shared.SendSuccess(c, http.StatusOK, dto.VerifyPasswordResponse{
		Valid:    true,
		UserID:   user.ID,
		Username: user.Username,
		FullName: user.FullName,
	})
}

// RegisterDevice registers an installation and issues its initial device token.
func (h *Handler) RegisterDevice(c *gin.Context) {
	var req dto.DeviceRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "device_id is required")
		return
	}

	token, issuedAt, err := h.service.RegisterDevice(req.UserID, req.DeviceID, req.MachineFingerprint)
	if err != nil {
		shared.SendInternalError(c, "unable to register device: "+err.Error())
		return
	}

	shared.SendSuccess(c, http.StatusOK, dto.DeviceRegisterResponse{
		DeviceID: req.DeviceID,
		Token:    token,
		IssuedAt: issuedAt,
	})
}

// ValidateToken verifies whether the device token is valid and active.
func (h *Handler) ValidateToken(c *gin.Context) {
	if !h.service.TokenRestrictionEnabled() {
		shared.SendSuccess(c, http.StatusOK, dto.ValidateTokenResponse{Valid: true, Reason: "token_restriction_disabled"})
		return
	}

	var req dto.ValidateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Fallback: check headers if not in JSON body
		req.DeviceID = c.GetHeader("X-Device-Id")
		req.Token = c.GetHeader("X-Device-Token")
	}

	if strings.TrimSpace(req.DeviceID) == "" || strings.TrimSpace(req.Token) == "" {
		shared.SendSuccess(c, http.StatusOK, dto.ValidateTokenResponse{
			Valid:  false,
			Reason: "missing_device_id_or_token",
		})
		return
	}

	valid, reason, user, err := h.service.ValidateToken(req.DeviceID, req.Token)
	if err != nil {
		shared.SendInternalError(c, "validation error")
		return
	}

	if !valid {
		shared.SendSuccess(c, http.StatusOK, dto.ValidateTokenResponse{
			Valid:  false,
			Reason: reason,
		})
		return
	}

	shared.SendSuccess(c, http.StatusOK, dto.ValidateTokenResponse{
		Valid:    true,
		UserID:   user.ID,
		Username: user.Username,
	})
}

// RequestActivation handles activation submission when a device token is revoked or expired.
func (h *Handler) RequestActivation(c *gin.Context) {
	var req dto.RequestActivationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "device_id and domain_requested are required")
		return
	}

	requestID, err := h.service.RequestActivation(req.DeviceID, req.DomainRequested)
	if err != nil {
		shared.SendInternalError(c, "unable to request activation: "+err.Error())
		return
	}

	shared.SendSuccess(c, http.StatusOK, dto.RequestActivationResponse{
		RequestID: requestID,
		Status:    "pending",
	})
}

// CheckActivation handles client pull for activation request status.
func (h *Handler) CheckActivation(c *gin.Context) {
	deviceID := c.Query("device_id")
	if deviceID == "" {
		deviceID = c.GetHeader("X-Device-Id")
	}
	if deviceID == "" {
		shared.SendBadRequest(c, "INVALID_REQUEST", "device_id query parameter or header is required")
		return
	}

	status, rawToken, reason, err := h.service.CheckActivation(deviceID)
	if err != nil {
		shared.SendInternalError(c, "unable to check activation: "+err.Error())
		return
	}

	shared.SendSuccess(c, http.StatusOK, dto.CheckActivationResponse{
		Status: status,
		Token:  rawToken,
		Reason: reason,
	})
}

// RequestMonthlyOtp generates and emails an OTP for the routine 30-day verification.
func (h *Handler) RequestMonthlyOtp(c *gin.Context) {
	var req dto.MonthlyReverifyRequestOtpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "device_id is required")
		return
	}

	requestID, maskedEmail, err := h.service.SendMonthlyOtp(req.DeviceID)
	if err != nil {
		shared.SendInternalError(c, "unable to send verification code: "+err.Error())
		return
	}

	shared.SendSuccess(c, http.StatusOK, dto.MonthlyReverifyRequestOtpResponse{
		RequestID: requestID,
		SentTo:    maskedEmail,
	})
}

// VerifyMonthlyOtp verifies the monthly OTP code and unblocks access.
func (h *Handler) VerifyMonthlyOtp(c *gin.Context) {
	var req dto.MonthlyReverifyVerifyOtpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "device_id, request_id, and otp are required")
		return
	}

	verified, err := h.service.VerifyMonthlyOtp(req.DeviceID, req.RequestID, req.Otp)
	if err != nil {
		shared.SendInternalError(c, "verification check failed: "+err.Error())
		return
	}

	shared.SendSuccess(c, http.StatusOK, dto.MonthlyReverifyVerifyOtpResponse{
		Verified: verified,
	})
}
