package installer

import (
	"net/http"

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

func (h *Handler) RequestOtp(c *gin.Context) {
	var req dto.RequestOtpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "username, department and branch are required")
		return
	}

	requestID, err := h.service.RequestOtp(req.Username, req.Department, req.Branch)
	if err != nil {
		shared.SendInternalError(c, "unable to send installer otp")
		return
	}
	shared.SendSuccess(c, http.StatusOK, dto.RequestOtpResponse{RequestID: requestID})
}

func (h *Handler) VerifyOtp(c *gin.Context) {
	var req dto.VerifyOtpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "request_id and otp are required")
		return
	}

	valid, err := h.service.VerifyOtp(req.RequestID, req.Otp)
	if err != nil {
		shared.SendInternalError(c, "unable to verify installer otp")
		return
	}
	shared.SendSuccess(c, http.StatusOK, dto.VerifyOtpResponse{Valid: valid})
}
