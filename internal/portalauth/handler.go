package portalauth

import (
	"errors"
	"fmt"
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

func (h *Handler) Register(c *gin.Context) {
	var req dto.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "username, email, password, full_name, department and branch are required")
		return
	}

	userID, err := h.service.Register(req.Username, req.Email, req.Password, req.FullName, req.Department, req.Branch)
	if err != nil {
		if errors.Is(err, ErrUsernameTaken) {
			shared.SendBadRequest(c, "USERNAME_TAKEN", "an account with this username already exists")
			return
		}
		if errors.Is(err, ErrEmailTaken) {
			shared.SendBadRequest(c, "EMAIL_TAKEN", "an account with this email already exists")
			return
		}
		shared.SendInternalError(c, "unable to register")
		return
	}
	shared.SendSuccess(c, http.StatusOK, dto.RegisterResponse{UserID: userID})
}

func (h *Handler) Login(c *gin.Context) {
	var req dto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "identifier and password are required")
		return
	}

	user, err := h.service.Login(req.Identifier, req.Password)
	if err != nil {
		shared.SendUnauthorized(c, "invalid credentials or inactive account")
		return
	}

	token, err := h.service.IssueToken(user)
	if err != nil {
		shared.SendInternalError(c, "unable to issue token")
		return
	}
	keys, err := h.service.GrantedLinkKeys(user.ID)
	if err != nil {
		shared.SendInternalError(c, "unable to load access grants")
		return
	}

	shared.SendSuccess(c, http.StatusOK, dto.LoginResponse{
		Token: token, Username: user.Username, Email: user.Email, FullName: user.FullName, Department: user.Department, Branch: user.Branch, Role: user.Role, GrantedLinkKeys: keys,
	})
}

func (h *Handler) Me(c *gin.Context) {
	userID := c.GetUint("portal_user_id")
	user, err := h.service.GetByID(userID)
	if err != nil {
		shared.SendUnauthorized(c, "user not found")
		return
	}
	keys, err := h.service.GrantedLinkKeys(user.ID)
	if err != nil {
		shared.SendInternalError(c, "unable to load access grants")
		return
	}
	shared.SendSuccess(c, http.StatusOK, dto.MeResponse{
		Username: user.Username, Email: user.Email, FullName: user.FullName, Department: user.Department, Branch: user.Branch, Role: user.Role, GrantedLinkKeys: keys,
	})
}

func (h *Handler) ForgotPasswordRequest(c *gin.Context) {
	var req dto.ForgotPasswordRequestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "email is required")
		return
	}
	if err := h.service.RequestPasswordReset(req.Email); err != nil {
		fmt.Printf("[FORGOT_PW_ERROR] Failed to send password reset OTP to %s: %v\n", req.Email, err)
		shared.SendInternalError(c, "unable to process request: "+err.Error())
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"message": "if that account exists, an OTP has been sent"})
}

func (h *Handler) ForgotPasswordReset(c *gin.Context) {
	var req dto.ForgotPasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "email, otp and new_password are required")
		return
	}
	ok, err := h.service.ResetPassword(req.Email, req.Otp, req.NewPassword)
	if err != nil {
		shared.SendInternalError(c, "unable to reset password")
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"reset": ok})
}

func (h *Handler) UpdateProfile(c *gin.Context) {
	userID := c.GetUint("portal_user_id")
	var req dto.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "full_name is required")
		return
	}
	if err := h.service.UpdateProfile(userID, req.Email, req.FullName, req.Department, req.Branch); err != nil {
		shared.SendBadRequest(c, "UPDATE_FAILED", err.Error())
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"saved": true})
}

func (h *Handler) ChangePassword(c *gin.Context) {
	userID := c.GetUint("portal_user_id")
	var req dto.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		shared.SendBadRequest(c, "INVALID_REQUEST", "old_password and new_password are required")
		return
	}
	if err := h.service.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
		shared.SendBadRequest(c, "PASSWORD_CHANGE_FAILED", err.Error())
		return
	}
	shared.SendSuccess(c, http.StatusOK, gin.H{"saved": true, "message": "password updated successfully"})
}
