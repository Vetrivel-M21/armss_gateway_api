package devicetokenadmin

import (
	"net/http"
	"strconv"

	"armss-gateway/backend/internal/dto"
	"armss-gateway/backend/internal/shared"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler() *Handler {
	return &Handler{service: NewService()}
}

func (h *Handler) ListDevices(c *gin.Context) {
	devices, err := h.service.ListDevices()
	if err != nil {
		shared.SendInternalError(c, "unable to list devices: "+err.Error())
		return
	}
	shared.SendSuccess(c, http.StatusOK, devices)
}

func (h *Handler) RevokeDevice(c *gin.Context) {
	deviceID := c.Param("device_id")
	if deviceID == "" {
		shared.SendBadRequest(c, "INVALID_REQUEST", "device_id is required")
		return
	}

	actor := "admin"
	if customActor := c.GetHeader("X-Admin-Actor"); customActor != "" {
		actor = customActor
	}

	if err := h.service.RevokeDevice(deviceID, actor); err != nil {
		shared.SendInternalError(c, "unable to revoke device token: "+err.Error())
		return
	}

	shared.SendSuccess(c, http.StatusOK, gin.H{"revoked": true})
}

func (h *Handler) ListRequests(c *gin.Context) {
	status := c.Query("status")
	requests, err := h.service.ListRequests(status)
	if err != nil {
		shared.SendInternalError(c, "unable to list activation requests: "+err.Error())
		return
	}
	shared.SendSuccess(c, http.StatusOK, requests)
}

func (h *Handler) ApproveRequest(c *gin.Context) {
	requestID := c.Param("request_id")
	if requestID == "" {
		shared.SendBadRequest(c, "INVALID_REQUEST", "request_id is required")
		return
	}

	actor := "admin"
	if customActor := c.GetHeader("X-Admin-Actor"); customActor != "" {
		actor = customActor
	}

	var adminID *uint
	if idStr := c.GetHeader("X-Admin-User-Id"); idStr != "" {
		if id, err := strconv.ParseUint(idStr, 10, 64); err == nil {
			uid := uint(id)
			adminID = &uid
		}
	}

	if err := h.service.ApproveRequest(requestID, actor, adminID); err != nil {
		shared.SendInternalError(c, "unable to approve request: "+err.Error())
		return
	}

	shared.SendSuccess(c, http.StatusOK, gin.H{"approved": true})
}

func (h *Handler) RejectRequest(c *gin.Context) {
	requestID := c.Param("request_id")
	if requestID == "" {
		shared.SendBadRequest(c, "INVALID_REQUEST", "request_id is required")
		return
	}

	var req dto.AdminRejectRequest
	_ = c.ShouldBindJSON(&req)

	actor := "admin"
	if customActor := c.GetHeader("X-Admin-Actor"); customActor != "" {
		actor = customActor
	}

	var adminID *uint
	if idStr := c.GetHeader("X-Admin-User-Id"); idStr != "" {
		if id, err := strconv.ParseUint(idStr, 10, 64); err == nil {
			uid := uint(id)
			adminID = &uid
		}
	}

	if err := h.service.RejectRequest(requestID, actor, adminID, req.Reason); err != nil {
		shared.SendInternalError(c, "unable to reject request: "+err.Error())
		return
	}

	shared.SendSuccess(c, http.StatusOK, gin.H{"rejected": true})
}

func (h *Handler) ListAuditLogs(c *gin.Context) {
	var userIDPtr *uint
	if uidStr := c.Query("user_id"); uidStr != "" {
		if uid, err := strconv.ParseUint(uidStr, 10, 64); err == nil {
			u := uint(uid)
			userIDPtr = &u
		}
	}

	var deviceIDPtr *string
	if did := c.Query("device_id"); did != "" {
		deviceIDPtr = &did
	}

	limit := 100
	if lStr := c.Query("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil {
			limit = l
		}
	}

	logs, err := h.service.ListAuditLogs(userIDPtr, deviceIDPtr, limit)
	if err != nil {
		shared.SendInternalError(c, "unable to load audit logs: "+err.Error())
		return
	}

	shared.SendSuccess(c, http.StatusOK, logs)
}
