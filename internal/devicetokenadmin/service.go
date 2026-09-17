package devicetokenadmin

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"armss-gateway/backend/internal/database"
	"armss-gateway/backend/internal/devicetoken"
	"armss-gateway/backend/internal/dto"
	"armss-gateway/backend/internal/models"

	"gorm.io/gorm"
)

const monthlyReverifyDuration = 30 * 24 * time.Hour

var ErrDeviceNotFound = errors.New("device not found")
var ErrRequestNotFound = errors.New("activation request not found")

type Service struct{}

func NewService() *Service {
	return &Service{}
}

func (s *Service) ListDevices() ([]dto.AdminDeviceResponse, error) {
	var devices []models.Device
	if err := database.DB.Preload("User").Order("created_at DESC").Find(&devices).Error; err != nil {
		return nil, err
	}

	result := make([]dto.AdminDeviceResponse, len(devices))
	for i, d := range devices {
		var token models.DeviceToken
		tokenStatus := "none"
		tokenVersion := 0
		if err := database.DB.Where("device_id = ?", d.ID).Order("token_version DESC").First(&token).Error; err == nil {
			tokenStatus = string(token.Status)
			tokenVersion = token.TokenVersion
		}

		username := ""
		email := ""
		fullName := ""
		if d.User != nil {
			username = d.User.Username
			email = d.User.Email
			fullName = d.User.FullName
		} else if d.UserID > 0 {
			var u models.PortalUser
			if err := database.DB.Where("id = ?", d.UserID).First(&u).Error; err == nil {
				username = u.Username
				email = u.Email
				fullName = u.FullName
			}
		}

		isExpired := time.Since(d.LastOtpVerifiedAt) > monthlyReverifyDuration

		result[i] = dto.AdminDeviceResponse{
			DeviceID:           d.ID,
			UserID:             d.UserID,
			Username:           username,
			Email:              email,
			FullName:           fullName,
			MachineFingerprint: d.MachineFingerprint,
			TokenStatus:        tokenStatus,
			TokenVersion:       tokenVersion,
			LastOtpVerifiedAt:  d.LastOtpVerifiedAt,
			IsOtpExpired:       isExpired,
			CreatedAt:          d.CreatedAt,
		}
	}

	return result, nil
}

func (s *Service) RevokeDevice(deviceID string, actor string) error {
	return database.DB.Transaction(func(tx *gorm.DB) error {
		var device models.Device
		if err := tx.Where("id = ?", deviceID).First(&device).Error; err != nil {
			return ErrDeviceNotFound
		}

		var activeTokens []models.DeviceToken
		if err := tx.Where("device_id = ? AND status = ?", deviceID, models.TokenStatusActive).Find(&activeTokens).Error; err != nil {
			return err
		}

		for _, t := range activeTokens {
			if err := tx.Model(&t).Update("status", models.TokenStatusRevoked).Error; err != nil {
				return err
			}
		}

		s.logAuditTx(tx, "token_revoked", &device.UserID, &deviceID, actor, map[string]interface{}{
			"revoked_count": len(activeTokens),
		})
		return nil
	})
}

func (s *Service) ListRequests(statusFilter string) ([]dto.AdminActivationRequestResponse, error) {
	var requests []models.ActivationRequest
	query := database.DB.Preload("User").Order("requested_at DESC")
	if statusFilter != "" {
		query = query.Where("status = ?", statusFilter)
	}

	if err := query.Find(&requests).Error; err != nil {
		return nil, err
	}

	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	result := make([]dto.AdminActivationRequestResponse, len(requests))
	for i, r := range requests {
		username := ""
		email := ""
		fullName := ""
		if r.User != nil {
			username = r.User.Username
			email = r.User.Email
			fullName = r.User.FullName
		}

		status := string(r.Status)
		if r.Status == models.ActivationStatusPending && r.RequestedAt.Before(cutoff) {
			status = "expired"
		}

		result[i] = dto.AdminActivationRequestResponse{
			RequestID:       r.ID,
			UserID:          r.UserID,
			Username:        username,
			Email:           email,
			FullName:        fullName,
			DeviceID:        r.DeviceID,
			DomainRequested: r.DomainRequested,
			Status:          status,
			RequestedAt:     r.RequestedAt,
			ApprovedAt:      r.ApprovedAt,
			RejectionReason: r.RejectionReason,
		}
	}

	return result, nil
}

func (s *Service) ApproveRequest(requestID string, adminActor string, adminID *uint) error {
	return database.DB.Transaction(func(tx *gorm.DB) error {
		var req models.ActivationRequest
		if err := tx.Where("id = ?", requestID).First(&req).Error; err != nil {
			return ErrRequestNotFound
		}

		rawToken, err := devicetoken.GenerateRawToken()
		if err != nil {
			return fmt.Errorf("generating token: %w", err)
		}
		tokenHash := devicetoken.HashToken(rawToken)

		// Determine next version
		var latestToken models.DeviceToken
		nextVersion := 1
		if err := tx.Where("device_id = ?", req.DeviceID).Order("token_version DESC").First(&latestToken).Error; err == nil {
			nextVersion = latestToken.TokenVersion + 1
		}

		// Revoke old tokens
		_ = tx.Model(&models.DeviceToken{}).
			Where("device_id = ? AND status = ?", req.DeviceID, models.TokenStatusActive).
			Update("status", models.TokenStatusRevoked).Error

		now := time.Now()
		newToken := models.DeviceToken{
			UserID:       req.UserID,
			DeviceID:     req.DeviceID,
			TokenVersion: nextVersion,
			Status:       models.TokenStatusActive,
			TokenHash:    tokenHash,
			IssuedAt:     now,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		if err := tx.Create(&newToken).Error; err != nil {
			return err
		}

		// Update activation request
		req.Status = models.ActivationStatusApproved
		req.ApprovedBy = adminID
		req.ApprovedAt = &now
		req.NewTokenHash = tokenHash
		req.NewTokenRaw = rawToken
		if err := tx.Save(&req).Error; err != nil {
			return err
		}

		// Refresh device OTP verification timestamp
		_ = tx.Model(&models.Device{}).
			Where("id = ?", req.DeviceID).
			Update("last_otp_verified_at", now).Error

		s.logAuditTx(tx, "activation_approved", &req.UserID, &req.DeviceID, adminActor, map[string]interface{}{
			"request_id":    requestID,
			"token_version": nextVersion,
		})
		s.logAuditTx(tx, "token_issued", &req.UserID, &req.DeviceID, adminActor, map[string]interface{}{
			"token_version": nextVersion,
			"status":        models.TokenStatusActive,
			"source":        "activation_approval",
		})

		return nil
	})
}

func (s *Service) RejectRequest(requestID string, adminActor string, adminID *uint, reason string) error {
	return database.DB.Transaction(func(tx *gorm.DB) error {
		var req models.ActivationRequest
		if err := tx.Where("id = ?", requestID).First(&req).Error; err != nil {
			return ErrRequestNotFound
		}

		now := time.Now()
		req.Status = models.ActivationStatusRejected
		req.ApprovedBy = adminID
		req.ApprovedAt = &now
		req.RejectionReason = reason
		if err := tx.Save(&req).Error; err != nil {
			return err
		}

		s.logAuditTx(tx, "activation_rejected", &req.UserID, &req.DeviceID, adminActor, map[string]interface{}{
			"request_id": requestID,
			"reason":     reason,
		})

		return nil
	})
}

func (s *Service) ListAuditLogs(userID *uint, deviceID *string, limit int) ([]dto.AdminAuditLogResponse, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	query := database.DB.Order("created_at DESC").Limit(limit)
	if userID != nil && *userID > 0 {
		query = query.Where("user_id = ?", *userID)
	}
	if deviceID != nil && *deviceID != "" {
		query = query.Where("device_id = ?", *deviceID)
	}

	var logs []models.AuditLog
	if err := query.Find(&logs).Error; err != nil {
		return nil, err
	}

	result := make([]dto.AdminAuditLogResponse, len(logs))
	for i, l := range logs {
		result[i] = dto.AdminAuditLogResponse{
			ID:        l.ID,
			EventType: l.EventType,
			UserID:    l.UserID,
			DeviceID:  l.DeviceID,
			Actor:     l.Actor,
			Metadata:  l.Metadata,
			CreatedAt: l.CreatedAt,
		}
	}
	return result, nil
}

func (s *Service) logAuditTx(tx *gorm.DB, eventType string, userID *uint, deviceID *string, actor string, metadata map[string]interface{}) {
	metaJSON, _ := json.Marshal(metadata)
	record := models.AuditLog{
		EventType: eventType,
		UserID:    userID,
		DeviceID:  deviceID,
		Actor:     actor,
		Metadata:  string(metaJSON),
		CreatedAt: time.Now(),
	}
	_ = tx.Create(&record).Error
}
