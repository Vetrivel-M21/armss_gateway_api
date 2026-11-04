package devicetoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"armss-gateway/backend/internal/config"
	"armss-gateway/backend/internal/database"
	"armss-gateway/backend/internal/dto"
	"armss-gateway/backend/internal/mail"
	"armss-gateway/backend/internal/models"

	"gorm.io/gorm"
)

const otpTTL = 15 * time.Minute
const monthlyReverifyDuration = 30 * 24 * time.Hour

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrAccountInactive = errors.New("this account is inactive. Please contact an administrator to activate your account")
var ErrInvalidPassword = errors.New("incorrect password. Please verify your credentials")
var ErrDeviceNotFound = errors.New("device not found")
var ErrUserNotFound = errors.New("user not found")

type Service struct {
	cfg  *config.Config
	mail *mail.Service
}

func (s *Service) TokenRestrictionEnabled() bool {
	var setting models.SystemSetting
	if err := database.DB.Where("`key` = ?", "token_restriction_enabled").First(&setting).Error; err != nil {
		return true
	}
	return setting.Value != "false"
}

func NewService(cfg *config.Config) *Service {
	return &Service{
		cfg:  cfg,
		mail: mail.NewService(cfg),
	}
}

// HashToken returns the hex-encoded SHA-256 hash of a raw token.
func HashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// GenerateRawToken generates a 32-byte (64 hex characters) cryptographically secure random string.
func GenerateRawToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// VerifyPassword checks either the centralized installer password from configuration or user credentials.
func (s *Service) VerifyPassword(identifier, password string) (*models.PortalUser, error) {
	// 1. Centralized installer password check: check system_settings first, then config
	expectedPassword := s.cfg.InstallerPassword
	var setting models.SystemSetting
	if err := database.DB.Where("`key` = ?", "installer_password").First(&setting).Error; err == nil && setting.Value != "" {
		expectedPassword = setting.Value
	}
	if expectedPassword == "" {
		expectedPassword = "Armss@Installer2026"
	}

	if password == expectedPassword {
		var user models.PortalUser
		if identifier != "" {
			if err := database.DB.Where("(username = ? OR email = ?) AND is_active = ?", identifier, identifier, true).First(&user).Error; err == nil {
				return &user, nil
			}
		}
		if err := database.DB.Where("is_active = ?", true).Order("id ASC").First(&user).Error; err == nil {
			return &user, nil
		}
		var defaultUser models.PortalUser
		if err := database.DB.Where("username = ?", "admin").First(&defaultUser).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			defaultUser = models.PortalUser{
				Username: "admin",
				Email:    s.cfg.InstallerAdminEmail,
				FullName: "System Administrator",
				IsActive: true,
			}
			if defaultUser.Email == "" {
				defaultUser.Email = "armssdirector@gmail.com"
			}
			_ = database.DB.Create(&defaultUser).Error
		}
		return &defaultUser, nil
	}

	// 2. Individual user credential check (fallback)
	if identifier != "" {
		var user models.PortalUser
		if err := database.DB.Where("username = ? OR email = ?", identifier, identifier).First(&user).Error; err != nil {
			return nil, ErrUserNotFound
		}
		if !user.IsActive {
			return nil, ErrAccountInactive
		}
		if user.Password != password {
			return nil, ErrInvalidPassword
		}
		return &user, nil
	}

	return nil, ErrInvalidCredentials
}

// RegisterDevice creates or updates a device record, marks its last_otp_verified_at as now,
// and issues the initial active token for this user + device pair.
func (s *Service) RegisterDevice(userID uint, deviceID, fingerprint string) (string, time.Time, error) {
	var user models.PortalUser
	if userID == 0 {
		if err := database.DB.Where("is_active = ?", true).Order("id ASC").First(&user).Error; err != nil {
			return "", time.Time{}, ErrUserNotFound
		}
		userID = user.ID
	} else {
		if err := database.DB.Where("id = ? AND is_active = ?", userID, true).First(&user).Error; err != nil {
			return "", time.Time{}, ErrUserNotFound
		}
	}

	rawToken, err := GenerateRawToken()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generating token: %w", err)
	}
	tokenHash := HashToken(rawToken)
	now := time.Now()

	err = database.DB.Transaction(func(tx *gorm.DB) error {
		var device models.Device
		err := tx.Where("id = ?", deviceID).First(&device).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			device = models.Device{
				ID:                 deviceID,
				UserID:             userID,
				MachineFingerprint: fingerprint,
				LastOtpVerifiedAt:  now,
				CreatedAt:          now,
				UpdatedAt:          now,
			}
			if err := tx.Create(&device).Error; err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			if userID > 0 {
				device.UserID = userID
			}
			if fingerprint != "" {
				device.MachineFingerprint = fingerprint
			}
			// Preserve existing LastOtpVerifiedAt so auto-updates or re-registrations
			// do NOT reset the 30-day monthly OTP countdown!
			if device.LastOtpVerifiedAt.IsZero() {
				device.LastOtpVerifiedAt = now
			}
			device.UpdatedAt = now
			if err := tx.Save(&device).Error; err != nil {
				return err
			}
		}

		// Revoke previous tokens for this device so only one active token exists
		var latestToken models.DeviceToken
		nextVersion := 1
		if err := tx.Where("device_id = ?", deviceID).Order("token_version DESC").First(&latestToken).Error; err == nil {
			nextVersion = latestToken.TokenVersion + 1
		}
		_ = tx.Model(&models.DeviceToken{}).
			Where("device_id = ? AND status = ?", deviceID, models.TokenStatusActive).
			Update("status", models.TokenStatusRevoked).Error

		tokenRecord := models.DeviceToken{
			UserID:       userID,
			DeviceID:     deviceID,
			TokenVersion: nextVersion,
			Status:       models.TokenStatusActive,
			TokenHash:    tokenHash,
			IssuedAt:     now,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		if err := tx.Create(&tokenRecord).Error; err != nil {
			return err
		}

		s.logAuditTx(tx, "device_registered", &userID, &deviceID, "installer", map[string]interface{}{
			"fingerprint":   fingerprint,
			"token_version": nextVersion,
		})
		s.logAuditTx(tx, "token_issued", &userID, &deviceID, "system", map[string]interface{}{
			"token_version": nextVersion,
			"status":        models.TokenStatusActive,
		})

		return nil
	})

	if err != nil {
		return "", time.Time{}, err
	}

	return rawToken, now, nil
}

// ValidateToken checks if a given token is active and verifies whether monthly OTP re-verification is due.
func (s *Service) ValidateToken(deviceID, rawToken string) (bool, string, *models.PortalUser, error) {
	tokenHash := HashToken(rawToken)

	var token models.DeviceToken
	err := database.DB.Where("device_id = ? AND token_hash = ?", deviceID, tokenHash).First(&token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, "invalid_token", nil, nil
	} else if err != nil {
		return false, "db_error", nil, err
	}

	if token.Status != models.TokenStatusActive {
		return false, "revoked_by_admin", nil, nil
	}

	var device models.Device
	if err := database.DB.Where("id = ?", deviceID).First(&device).Error; err != nil {
		return false, "device_not_found", nil, nil
	}

	// Check 30-day monthly OTP re-verification requirement
	if time.Since(device.LastOtpVerifiedAt) > monthlyReverifyDuration {
		var latestReq models.MonthlyVerificationRequest
		if err := database.DB.Where("device_id = ?", deviceID).Order("created_at DESC").First(&latestReq).Error; err == nil {
			if latestReq.Status == models.MonthlyStatusPendingApproval {
				return false, "monthly_approval_pending", nil, nil
			}
		}
		return false, "otp_reverification_required", nil, nil
	}

	var user models.PortalUser
	if err := database.DB.Where("id = ?", token.UserID).First(&user).Error; err != nil {
		return false, "user_not_found", nil, nil
	}

	return true, "", &user, nil
}

// RequestActivation creates a pending activation request for a blocked device.
func (s *Service) RequestActivation(deviceID, domain string) (string, error) {
	var device models.Device
	if err := database.DB.Where("id = ?", deviceID).First(&device).Error; err != nil {
		return "", ErrDeviceNotFound
	}

	requestID, err := randomHex(16)
	if err != nil {
		return "", err
	}

	now := time.Now()
	record := models.ActivationRequest{
		ID:              requestID,
		UserID:          device.UserID,
		DeviceID:        deviceID,
		DomainRequested: domain,
		Status:          models.ActivationStatusPending,
		RequestedAt:     now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := database.DB.Create(&record).Error; err != nil {
		return "", err
	}

	s.LogAudit("activation_requested", &device.UserID, &deviceID, fmt.Sprintf("user:%d", device.UserID), map[string]interface{}{
		"domain":     domain,
		"request_id": requestID,
	})

	return requestID, nil
}

// CheckActivation inspects the latest activation request for a device and returns status, new token (if approved), and reason.
func (s *Service) CheckActivation(deviceID string) (string, string, string, error) {
	var req models.ActivationRequest
	err := database.DB.Where("device_id = ?", deviceID).Order("requested_at DESC").First(&req).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "not_found", "", "", nil
	} else if err != nil {
		return "", "", "", err
	}

	switch req.Status {
	case models.ActivationStatusPending:
		if time.Since(req.RequestedAt) > 7*24*time.Hour {
			return "expired", "", "Activation request has expired after 7 days. Please submit a new request.", nil
		}
		return "pending", "", "", nil
	case models.ActivationStatusRejected:
		return "rejected", "", req.RejectionReason, nil
	case models.ActivationStatusApproved:
		return "approved", req.NewTokenRaw, "", nil
	default:
		return string(req.Status), "", "", nil
	}
}

// SendMonthlyOtp sends a 6-digit OTP code to the current user's email address for 30-day device re-verification.
func (s *Service) SendMonthlyOtp(deviceID string) (string, string, error) {
	var device models.Device
	if err := database.DB.Where("id = ?", deviceID).First(&device).Error; err != nil {
		return "", "", ErrDeviceNotFound
	}

	var user models.PortalUser
	if err := database.DB.Where("id = ?", device.UserID).First(&user).Error; err != nil {
		user = models.PortalUser{FullName: "Staff User"}
	}

	requestID, err := randomHex(16)
	if err != nil {
		return "", "", err
	}
	otp, err := randomOtp()
	if err != nil {
		return "", "", err
	}

	record := models.MonthlyVerificationRequest{
		ID:          requestID,
		UserID:      device.UserID,
		DeviceID:    deviceID,
		OtpCode:     otp,
		OtpVerified: false,
		Status:      models.MonthlyStatusPendingOtp,
		RequestedAt: time.Now(),
		CreatedAt:   time.Now(),
	}
	if err := database.DB.Create(&record).Error; err != nil {
		return "", "", err
	}

	// Target the current user's email address
	recipient := strings.TrimSpace(user.Email)
	if recipient == "" {
		recipient = strings.TrimSpace(s.cfg.InstallerAdminEmail)
	}
	if recipient == "" {
		recipient = s.cfg.SMTPFromAddress
	}

	workstation := device.MachineFingerprint
	if workstation == "" {
		workstation = device.ID
	}

	heading := "Monthly Security Verification Code"
	message := fmt.Sprintf(
		"Hello %s,\n\nA routine 30-day security re-verification is required on your workstation (%s). Please enter this 6-digit OTP code in the ARMSS Gateway desktop application to proceed with your verification request.",
		user.FullName, workstation,
	)

	err = s.mail.SendOTP(recipient, "ARMSS Gateway Monthly Security Verification",
		heading,
		message,
		otp)
	if err != nil {
		return "", "", fmt.Errorf("sending email: %w", err)
	}

	masked := maskEmail(recipient)
	return requestID, masked, nil
}

// VerifyMonthlyOtp validates the OTP code entered by the user.
// Access is NOT unlocked here — the user must request admin approval next.
func (s *Service) VerifyMonthlyOtp(deviceID, requestID, otp string) (bool, error) {
	var device models.Device
	if err := database.DB.Where("id = ?", deviceID).First(&device).Error; err != nil {
		return false, ErrDeviceNotFound
	}

	var req models.MonthlyVerificationRequest
	if err := database.DB.Where("id = ? AND device_id = ?", requestID, deviceID).First(&req).Error; err != nil {
		// Fallback check in InstallerOtpRequest for backward compatibility
		return s.verifyLegacyMonthlyOtp(deviceID, requestID, otp)
	}

	if req.OtpCode != otp {
		s.LogAudit("monthly_otp_verification_failed", &device.UserID, &deviceID, fmt.Sprintf("user:%d", device.UserID), map[string]interface{}{
			"attempted_at": time.Now(),
			"request_id":   requestID,
		})
		return false, nil
	}

	now := time.Now()
	if err := database.DB.Model(&req).Updates(map[string]interface{}{
		"otp_verified":    true,
		"otp_verified_at": now,
		"updated_at":      now,
	}).Error; err != nil {
		return false, err
	}

	s.LogAudit("monthly_otp_verification_success", &device.UserID, &deviceID, fmt.Sprintf("user:%d", device.UserID), map[string]interface{}{
		"verified_at": now,
		"request_id":  requestID,
	})
	return true, nil
}

// RequestMonthlyApproval transitions a verified OTP request to pending administrator approval.
func (s *Service) RequestMonthlyApproval(deviceID, requestID string) (bool, error) {
	var device models.Device
	if err := database.DB.Where("id = ?", deviceID).First(&device).Error; err != nil {
		return false, ErrDeviceNotFound
	}

	var req models.MonthlyVerificationRequest
	if err := database.DB.Where("id = ? AND device_id = ?", requestID, deviceID).First(&req).Error; err != nil {
		return false, errors.New("monthly verification request not found")
	}

	if !req.OtpVerified {
		return false, errors.New("OTP must be verified before requesting administrator approval")
	}

	now := time.Now()
	if err := database.DB.Model(&req).Updates(map[string]interface{}{
		"status":     models.MonthlyStatusPendingApproval,
		"updated_at": now,
	}).Error; err != nil {
		return false, err
	}

	s.LogAudit("monthly_approval_requested", &device.UserID, &deviceID, fmt.Sprintf("user:%d", device.UserID), map[string]interface{}{
		"requested_at": now,
		"request_id":   requestID,
	})
	return true, nil
}

// CheckMonthlyStatus returns the latest monthly verification state for a device.
func (s *Service) CheckMonthlyStatus(deviceID string) (dto.MonthlyStatusResponse, error) {
	var device models.Device
	if err := database.DB.Where("id = ?", deviceID).First(&device).Error; err != nil {
		return dto.MonthlyStatusResponse{Status: "none"}, ErrDeviceNotFound
	}

	isReverifyRequired := time.Since(device.LastOtpVerifiedAt) > monthlyReverifyDuration

	var req models.MonthlyVerificationRequest
	err := database.DB.Where("device_id = ?", deviceID).Order("created_at DESC").First(&req).Error
	if err != nil {
		return dto.MonthlyStatusResponse{
			Status:             "none",
			IsReverifyRequired: isReverifyRequired,
		}, nil
	}

	return dto.MonthlyStatusResponse{
		Status:             string(req.Status),
		IsReverifyRequired: isReverifyRequired,
		RequestID:          req.ID,
		RequestedAt:        &req.RequestedAt,
		ApprovedAt:         req.ApprovedAt,
		RejectionReason:    req.RejectionReason,
	}, nil
}

func (s *Service) verifyLegacyMonthlyOtp(deviceID, requestID, otp string) (bool, error) {
	var device models.Device
	if err := database.DB.Where("id = ?", deviceID).First(&device).Error; err != nil {
		return false, ErrDeviceNotFound
	}
	result := database.DB.Model(&models.InstallerOtpRequest{}).
		Where("id = ? AND otp_code = ? AND verified = ? AND expires_at > ?", requestID, otp, false, time.Now()).
		Update("verified", true)
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected == 1, nil
}

func (s *Service) LogAudit(eventType string, userID *uint, deviceID *string, actor string, metadata map[string]interface{}) {
	s.logAuditTx(database.DB, eventType, userID, deviceID, actor, metadata)
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

func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}
	name, domain := parts[0], parts[1]
	if len(name) <= 2 {
		return name[:1] + "*@" + domain
	}
	return name[:2] + strings.Repeat("*", len(name)-2) + "@" + domain
}

func randomHex(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomOtp() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
