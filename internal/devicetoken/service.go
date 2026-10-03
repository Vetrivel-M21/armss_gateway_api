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
	"armss-gateway/backend/internal/mail"
	"armss-gateway/backend/internal/models"

	"gorm.io/gorm"
)

const otpTTL = 15 * time.Minute
const monthlyReverifyDuration = 30 * 24 * time.Hour

var ErrInvalidCredentials = errors.New("invalid credentials or inactive account")
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
			return nil, ErrInvalidCredentials
		}
		if !user.IsActive || user.Password != password {
			return nil, ErrInvalidCredentials
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

// SendMonthlyOtp sends a 6-digit OTP code to the registered email address of the device's user.
func (s *Service) SendMonthlyOtp(deviceID string) (string, string, error) {
	var device models.Device
	if err := database.DB.Where("id = ?", deviceID).First(&device).Error; err != nil {
		return "", "", ErrDeviceNotFound
	}

	var user models.PortalUser
	if err := database.DB.Where("id = ?", device.UserID).First(&user).Error; err != nil {
		return "", "", ErrUserNotFound
	}

	requestID, err := randomHex(16)
	if err != nil {
		return "", "", err
	}
	otp, err := randomOtp()
	if err != nil {
		return "", "", err
	}

	record := models.InstallerOtpRequest{
		ID:        requestID,
		OtpCode:   otp,
		ExpiresAt: time.Now().Add(otpTTL),
		Verified:  false,
		CreatedAt: time.Now(),
	}
	if err := database.DB.Create(&record).Error; err != nil {
		return "", "", err
	}

	err = s.mail.SendOTP(user.Email, "ARMSS Gateway Monthly Security Verification",
		"Monthly Security Verification",
		fmt.Sprintf("Hello %s, please enter this OTP in your ARMSS Gateway desktop application to complete your routine 30-day security check.", user.FullName),
		otp)
	if err != nil {
		return "", "", fmt.Errorf("sending email: %w", err)
	}

	masked := maskEmail(user.Email)
	return requestID, masked, nil
}

// VerifyMonthlyOtp validates the OTP code and refreshes last_otp_verified_at.
func (s *Service) VerifyMonthlyOtp(deviceID, requestID, otp string) (bool, error) {
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

	if result.RowsAffected == 1 {
		now := time.Now()
		database.DB.Model(&device).Update("last_otp_verified_at", now)
		s.LogAudit("otp_reverification_success", &device.UserID, &deviceID, fmt.Sprintf("user:%d", device.UserID), map[string]interface{}{
			"verified_at": now,
		})
		return true, nil
	}

	s.LogAudit("otp_reverification_failed", &device.UserID, &deviceID, fmt.Sprintf("user:%d", device.UserID), map[string]interface{}{
		"attempted_at": time.Now(),
	})
	return false, nil
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
