package portaladmin

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"armss-gateway/backend/internal/database"
	"armss-gateway/backend/internal/dto"
	"armss-gateway/backend/internal/models"

	"gorm.io/gorm"
)

type Service struct{}

func NewService() *Service {
	return &Service{}
}

func (s *Service) ListLinks(includeInactive bool) ([]models.PortalLink, error) {
	var links []models.PortalLink
	query := database.DB.Order("sort_order ASC, id ASC")
	if !includeInactive {
		query = query.Where("is_active = ?", true)
	}
	return links, query.Find(&links).Error
}

func (s *Service) SaveLink(req dto.PortalLinkRequest) (*models.PortalLink, error) {
	linkKey := strings.TrimSpace(req.Key)
	if linkKey == "" {
		linkKey = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(req.Name), " ", "_"))
	}
	parsed, err := url.Parse(strings.TrimSpace(req.URL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("url must be a valid http or https URL")
	}
	active := true
	if req.IsActive != nil {
		active = *req.IsActive
	}
	icon := req.Icon
	if icon == "" {
		icon = "apps_outlined"
	}
	color := req.Color
	if color == "" {
		color = "#0284C7"
	}
	var link models.PortalLink
	err = database.DB.Where("link_key = ?", linkKey).First(&link).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		link = models.PortalLink{LinkKey: linkKey}
	} else if err != nil {
		return nil, err
	}
	link.TabName, link.Name, link.URL = strings.TrimSpace(req.TabName), strings.TrimSpace(req.Name), strings.TrimSpace(req.URL)
	link.Icon, link.Color, link.SortOrder, link.IsActive = icon, color, req.SortOrder, active
	if err := database.DB.Save(&link).Error; err != nil {
		return nil, err
	}
	return &link, nil
}

func (s *Service) DeleteLink(key string) error {
	return database.DB.Model(&models.PortalLink{}).Where("link_key = ?", key).Update("is_active", false).Error
}

func (s *Service) SetLinkImage(key, imagePath string) error {
	return database.DB.Model(&models.PortalLink{}).Where("link_key = ?", key).Update("image_path", imagePath).Error
}

func (s *Service) ListUsers() ([]dto.AdminUserResponse, error) {
	var users []models.PortalUser
	if err := database.DB.Find(&users).Error; err != nil {
		return nil, err
	}

	var grants []models.PortalUserGrant
	if err := database.DB.Find(&grants).Error; err != nil {
		return nil, err
	}
	keysByUser := make(map[uint][]string)
	for _, g := range grants {
		keysByUser[g.UserID] = append(keysByUser[g.UserID], g.LinkKey)
	}

	result := make([]dto.AdminUserResponse, len(users))
	for i, u := range users {
		role := u.Role
		if role == "" {
			role = "user"
		}
		result[i] = dto.AdminUserResponse{
			ID:              u.ID,
			Username:        u.Username,
			Email:           u.Email,
			FullName:        u.FullName,
			Department:      u.Department,
			Branch:          u.Branch,
			Role:            role,
			BoundDeviceID:   u.BoundDeviceID,
			LastLoginAt:     u.LastLoginAt,
			IsActive:        u.IsActive,
			GrantedLinkKeys: keysByUser[u.ID],
		}
	}
	return result, nil
}

// ReleaseDeviceLock releases the 1-to-1 device lock and invalidates active sessions
// for a specific user, permitting them to bind a new device.
func (s *Service) ReleaseDeviceLock(userID uint) error {
	now := time.Now()
	err := database.DB.Model(&models.PortalUser{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"bound_device_id":      "",
		"active_session_token": "",
		"updated_at":           now,
	}).Error
	if err == nil {
		_ = database.DB.Create(&models.AuditLog{
			EventType: "DEVICE_LOCK_RELEASED",
			Actor:     "admin",
			UserID:    &userID,
			Metadata:  fmt.Sprintf("Device lock released for user ID %d", userID),
			CreatedAt: now,
		}).Error
	}
	return err
}

// SetRole changes a user's role ('admin' or 'user').
func (s *Service) SetRole(userID uint, role string) error {
	trimmed := strings.ToLower(strings.TrimSpace(role))
	if trimmed != "admin" && trimmed != "user" {
		return fmt.Errorf("invalid role: must be 'admin' or 'user'")
	}
	return database.DB.Model(&models.PortalUser{}).Where("id = ?", userID).Update("role", trimmed).Error
}

// SetActive approves (or revokes) a registered account — separate from
// SetGrants so an admin can approve first and decide specific links later.
func (s *Service) SetActive(userID uint, isActive bool) error {
	return database.DB.Model(&models.PortalUser{}).Where("id = ?", userID).Update("is_active", isActive).Error
}

// GetPassword returns a user's plaintext password for the admin UI's
// "view password" action — consistent with the accepted plaintext-storage
// tradeoff, since it's only reachable by an already-admin-authenticated
// request.
func (s *Service) GetPassword(userID uint) (string, error) {
	var user models.PortalUser
	if err := database.DB.Select("password").Where("id = ?", userID).First(&user).Error; err != nil {
		return "", err
	}
	return user.Password, nil
}

// SetPassword lets an admin directly set a user's password, separate from
// the user's own OTP-verified forgot-password flow.
func (s *Service) SetPassword(userID uint, newPassword string) error {
	return database.DB.Model(&models.PortalUser{}).Where("id = ?", userID).Update("password", newPassword).Error
}

// SetGrants replaces a user's full grant set with exactly the given keys —
// the admin UI sends the whole desired set (checkboxes), not incremental
// add/remove calls.
func (s *Service) SetGrants(userID uint, linkKeys []string) error {
	return database.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&models.PortalUserGrant{}).Error; err != nil {
			return err
		}
		for _, key := range linkKeys {
			if key == "" {
				continue
			}
			if err := tx.Create(&models.PortalUserGrant{UserID: userID, LinkKey: key}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteUser permanently removes a portal user and their associated grants,
// OTP requests, devices, tokens, and activation requests.
func (s *Service) DeleteUser(userID uint) error {
	return database.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&models.PortalUserGrant{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&models.PortalUserOtpRequest{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&models.ActivationRequest{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&models.DeviceToken{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&models.Device{}).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.AuditLog{}).Where("user_id = ?", userID).Update("user_id", nil).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", userID).Delete(&models.PortalUser{}).Error
	})
}

// GetInstallerPassword reads the dynamic installer password from system_settings,
// falling back to defaultPassword from configuration.
func (s *Service) GetInstallerPassword(defaultPassword string) (string, error) {
	var setting models.SystemSetting
	if err := database.DB.Where("`key` = ?", "installer_password").First(&setting).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return defaultPassword, nil
		}
		return "", err
	}
	if setting.Value == "" {
		return defaultPassword, nil
	}
	return setting.Value, nil
}

// SetInstallerPassword updates or inserts the dynamic installer password in system_settings
// and records an audit log entry.
func (s *Service) SetInstallerPassword(newPassword string, actor string) error {
	now := time.Now()
	var setting models.SystemSetting
	err := database.DB.Where("`key` = ?", "installer_password").First(&setting).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		setting = models.SystemSetting{
			Key:       "installer_password",
			Value:     newPassword,
			UpdatedAt: now,
		}
		if err := database.DB.Create(&setting).Error; err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if err := database.DB.Model(&models.SystemSetting{}).Where("`key` = ?", "installer_password").Updates(map[string]interface{}{
			"value":      newPassword,
			"updated_at": now,
		}).Error; err != nil {
			return err
		}
	}

	if actor == "" {
		actor = "admin"
	}
	_ = database.DB.Create(&models.AuditLog{
		EventType: "INSTALLER_PASSWORD_UPDATED",
		Actor:     actor,
		Metadata:  "Central installation password updated by admin",
		CreatedAt: now,
	}).Error

	return nil
}

// GetInstallerAdminEmail reads the dynamic installer admin email from system_settings,
// falling back to defaultEmail from configuration.
func (s *Service) GetInstallerAdminEmail(defaultEmail string) (string, error) {
	var setting models.SystemSetting
	if err := database.DB.Where("`key` = ?", "installer_admin_email").First(&setting).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return defaultEmail, nil
		}
		return "", err
	}
	val := strings.TrimSpace(setting.Value)
	if val == "" {
		return defaultEmail, nil
	}
	return val, nil
}

// SetInstallerAdminEmail updates or inserts the dynamic installer admin email in system_settings
// and records an audit log entry.
func (s *Service) SetInstallerAdminEmail(newEmail string, actor string) error {
	now := time.Now()
	cleanEmail := strings.TrimSpace(newEmail)

	var setting models.SystemSetting
	err := database.DB.Where("`key` = ?", "installer_admin_email").First(&setting).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		setting = models.SystemSetting{
			Key:       "installer_admin_email",
			Value:     cleanEmail,
			UpdatedAt: now,
		}
		if err := database.DB.Create(&setting).Error; err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if err := database.DB.Model(&models.SystemSetting{}).Where("`key` = ?", "installer_admin_email").Updates(map[string]interface{}{
			"value":      cleanEmail,
			"updated_at": now,
		}).Error; err != nil {
			return err
		}
	}

	if actor == "" {
		actor = "admin"
	}
	_ = database.DB.Create(&models.AuditLog{
		EventType: "INSTALLER_EMAIL_UPDATED",
		Actor:     actor,
		Metadata:  fmt.Sprintf("Installer OTP recipient email updated to %s by %s", cleanEmail, actor),
		CreatedAt: now,
	}).Error

	return nil
}

func (s *Service) GetTokenRestrictionEnabled() (bool, error) {
	var setting models.SystemSetting
	if err := database.DB.Where("`key` = ?", "token_restriction_enabled").First(&setting).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return true, nil
		}
		return true, err
	}
	return setting.Value != "false", nil
}

func (s *Service) SetTokenRestrictionEnabled(enabled bool, actor string) error {
	now := time.Now()
	value := "false"
	if enabled {
		value = "true"
	}
	var setting models.SystemSetting
	err := database.DB.Where("`key` = ?", "token_restriction_enabled").First(&setting).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := database.DB.Create(&models.SystemSetting{Key: "token_restriction_enabled", Value: value, UpdatedAt: now}).Error; err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if err := database.DB.Model(&models.SystemSetting{}).Where("`key` = ?", "token_restriction_enabled").Updates(map[string]interface{}{"value": value, "updated_at": now}).Error; err != nil {
		return err
	}
	if actor == "" {
		actor = "admin"
	}
	return database.DB.Create(&models.AuditLog{EventType: "TOKEN_RESTRICTION_UPDATED", Actor: actor, Metadata: "Gateway token restriction updated to " + value, CreatedAt: now}).Error
}

// GetActiveInstallerOtp returns the most recent unverified, unexpired installer OTP.
func (s *Service) GetActiveInstallerOtp() (map[string]interface{}, error) {
	var otp models.InstallerOtpRequest
	now := time.Now()
	err := database.DB.Where("verified = ? AND expires_at > ?", false, now).Order("created_at DESC").First(&otp).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return map[string]interface{}{
				"has_active_otp": false,
			}, nil
		}
		return nil, err
	}

	expiresIn := int(time.Until(otp.ExpiresAt).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}

	return map[string]interface{}{
		"has_active_otp": true,
		"otp_code":       otp.OtpCode,
		"request_id":     otp.ID,
		"expires_in":     expiresIn,
		"created_at":     otp.CreatedAt.Format(time.RFC3339),
	}, nil
}

func (s *Service) GetAdminPassword(fallback string) (string, error) {
	var setting models.SystemSetting
	err := database.DB.Where("`key` = ?", "admin_password").First(&setting).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return fallback, nil
	}
	if err != nil {
		return "", err
	}
	val := strings.TrimSpace(setting.Value)
	if val == "" {
		return fallback, nil
	}
	return val, nil
}

func (s *Service) SetAdminPassword(newPassword, actor string) error {
	trimmed := strings.TrimSpace(newPassword)
	if len(trimmed) < 4 {
		return fmt.Errorf("password must be at least 4 characters")
	}
	now := time.Now()
	var setting models.SystemSetting
	err := database.DB.Where("`key` = ?", "admin_password").First(&setting).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := database.DB.Create(&models.SystemSetting{Key: "admin_password", Value: trimmed, UpdatedAt: now}).Error; err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if err := database.DB.Model(&models.SystemSetting{}).Where("`key` = ?", "admin_password").Updates(map[string]interface{}{"value": trimmed, "updated_at": now}).Error; err != nil {
		return err
	}
	_ = database.DB.Model(&models.PortalUser{}).Where("username = ?", "admin").Update("password", trimmed).Error
	if actor == "" {
		actor = "admin"
	}
	return database.DB.Create(&models.AuditLog{EventType: "ADMIN_PASSWORD_UPDATED", Actor: actor, Metadata: "Admin password updated", CreatedAt: now}).Error
}
