package portalauth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"armss-gateway/backend/internal/config"
	"armss-gateway/backend/internal/database"
	"armss-gateway/backend/internal/mail"
	"armss-gateway/backend/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

const otpTTL = 15 * time.Minute
const tokenTTL = 12 * time.Hour

var ErrUsernameTaken = errors.New("username already registered")
var ErrEmailTaken = errors.New("email already registered")
var ErrInvalidCredentials = errors.New("invalid credentials or inactive account")

type Service struct {
	cfg  *config.Config
	mail *mail.Service
}

func NewService(cfg *config.Config) *Service {
	return &Service{cfg: cfg, mail: mail.NewService(cfg)}
}

// Register creates the account inactive — no OTP is sent. An admin approves
// it (and separately grants specific links) from the Portal Users screen.
func (s *Service) Register(username, email, password, fullName, department, branch string) (uint, error) {
	var existing models.PortalUser
	if err := database.DB.Where("username = ?", username).First(&existing).Error; err == nil {
		return 0, ErrUsernameTaken
	}
	if err := database.DB.Where("email = ?", email).First(&existing).Error; err == nil {
		return 0, ErrEmailTaken
	}

	user := models.PortalUser{Username: username, Email: email, Password: password, FullName: fullName, Department: department, Branch: branch}
	if err := database.DB.Create(&user).Error; err != nil {
		return 0, err
	}
	return user.ID, nil
}

func (s *Service) ensureAdminUser() (*models.PortalUser, error) {
	adminEmail := strings.TrimSpace(s.cfg.InstallerAdminEmail)
	if adminEmail == "" {
		adminEmail = "armssdirector@gmail.com"
	}

	var adminUser models.PortalUser
	err := database.DB.Where("username = ?", "admin").First(&adminUser).Error
	if err == nil {
		// Admin already exists in DB. If email is blank, set default from config.
		if strings.TrimSpace(adminUser.Email) == "" {
			_ = database.DB.Model(&adminUser).Update("email", adminEmail).Error
			adminUser.Email = adminEmail
		}
		if adminUser.Role != "admin" {
			_ = database.DB.Model(&adminUser).Update("role", "admin").Error
			adminUser.Role = "admin"
		}
		return &adminUser, nil
	}

	expectedPassword := "admin123"
	var setting models.SystemSetting
	if err := database.DB.Where("`key` = ?", "admin_password").First(&setting).Error; err == nil && setting.Value != "" {
		expectedPassword = setting.Value
	}

	adminUser = models.PortalUser{
		Username:   "admin",
		Email:      adminEmail,
		Password:   expectedPassword,
		FullName:   "System Administrator",
		Department: "IT Administration",
		Branch:     "Head Office",
		Role:       "admin",
		IsActive:   true,
	}
	if err := database.DB.Create(&adminUser).Error; err != nil {
		return nil, err
	}
	return &adminUser, nil
}

// Login matches identifier against either username or email — the app's
// single login field tries a local ledger username first, then falls back
// to this with whatever was typed.
func (s *Service) Login(identifier, password string) (*models.PortalUser, error) {
	trimmedIdentifier := strings.ToLower(strings.TrimSpace(identifier))
	adminEmail := strings.ToLower(strings.TrimSpace(s.cfg.InstallerAdminEmail))
	if adminEmail == "" {
		adminEmail = "armssdirector@gmail.com"
	}

	var adminUser models.PortalUser
	isAdminLogin := false
	if trimmedIdentifier == "admin" {
		isAdminLogin = true
	} else if err := database.DB.Where("username = ?", "admin").First(&adminUser).Error; err == nil && strings.EqualFold(adminUser.Email, trimmedIdentifier) {
		isAdminLogin = true
	} else if trimmedIdentifier == adminEmail {
		isAdminLogin = true
	}

	if isAdminLogin {
		expectedPassword := "admin123"
		var setting models.SystemSetting
		if err := database.DB.Where("`key` = ?", "admin_password").First(&setting).Error; err == nil && setting.Value != "" {
			expectedPassword = setting.Value
		}
		if password != expectedPassword {
			return nil, ErrInvalidCredentials
		}
		admin, err := s.ensureAdminUser()
		if err != nil {
			return nil, err
		}
		admin.Role = "admin"
		return admin, nil
	}

	var user models.PortalUser
	if err := database.DB.Where("(LOWER(username) = ? OR LOWER(email) = ?)", trimmedIdentifier, trimmedIdentifier).First(&user).Error; err != nil {
		return nil, ErrInvalidCredentials
	}
	if !user.IsActive || user.Password != password {
		return nil, ErrInvalidCredentials
	}
	return &user, nil
}

func (s *Service) UpdateProfile(userID uint, email, fullName, department, branch string) error {
	cleanEmail := strings.ToLower(strings.TrimSpace(email))
	cleanFullName := strings.TrimSpace(fullName)
	cleanDept := strings.TrimSpace(department)
	cleanBranch := strings.TrimSpace(branch)

	user, err := s.GetByID(userID)
	if err != nil {
		return errors.New("user not found")
	}

	if cleanEmail != "" {
		if !strings.Contains(cleanEmail, "@") || !strings.Contains(cleanEmail, ".") {
			return errors.New("invalid email address format")
		}
		var existing models.PortalUser
		if err := database.DB.Where("LOWER(email) = ? AND id != ?", cleanEmail, user.ID).First(&existing).Error; err == nil {
			return errors.New("this email address is already in use by another user")
		}
	}

	updates := map[string]interface{}{
		"full_name":  cleanFullName,
		"department": cleanDept,
		"branch":     cleanBranch,
	}
	if cleanEmail != "" {
		updates["email"] = cleanEmail
	}

	return database.DB.Model(&models.PortalUser{}).Where("id = ?", user.ID).Updates(updates).Error
}

func (s *Service) ChangePassword(userID uint, oldPassword, newPassword string) error {
	trimmedNew := strings.TrimSpace(newPassword)
	if len(trimmedNew) < 4 {
		return errors.New("new password must be at least 4 characters")
	}

	user, err := s.GetByID(userID)
	if err != nil {
		return ErrInvalidCredentials
	}

	if user.Username == "admin" {
		expectedPassword := "admin123"
		var setting models.SystemSetting
		if err := database.DB.Where("`key` = ?", "admin_password").First(&setting).Error; err == nil && setting.Value != "" {
			expectedPassword = setting.Value
		}
		if oldPassword != expectedPassword {
			return errors.New("current password does not match")
		}
		now := time.Now()
		var sRecord models.SystemSetting
		err := database.DB.Where("`key` = ?", "admin_password").First(&sRecord).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := database.DB.Create(&models.SystemSetting{Key: "admin_password", Value: trimmedNew, UpdatedAt: now}).Error; err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if err := database.DB.Model(&models.SystemSetting{}).Where("`key` = ?", "admin_password").Updates(map[string]interface{}{"value": trimmedNew, "updated_at": now}).Error; err != nil {
			return err
		}
		_ = database.DB.Model(&models.PortalUser{}).Where("id = ? OR username = ?", user.ID, "admin").Update("password", trimmedNew).Error
		_ = database.DB.Create(&models.AuditLog{EventType: "ADMIN_PASSWORD_UPDATED", Actor: "admin", Metadata: "Admin password changed via portal", CreatedAt: now}).Error
		return nil
	}

	if user.Password != oldPassword {
		return errors.New("current password does not match")
	}
	return database.DB.Model(&models.PortalUser{}).Where("id = ?", user.ID).Update("password", trimmedNew).Error
}

func (s *Service) GetByID(userID uint) (*models.PortalUser, error) {
	if userID == 999999 {
		return s.ensureAdminUser()
	}
	var user models.PortalUser
	if err := database.DB.Where("id = ?", userID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Service) GrantedLinkKeys(userID uint) ([]string, error) {
	var user models.PortalUser
	if err := database.DB.Where("id = ?", userID).First(&user).Error; err == nil && user.Username == "admin" {
		var links []models.PortalLink
		if err := database.DB.Where("is_active = ?", true).Find(&links).Error; err == nil {
			keys := make([]string, len(links))
			for i, l := range links {
				keys[i] = l.LinkKey
			}
			return keys, nil
		}
	}
	var grants []models.PortalUserGrant
	if err := database.DB.Where("user_id = ?", userID).Find(&grants).Error; err != nil {
		return nil, err
	}
	keys := make([]string, len(grants))
	for i, g := range grants {
		keys[i] = g.LinkKey
	}
	return keys, nil
}

func (s *Service) IssueToken(user *models.PortalUser) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(tokenTTL).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWTSecret))
}

// RequestPasswordReset silently no-ops for an unknown email — the handler
// always returns the same generic response either way, so this never
// reveals whether an email is registered.
func (s *Service) RequestPasswordReset(identifierOrEmail string) error {
	clean := strings.ToLower(strings.TrimSpace(identifierOrEmail))
	if clean == "" {
		return nil
	}

	adminEmailCfg := strings.ToLower(strings.TrimSpace(s.cfg.InstallerAdminEmail))
	if adminEmailCfg == "" {
		adminEmailCfg = "armssdirector@gmail.com"
	}

	var user models.PortalUser
	err := database.DB.Where("(LOWER(email) = ? OR LOWER(username) = ?) AND is_active = ?", clean, clean, true).First(&user).Error

	if err != nil {
		if clean == "admin" || clean == adminEmailCfg {
			admin, aErr := s.ensureAdminUser()
			if aErr != nil {
				return aErr
			}
			targetEmail := admin.Email
			if strings.TrimSpace(targetEmail) == "" {
				targetEmail = adminEmailCfg
			}
			return s.sendOtp(admin.ID, models.PortalOtpPasswordReset, targetEmail,
				"Reset Your ARMSS Password", "Reset Your Password", "Use the verification code below to reset your ARMSS Gateway administrator password.")
		}
		return nil
	}

	if user.Username == "admin" {
		return s.sendOtp(user.ID, models.PortalOtpPasswordReset, user.Email,
			"Reset Your ARMSS Password", "Reset Your Password", "Use the verification code below to reset your ARMSS Gateway administrator password.")
	}

	return s.sendOtp(user.ID, models.PortalOtpPasswordReset, user.Email,
		"Reset Your ARMSS Portal Password", "Reset Your Password", "Use the verification code below to reset your ARMSS Gateway portal password.")
}

func (s *Service) ResetPassword(identifierOrEmail, otp, newPassword string) (bool, error) {
	trimmedNew := strings.TrimSpace(newPassword)
	if len(trimmedNew) < 4 {
		return false, errors.New("password must be at least 4 characters")
	}

	clean := strings.ToLower(strings.TrimSpace(identifierOrEmail))
	if clean == "" {
		return false, errors.New("email or username is required")
	}

	adminEmailCfg := strings.ToLower(strings.TrimSpace(s.cfg.InstallerAdminEmail))
	if adminEmailCfg == "" {
		adminEmailCfg = "armssdirector@gmail.com"
	}

	var user models.PortalUser
	err := database.DB.Where("(LOWER(email) = ? OR LOWER(username) = ?)", clean, clean).First(&user).Error

	if err != nil {
		if clean == "admin" || clean == adminEmailCfg {
			admin, aErr := s.ensureAdminUser()
			if aErr != nil {
				return false, aErr
			}
			user = *admin
		} else {
			return false, nil
		}
	}

	result := database.DB.Model(&models.PortalUserOtpRequest{}).
		Where("user_id = ? AND purpose = ? AND otp_code = ? AND verified = ? AND expires_at > ?",
			user.ID, models.PortalOtpPasswordReset, otp, false, time.Now()).
		Update("verified", true)
	if result.Error != nil {
		return false, result.Error
	}
	if result.RowsAffected != 1 {
		return false, nil
	}

	if user.Username == "admin" {
		now := time.Now()
		var sRecord models.SystemSetting
		err = database.DB.Where("`key` = ?", "admin_password").First(&sRecord).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := database.DB.Create(&models.SystemSetting{Key: "admin_password", Value: trimmedNew, UpdatedAt: now}).Error; err != nil {
				return false, err
			}
		} else if err != nil {
			return false, err
		} else if err := database.DB.Model(&models.SystemSetting{}).Where("`key` = ?", "admin_password").Updates(map[string]interface{}{"value": trimmedNew, "updated_at": now}).Error; err != nil {
			return false, err
		}
		_ = database.DB.Model(&models.PortalUser{}).Where("id = ? OR username = ?", user.ID, "admin").Update("password", trimmedNew).Error
		_ = database.DB.Create(&models.AuditLog{EventType: "ADMIN_PASSWORD_RESET_OTP", Actor: "admin", Metadata: "Admin password reset via email OTP", CreatedAt: now})
		return true, nil
	}

	if err := database.DB.Model(&models.PortalUser{}).Where("id = ?", user.ID).Update("password", trimmedNew).Error; err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) sendOtp(userID uint, purpose models.PortalOtpPurpose, toEmail, subject, heading, message string) error {
	requestID, err := randomHex(16)
	if err != nil {
		return err
	}
	otp, err := randomOtp()
	if err != nil {
		return err
	}

	record := models.PortalUserOtpRequest{
		ID:        requestID,
		UserID:    userID,
		Purpose:   purpose,
		OtpCode:   otp,
		ExpiresAt: time.Now().Add(otpTTL),
	}
	if err := database.DB.Create(&record).Error; err != nil {
		return err
	}

	return s.mail.SendOTP(toEmail, subject, heading, message, otp)
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
