package models

import "time"

// PortalUser is a self-registered account for the ARMSS Gateway app's portal
// tabs — a separate identity system from mis_desktop's local (offline)
// ledger login. Starts inactive until the registrant verifies their own
// email via OTP, and starts with zero grants until an admin grants access
// to individual links.
//
// Password is stored in plain text — an explicit, confirmed decision (not
// an oversight); see the ARMSS Gateway backend plan for the tradeoff.
type PortalUser struct {
	ID         uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Username   string    `gorm:"size:50;uniqueIndex;not null" json:"username"`
	Email      string    `gorm:"size:150;uniqueIndex;not null" json:"email"`
	Password   string    `gorm:"size:255;not null" json:"-"`
	FullName   string    `gorm:"size:150;not null" json:"full_name"`
	Department string    `gorm:"size:150;not null;default:''" json:"department"`
	Branch     string    `gorm:"size:150;not null;default:''" json:"branch"`
	Role       string    `gorm:"size:50;not null;default:'user'" json:"role"`
	IsActive   bool      `gorm:"default:false;not null" json:"is_active"`
	CreatedAt  time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt  time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

type PortalLink struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	LinkKey   string    `gorm:"size:100;uniqueIndex;not null" json:"key"`
	TabName   string    `gorm:"size:100;not null" json:"tab_name"`
	Name      string    `gorm:"size:150;not null" json:"name"`
	URL       string    `gorm:"size:2048;not null" json:"url"`
	Icon      string    `gorm:"size:80;not null;default:'apps_outlined'" json:"icon"`
	Color     string    `gorm:"size:20;not null;default:'#0284C7'" json:"color"`
	ImagePath *string   `gorm:"size:500" json:"image_path,omitempty"`
	SortOrder int       `gorm:"not null;default:0" json:"sort_order"`
	IsActive  bool      `gorm:"not null;default:true" json:"is_active"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (PortalLink) TableName() string { return "portal_links" }

// PortalUserGrant records that a PortalUser may see one specific portal link
// (identified by the stable `key` the Flutter app assigns each PortalLink —
// the link catalog itself stays hardcoded in the app, not in this database).
type PortalUserGrant struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID    uint      `gorm:"not null;uniqueIndex:idx_user_link" json:"user_id"`
	LinkKey   string    `gorm:"size:100;not null;uniqueIndex:idx_user_link" json:"link_key"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}

type PortalOtpPurpose string

const (
	PortalOtpPasswordReset PortalOtpPurpose = "PASSWORD_RESET"
)

// PortalUserOtpRequest backs the forgot-password flow — the OTP is always
// emailed to the user's own registered address. Registration has no OTP
// step; new accounts are approved by an admin instead.
type PortalUserOtpRequest struct {
	ID        string           `gorm:"primaryKey;size:36" json:"id"`
	UserID    uint             `gorm:"not null;index" json:"user_id"`
	Purpose   PortalOtpPurpose `gorm:"type:enum('PASSWORD_RESET');not null" json:"purpose"`
	OtpCode   string           `gorm:"size:6;not null" json:"-"`
	ExpiresAt time.Time        `gorm:"not null" json:"expires_at"`
	Verified  bool             `gorm:"default:false;not null" json:"verified"`
	CreatedAt time.Time        `gorm:"autoCreateTime" json:"created_at"`
}

// InstallerOtpRequest backs the ARMSS Gateway Windows installer's OTP gate —
// a code is emailed to the configured admin address and the installing user
// must relay it back before Setup will proceed. Single-use and short-lived.
// Not tied to any PortalUser — the installer runs before any account exists.
type InstallerOtpRequest struct {
	ID         string    `gorm:"primaryKey;size:36" json:"id"`
	Username   string    `gorm:"size:100;not null" json:"username"`
	Department string    `gorm:"size:150;not null" json:"department"`
	Branch     string    `gorm:"size:150;not null" json:"branch"`
	OtpCode    string    `gorm:"size:6;not null" json:"-"`
	ExpiresAt  time.Time `gorm:"not null" json:"expires_at"`
	Verified   bool      `gorm:"default:false;not null" json:"verified"`
	CreatedAt  time.Time `gorm:"autoCreateTime" json:"created_at"`
}

// Device represents an installation instance of the desktop application on a
// specific machine, tied to a verified PortalUser.
type Device struct {
	ID                 string      `gorm:"primaryKey;size:64" json:"device_id"`
	UserID             uint        `gorm:"not null;index" json:"user_id"`
	User               *PortalUser `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"user,omitempty"`
	MachineFingerprint string      `gorm:"size:255;not null" json:"machine_fingerprint"`
	LastOtpVerifiedAt  time.Time   `gorm:"not null" json:"last_otp_verified_at"`
	CreatedAt          time.Time   `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt          time.Time   `gorm:"autoUpdateTime" json:"updated_at"`
}

func (Device) TableName() string {
	return "devices"
}

type TokenStatus string

const (
	TokenStatusActive  TokenStatus = "active"
	TokenStatusRevoked TokenStatus = "revoked"
	TokenStatusPending TokenStatus = "pending"
)

// DeviceToken is a per-user, per-device token that gates access to company
// digital products. The raw token is hashed before storing; raw tokens are never
// kept in the database.
type DeviceToken struct {
	ID           uint        `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID       uint        `gorm:"not null;index" json:"user_id"`
	User         *PortalUser `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"user,omitempty"`
	DeviceID     string      `gorm:"size:64;not null;index:idx_tokens_device_status" json:"device_id"`
	Device       *Device     `gorm:"foreignKey:DeviceID;constraint:OnDelete:CASCADE" json:"device,omitempty"`
	TokenVersion int         `gorm:"default:1;not null" json:"token_version"`
	Status       TokenStatus `gorm:"type:enum('active','revoked','pending');default:'active';not null;index:idx_tokens_device_status" json:"status"`
	TokenHash    string      `gorm:"size:64;not null;index" json:"-"`
	IssuedAt     time.Time   `gorm:"not null" json:"issued_at"`
	ExpiresAt    *time.Time  `json:"expires_at"`
	CreatedAt    time.Time   `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time   `gorm:"autoUpdateTime" json:"updated_at"`
}

func (DeviceToken) TableName() string {
	return "device_tokens"
}

type ActivationStatus string

const (
	ActivationStatusPending  ActivationStatus = "pending"
	ActivationStatusApproved ActivationStatus = "approved"
	ActivationStatusRejected ActivationStatus = "rejected"
)

// ActivationRequest records a user's request to unblock or activate access for
// a specific device and domain after access has been revoked or expired.
type ActivationRequest struct {
	ID              string           `gorm:"primaryKey;size:36" json:"request_id"`
	UserID          uint             `gorm:"not null;index" json:"user_id"`
	User            *PortalUser      `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"user,omitempty"`
	DeviceID        string           `gorm:"size:64;not null;index" json:"device_id"`
	Device          *Device          `gorm:"foreignKey:DeviceID;constraint:OnDelete:CASCADE" json:"device,omitempty"`
	DomainRequested string           `gorm:"size:255;not null" json:"domain_requested"`
	Status          ActivationStatus `gorm:"type:enum('pending','approved','rejected');default:'pending';not null;index" json:"status"`
	ApprovedBy      *uint            `gorm:"index" json:"approved_by,omitempty"`
	Approver        *PortalUser      `gorm:"foreignKey:ApprovedBy;constraint:OnDelete:SET NULL" json:"approver,omitempty"`
	ApprovedAt      *time.Time       `json:"approved_at,omitempty"`
	RejectionReason string           `gorm:"size:255" json:"rejection_reason,omitempty"`
	NewTokenHash    string           `gorm:"size:64" json:"-"`
	NewTokenRaw     string           `gorm:"size:128" json:"-"` // cleared after one-time client pull
	RequestedAt     time.Time        `gorm:"not null" json:"requested_at"`
	CreatedAt       time.Time        `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt       time.Time        `gorm:"autoUpdateTime" json:"updated_at"`
}

func (ActivationRequest) TableName() string {
	return "activation_requests"
}

// AuditLog captures security and lifecycle events for tokens, devices, and activations.
type AuditLog struct {
	ID        uint        `gorm:"primaryKey;autoIncrement" json:"id"`
	EventType string      `gorm:"size:50;not null;index" json:"event_type"`
	UserID    *uint       `gorm:"index" json:"user_id,omitempty"`
	User      *PortalUser `gorm:"foreignKey:UserID;constraint:OnDelete:SET NULL" json:"user,omitempty"`
	DeviceID  *string     `gorm:"size:64;index" json:"device_id,omitempty"`
	Device    *Device     `gorm:"foreignKey:DeviceID;constraint:OnDelete:SET NULL" json:"device,omitempty"`
	Actor     string      `gorm:"size:100;not null" json:"actor"`
	Metadata  string      `gorm:"type:text" json:"metadata,omitempty"`
	CreatedAt time.Time   `gorm:"not null;index" json:"created_at"`
}

func (AuditLog) TableName() string {
	return "audit_log"
}

// SystemSetting stores key-value dynamic configuration entries like installer password.
type SystemSetting struct {
	Key       string    `gorm:"primaryKey;size:100" json:"key"`
	Value     string    `gorm:"type:text;not null" json:"value"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (SystemSetting) TableName() string {
	return "system_settings"
}
