package dto

import "time"

type VerifyPasswordRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password" binding:"required"`
}

type VerifyPasswordResponse struct {
	Valid    bool   `json:"valid"`
	UserID   uint   `json:"user_id,omitempty"`
	Username string `json:"username,omitempty"`
	FullName string `json:"full_name,omitempty"`
	Message  string `json:"message,omitempty"`
}

type DeviceRegisterRequest struct {
	UserID             uint   `json:"user_id"`
	DeviceID           string `json:"device_id" binding:"required"`
	MachineFingerprint string `json:"machine_fingerprint"`
}

type DeviceRegisterResponse struct {
	DeviceID string    `json:"device_id"`
	Token    string    `json:"token"`
	IssuedAt time.Time `json:"issued_at"`
}

type ValidateTokenRequest struct {
	DeviceID string `json:"device_id" binding:"required"`
	Token    string `json:"token" binding:"required"`
}

type ValidateTokenResponse struct {
	Valid    bool   `json:"valid"`
	Reason   string `json:"reason,omitempty"`
	UserID   uint   `json:"user_id,omitempty"`
	Username string `json:"username,omitempty"`
}

type RequestActivationRequest struct {
	DeviceID        string `json:"device_id" binding:"required"`
	DomainRequested string `json:"domain_requested" binding:"required"`
}

type RequestActivationResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

type CheckActivationResponse struct {
	Status  string `json:"status"` // pending | approved | rejected | not_found
	Token   string `json:"token,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type MonthlyReverifyRequestOtpRequest struct {
	DeviceID string `json:"device_id" binding:"required"`
}

type MonthlyReverifyRequestOtpResponse struct {
	RequestID string `json:"request_id"`
	SentTo    string `json:"sent_to"`
}

type MonthlyReverifyVerifyOtpRequest struct {
	DeviceID  string `json:"device_id" binding:"required"`
	RequestID string `json:"request_id" binding:"required"`
	Otp       string `json:"otp" binding:"required"`
}

type MonthlyReverifyVerifyOtpResponse struct {
	Verified bool `json:"verified"`
}

type AdminDeviceResponse struct {
	DeviceID           string    `json:"device_id"`
	UserID             uint      `json:"user_id"`
	Username           string    `json:"username"`
	Email              string    `json:"email"`
	FullName           string    `json:"full_name"`
	MachineFingerprint string    `json:"machine_fingerprint"`
	TokenStatus        string    `json:"token_status"`
	TokenVersion       int       `json:"token_version"`
	LastOtpVerifiedAt  time.Time `json:"last_otp_verified_at"`
	IsOtpExpired       bool      `json:"is_otp_expired"`
	CreatedAt          time.Time `json:"created_at"`
}

type AdminActivationRequestResponse struct {
	RequestID       string     `json:"request_id"`
	UserID          uint       `json:"user_id"`
	Username        string     `json:"username"`
	Email           string     `json:"email"`
	FullName        string     `json:"full_name"`
	DeviceID        string     `json:"device_id"`
	DomainRequested string     `json:"domain_requested"`
	Status          string     `json:"status"`
	RequestedAt     time.Time  `json:"requested_at"`
	ApprovedAt      *time.Time `json:"approved_at,omitempty"`
	RejectionReason string     `json:"rejection_reason,omitempty"`
}

type AdminRejectRequest struct {
	Reason string `json:"reason"`
}

type AdminAuditLogResponse struct {
	ID        uint      `json:"id"`
	EventType string    `json:"event_type"`
	UserID    *uint     `json:"user_id,omitempty"`
	DeviceID  *string   `json:"device_id,omitempty"`
	Actor     string    `json:"actor"`
	Metadata  string    `json:"metadata,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
