package dto

import "time"

type AdminUserResponse struct {
	ID              uint       `json:"id"`
	Username        string     `json:"username"`
	Email           string     `json:"email"`
	FullName        string     `json:"full_name"`
	Department      string     `json:"department"`
	Branch          string     `json:"branch"`
	Role            string     `json:"role"`
	BoundDeviceID   string     `json:"bound_device_id"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
	IsActive        bool       `json:"is_active"`
	GrantedLinkKeys []string   `json:"granted_link_keys"`
}

type SetRoleRequest struct {
	Role string `json:"role" binding:"required"`
}

type SetGrantsRequest struct {
	LinkKeys []string `json:"link_keys"`
}

type SetActiveRequest struct {
	IsActive bool `json:"is_active"`
}

type RevealPasswordResponse struct {
	Password string `json:"password"`
}

type SetPasswordRequest struct {
	NewPassword string `json:"new_password" binding:"required"`
}

type InstallerPasswordResponse struct {
	Password string `json:"password"`
}

type SetInstallerPasswordRequest struct {
	Password string `json:"password" binding:"required"`
}

type InstallerAdminEmailResponse struct {
	Email string `json:"email"`
}

type SetInstallerAdminEmailRequest struct {
	Email string `json:"email" binding:"required"`
}

type AdminPasswordResponse struct {
	Password string `json:"password"`
}

type SetAdminPasswordRequest struct {
	Password string `json:"password" binding:"required"`
}

type TokenRestrictionResponse struct {
	Enabled bool `json:"enabled"`
}

type SetTokenRestrictionRequest struct {
	Enabled bool `json:"enabled"`
}

type PortalLinkRequest struct {
	Key       string `json:"key"`
	TabName   string `json:"tab_name" binding:"required"`
	Name      string `json:"name" binding:"required"`
	URL       string `json:"url" binding:"required"`
	Icon      string `json:"icon"`
	Color     string `json:"color"`
	SortOrder int    `json:"sort_order"`
	IsActive  *bool  `json:"is_active"`
}
