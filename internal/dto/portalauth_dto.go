package dto

type RegisterRequest struct {
	Username   string `json:"username" binding:"required"`
	Email      string `json:"email" binding:"required,email"`
	Password   string `json:"password" binding:"required"`
	FullName   string `json:"full_name" binding:"required"`
	Department string `json:"department" binding:"required"`
	Branch     string `json:"branch" binding:"required"`
}

type RegisterResponse struct {
	UserID uint `json:"user_id"`
}

// LoginRequest.Identifier matches either the username or the email — the
// app's single login field tries a local ledger username first, then falls
// back to this endpoint with whatever was typed.
type LoginRequest struct {
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token           string   `json:"token"`
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	FullName        string   `json:"full_name"`
	Department      string   `json:"department"`
	Branch          string   `json:"branch"`
	Role            string   `json:"role"`
	GrantedLinkKeys []string `json:"granted_link_keys"`
}

type MeResponse struct {
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	FullName        string   `json:"full_name"`
	Department      string   `json:"department"`
	Branch          string   `json:"branch"`
	Role            string   `json:"role"`
	GrantedLinkKeys []string `json:"granted_link_keys"`
}

type ForgotPasswordRequestRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ForgotPasswordResetRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Otp         string `json:"otp" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type UpdateProfileRequest struct {
	Email      string `json:"email"`
	FullName   string `json:"full_name" binding:"required"`
	Department string `json:"department"`
	Branch     string `json:"branch"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}
