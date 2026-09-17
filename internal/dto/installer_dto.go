package dto

type RequestOtpRequest struct {
	Username   string `json:"username" binding:"required"`
	Department string `json:"department" binding:"required"`
	Branch     string `json:"branch" binding:"required"`
}

type RequestOtpResponse struct {
	RequestID string `json:"request_id"`
}

type VerifyOtpRequest struct {
	RequestID string `json:"request_id" binding:"required"`
	Otp       string `json:"otp" binding:"required"`
}

type VerifyOtpResponse struct {
	Valid bool `json:"valid"`
}
