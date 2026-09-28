package shared

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
}

type ErrorResponse struct {
	Success bool        `json:"success"`
	Error   ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func SendSuccess(c *gin.Context, statusCode int, data interface{}) {
	c.JSON(statusCode, APIResponse{Success: true, Data: data})
}

func SendError(c *gin.Context, statusCode int, code string, message string) {
	c.JSON(statusCode, ErrorResponse{Success: false, Error: ErrorDetail{Code: code, Message: message}})
}

func SendBadRequest(c *gin.Context, code string, message string) {
	SendError(c, http.StatusBadRequest, code, message)
}

func SendUnauthorized(c *gin.Context, message string) {
	SendError(c, http.StatusUnauthorized, "UNAUTHORIZED", message)
}

func SendForbidden(c *gin.Context, code string, message string) {
	SendError(c, http.StatusForbidden, code, message)
}

func SendInternalError(c *gin.Context, message string) {
	SendError(c, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", message)
}
