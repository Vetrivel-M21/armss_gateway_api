package mail

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"armss-gateway/backend/internal/config"
)

func TestSendViaBird_Success(t *testing.T) {
	// Mock Bird API server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer bk_test_key_123" {
			t.Errorf("unexpected Authorization header: %s", auth)
		}

		var payload birdMessagePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}

		if payload.From.Email != "noreply@arminfo.in" {
			t.Errorf("unexpected from email: %s", payload.From.Email)
		}
		if len(payload.To) == 0 || payload.To[0].Email != "test@example.com" {
			t.Errorf("unexpected to email: %+v", payload.To)
		}
		if payload.Category != "transactional" {
			t.Errorf("expected transactional category, got %s", payload.Category)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(birdMessageResponse{
			ID:        "em_test_123",
			Status:    "accepted",
			CreatedAt: "2026-09-21T06:45:00Z",
		})
	}))
	defer ts.Close()

	cfg := &config.Config{
		BirdAPIKey:      "bk_test_key_123",
		BirdAPIURL:      ts.URL,
		BirdFromEmail:   "noreply@arminfo.in",
		BirdFromName:    "ARMSS Gateway",
		SMTPFromAddress: "noreply@arminfo.in",
	}

	svc := NewService(cfg)
	err := svc.SendOTP("test@example.com", "Test OTP", "Heading", "Your code", "123456")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestStripHTML(t *testing.T) {
	html := "<h1>Header</h1><p>Hello <b>World</b></p>"
	expected := "HeaderHello World"
	got := stripHTML(html)
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

