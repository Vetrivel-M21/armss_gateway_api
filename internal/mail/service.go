// Package mail sends outbound email through Bird Email API (POST https://eu1.platform.bird.com/v1/email/messages)
// with automatic fallback to implicit-TLS SMTP (port 465).
package mail

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"armss-gateway/backend/internal/config"
)

type Service struct {
	cfg        *config.Config
	httpClient *http.Client
}

func NewService(cfg *config.Config) *Service {
	return &Service{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// SendOTP sends a branded HTML email presenting a one-time code — used by
// both the installer gate and the portal password-reset flow.
func (s *Service) SendOTP(to, subject, heading, message, otp string) error {
	return s.send(to, subject, "text/html", otpEmailHTML(heading, message, otp))
}

// Send sends a plain-text email, for any future non-OTP notification.
func (s *Service) Send(to, subject, body string) error {
	return s.send(to, subject, "text/plain", body)
}

// send attempts to dispatch the email via Bird HTTP REST API first,
// falling back to SMTP if Bird API is unconfigured or encounters an error.
func (s *Service) send(to, subject, contentType, body string) error {
	if s.cfg.BirdAPIKey != "" {
		err := s.sendViaBird(to, subject, contentType, body)
		if err == nil {
			return nil
		}
		log.Printf("[Bird Mailer] Warning: HTTP API send failed: %v. Falling back to SMTP...", err)
	}

	return s.sendViaSMTP(to, subject, contentType, body)
}

// birdAddress represents a sender or recipient in Bird Email API.
type birdAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

// birdMessagePayload represents the request schema for POST /v1/email/messages.
type birdMessagePayload struct {
	From     birdAddress   `json:"from"`
	To       []birdAddress `json:"to"`
	Subject  string        `json:"subject"`
	HTML     string        `json:"html,omitempty"`
	Text     string        `json:"text,omitempty"`
	Category string        `json:"category"`
}

// birdMessageResponse represents the JSON response returned by Bird Email API.
type birdMessageResponse struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// sendViaBird dispatches outbound email via Bird HTTP API (POST https://eu1.platform.bird.com/v1/email/messages).
func (s *Service) sendViaBird(to, subject, contentType, body string) error {
	endpoint := s.cfg.BirdAPIURL
	if endpoint == "" {
		endpoint = "https://eu1.platform.bird.com/v1/email/messages"
	}

	fromEmail := s.cfg.BirdFromEmail
	if fromEmail == "" {
		fromEmail = s.cfg.SMTPFromAddress
	}

	fromName := s.cfg.BirdFromName
	if fromName == "" {
		fromName = "ARMSS Gateway"
	}

	payload := birdMessagePayload{
		From: birdAddress{
			Email: fromEmail,
			Name:  fromName,
		},
		To: []birdAddress{
			{
				Email: to,
			},
		},
		Subject:  subject,
		Category: "transactional",
	}

	if contentType == "text/html" {
		payload.HTML = body
		payload.Text = stripHTML(body)
	} else {
		payload.Text = body
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal bird payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("create bird request: %w", err)
	}

	authHeader := s.cfg.BirdAPIKey
	if !strings.HasPrefix(authHeader, "Bearer ") && !strings.HasPrefix(authHeader, "AccessKey ") {
		authHeader = "Bearer " + authHeader
	}

	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("bird http do: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("bird api error status %d: %s", resp.StatusCode, string(respBody))
	}

	var birdResp birdMessageResponse
	if err := json.Unmarshal(respBody, &birdResp); err == nil && birdResp.ID != "" {
		log.Printf("[Bird Mailer] Message sent successfully via HTTP API (id: %s, status: %s, to: %s)", birdResp.ID, birdResp.Status, to)
	} else {
		log.Printf("[Bird Mailer] Message accepted via HTTP API (status: %d, to: %s)", resp.StatusCode, to)
	}

	return nil
}

// sendViaSMTP dials with implicit TLS (port 465) as a fallback relay.
func (s *Service) sendViaSMTP(to, subject, contentType, body string) error {
	addr := fmt.Sprintf("%s:%s", s.cfg.SMTPHost, s.cfg.SMTPPort)

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: s.cfg.SMTPHost,
	})
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))

	client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	auth := smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}

	if err := client.Mail(s.cfg.SMTPFromAddress); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt to: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}

	now := time.Now()
	dateHeader := now.Format(time.RFC1123Z)
	msgID := fmt.Sprintf("<%d.%d@%s>", now.UnixNano(), now.Nanosecond(), s.cfg.SMTPHost)

	fromName := s.cfg.BirdFromName
	if fromName == "" {
		fromName = "ARMSS Gateway"
	}

	headers := []string{
		fmt.Sprintf("From: %s <%s>", fromName, s.cfg.SMTPFromAddress),
		fmt.Sprintf("To: %s", to),
		fmt.Sprintf("Subject: %s", subject),
		fmt.Sprintf("Date: %s", dateHeader),
		fmt.Sprintf("Message-ID: %s", msgID),
		"MIME-Version: 1.0",
		fmt.Sprintf("Content-Type: %s; charset=UTF-8", contentType),
		"X-Priority: 1 (Highest)",
		"X-MSMail-Priority: High",
		"Importance: High",
	}

	msg := fmt.Sprintf("%s\r\n\r\n%s", strings.Join(headers, "\r\n"), body)
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}

	return client.Quit()
}

// stripHTML provides a simple plain-text fallback from HTML content.
func stripHTML(input string) string {
	var out strings.Builder
	inTag := false
	for _, r := range input {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			out.WriteRune(r)
		}
	}
	return strings.TrimSpace(out.String())
}
