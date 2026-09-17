// Package mail sends outbound email through the GoDaddy-hosted mailbox
// (noreply@arminfo.in) via implicit-TLS SMTP (port 465). Generic on purpose —
// used by both the installer OTP gate and the portal-user OTP flows.
package mail

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"armss-gateway/backend/internal/config"
)

type Service struct {
	cfg *config.Config
}

func NewService(cfg *config.Config) *Service {
	return &Service{cfg: cfg}
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

// send dials with TLS from the start of the connection — GoDaddy's port 465
// is implicit TLS (SMTPS), not STARTTLS, so the stdlib's smtp.SendMail
// helper (which only speaks STARTTLS over a plaintext-first connection)
// doesn't work here.
func (s *Service) send(to, subject, contentType, body string) error {
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
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: %s; charset=UTF-8\r\n\r\n%s",
		s.cfg.SMTPFromAddress, to, subject, contentType, body)

	now := time.Now()
	dateHeader := now.Format(time.RFC1123Z)
	msgID := fmt.Sprintf("<%d.%d@%s>", now.UnixNano(), now.Nanosecond(), s.cfg.SMTPHost)

	headers := []string{
		fmt.Sprintf("From: ARMSS Gateway <%s>", s.cfg.SMTPFromAddress),
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

	msg = fmt.Sprintf("%s\r\n\r\n%s", strings.Join(headers, "\r\n"), body)
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}

	return client.Quit()
}
