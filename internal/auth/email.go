package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"os"
	"time"
)

// SenderConfig configures email delivery. Priority order:
//  1. TPTEmailBaseURL — send via tpt-email gateway (cryptographically signed)
//  2. SMTPHost — send via raw SMTP
//  3. Neither — dev mode, print link to stderr
type SenderConfig struct {
	// tpt-email gateway (optional, preferred)
	TPTEmailBaseURL string
	TPTEmailAPIKey  string

	// Raw SMTP (optional, fallback)
	SMTPHost     string
	SMTPPort     int
	SMTPFrom     string
	SMTPPassword string

	Logger *slog.Logger
}

// Sender sends magic link emails.
type Sender struct {
	cfg SenderConfig
}

// NewSender creates a Sender from cfg. SMTPPort defaults to 587 if zero.
func NewSender(cfg SenderConfig) *Sender {
	if cfg.SMTPPort == 0 {
		cfg.SMTPPort = 587
	}
	return &Sender{cfg: cfg}
}

// SendMagicLink sends a one-time sign-in link to the given address.
func (s *Sender) SendMagicLink(to, magicURL string) error {
	if s.cfg.TPTEmailBaseURL != "" {
		return s.sendViaTptEmail(to, magicURL)
	}
	if s.cfg.SMTPHost != "" {
		return s.sendViaSMTP(to, magicURL)
	}
	// Dev mode — no transport configured.
	fmt.Fprintf(os.Stderr, "\n[DEV] Magic link for %s:\n  %s\n\n", to, magicURL)
	return nil
}

// sendViaTptEmail delivers via the tpt-email gateway (POST /api/v1/send).
// The gateway signs the message with its Ed25519 key, making phishing detectable.
func (s *Sender) sendViaTptEmail(to, magicURL string) error {
	body := struct {
		To      string `json:"to"`
		Type    string `json:"type"`
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}{
		To:      to,
		Type:    "transactional",
		Subject: "Your TPT Identity sign-in link",
		Body: fmt.Sprintf(
			"Here is your TPT Identity sign-in link:\n\n  %s\n\n"+
				"This link expires in 15 minutes and can only be used once.\n\n"+
				"If you did not request this link, you can safely ignore this email.\n",
			magicURL,
		),
	}

	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TPTEmailBaseURL+"/api/v1/send", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.TPTEmailAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.TPTEmailAPIKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.cfg.Logger.Error("tpt-email send failed", "to", to, "error", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.cfg.Logger.Error("tpt-email send failed", "to", to, "status", resp.StatusCode)
		return fmt.Errorf("tpt-email: unexpected status %d", resp.StatusCode)
	}
	return nil
}

func (s *Sender) sendViaSMTP(to, magicURL string) error {
	msg := fmt.Sprintf(
		"Subject: Your TPT Identity sign-in link\r\n"+
			"From: %s\r\n"+
			"To: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/plain; charset=UTF-8\r\n"+
			"\r\n"+
			"Here is your TPT Identity sign-in link:\r\n\r\n"+
			"  %s\r\n\r\n"+
			"This link expires in 15 minutes and can only be used once.\r\n\r\n"+
			"If you did not request this link, you can safely ignore this email.\r\n",
		s.cfg.SMTPFrom, to, magicURL,
	)

	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)
	var auth smtp.Auth
	if s.cfg.SMTPPassword != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTPFrom, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	}

	if err := smtp.SendMail(addr, auth, s.cfg.SMTPFrom, []string{to}, []byte(msg)); err != nil {
		s.cfg.Logger.Error("smtp send failed", "to", to, "error", err)
		return err
	}
	return nil
}
