package auth

import (
	"fmt"
	"log/slog"
	"net/smtp"
	"os"
)

// Sender sends magic link emails.
// When SMTPHost is empty (development mode) the link is printed to stderr instead.
type Sender struct {
	host     string
	port     int
	from     string
	password string
	logger   *slog.Logger
}

// NewSender creates an email Sender. Port defaults to 587 if zero.
func NewSender(host string, port int, from, password string, logger *slog.Logger) *Sender {
	if port == 0 {
		port = 587
	}
	return &Sender{host: host, port: port, from: from, password: password, logger: logger}
}

// SendMagicLink sends a one-time sign-in link to the given address.
// In dev mode (no SMTP host) it prints the link to stderr.
func (s *Sender) SendMagicLink(to, magicURL string) error {
	if s.host == "" {
		fmt.Fprintf(os.Stderr, "\n[DEV] Magic link for %s:\n  %s\n\n", to, magicURL)
		return nil
	}

	msg := fmt.Sprintf(
		"Subject: Your TPT Identity sign-in link\r\n"+
			"From: %s\r\n"+
			"To: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/plain; charset=UTF-8\r\n"+
			"\r\n"+
			"Hi,\r\n\r\n"+
			"Here is your TPT Identity sign-in link:\r\n\r\n"+
			"  %s\r\n\r\n"+
			"This link expires in 15 minutes and can only be used once.\r\n\r\n"+
			"If you did not request this link, you can safely ignore this email.\r\n",
		s.from, to, magicURL,
	)

	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	var auth smtp.Auth
	if s.password != "" {
		auth = smtp.PlainAuth("", s.from, s.password, s.host)
	}

	if err := smtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg)); err != nil {
		s.logger.Error("send magic link email failed", "to", to, "error", err)
		return err
	}
	return nil
}
