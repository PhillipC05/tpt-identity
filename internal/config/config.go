package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds all tpt-identity configuration fields.
type Config struct {
	Issuer     string `yaml:"issuer"`
	DBPath     string `yaml:"db_path"`
	ListenAddr string `yaml:"listen_addr"`
	APIKey     string `yaml:"api_key"`

	Identity struct {
		SigningKey    string   `yaml:"signing_key"`
		PreviousKeys []string `yaml:"previous_keys"` // retired keys still trusted during rotation window
		EncKey       string   `yaml:"enc_key"`
		Passphrase   string   `yaml:"passphrase"`
		KeyID        string   `yaml:"key_id"`
	} `yaml:"identity"`

	DIDWeb struct {
		Enabled bool   `yaml:"enabled"`
		Domain  string `yaml:"domain"`
	} `yaml:"did_web"`

	OIDC struct {
		IDTokenTTL     string `yaml:"id_token_ttl"`
		AccessTokenTTL string `yaml:"access_token_ttl"`
		CodeTTL        string `yaml:"code_ttl"`
	} `yaml:"oidc"`

	Email struct {
		SMTPHost     string `yaml:"smtp_host"`
		SMTPPort     int    `yaml:"smtp_port"`
		SMTPFrom     string `yaml:"from"`
		SMTPPassword string `yaml:"smtp_password"`
	} `yaml:"email"`

	Log struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"log"`
}

// Load reads the YAML config file at path and applies TPT_IDENTITY_* environment
// variable overrides. Env vars use underscore-separated uppercase keys, e.g.:
//
//	TPT_IDENTITY_ISSUER          → Config.Issuer
//	TPT_IDENTITY_DB_PATH         → Config.DBPath
//	TPT_IDENTITY_LISTEN_ADDR     → Config.ListenAddr
//	TPT_IDENTITY_API_KEY         → Config.APIKey
//	TPT_IDENTITY_IDENTITY_SIGNING_KEY → Config.Identity.SigningKey
//	TPT_IDENTITY_IDENTITY_PASSPHRASE  → Config.Identity.Passphrase
//	TPT_IDENTITY_IDENTITY_KEY_ID      → Config.Identity.KeyID
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read file: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}
	applyEnv(&cfg)
	return &cfg, nil
}

// applyEnv overrides config fields with TPT_IDENTITY_* environment variables.
func applyEnv(cfg *Config) {
	if v := env("ISSUER"); v != "" {
		cfg.Issuer = v
	}
	if v := env("DB_PATH"); v != "" {
		cfg.DBPath = v
	}
	if v := env("LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := env("API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := env("IDENTITY_SIGNING_KEY"); v != "" {
		cfg.Identity.SigningKey = v
	}
	if v := env("IDENTITY_ENC_KEY"); v != "" {
		cfg.Identity.EncKey = v
	}
	if v := env("IDENTITY_PASSPHRASE"); v != "" {
		cfg.Identity.Passphrase = v
	}
	if v := env("IDENTITY_KEY_ID"); v != "" {
		cfg.Identity.KeyID = v
	}
	if v := env("DID_WEB_DOMAIN"); v != "" {
		cfg.DIDWeb.Domain = v
	}
	if v := env("EMAIL_SMTP_HOST"); v != "" {
		cfg.Email.SMTPHost = v
	}
	if v := env("EMAIL_SMTP_FROM"); v != "" {
		cfg.Email.SMTPFrom = v
	}
	if v := env("EMAIL_SMTP_PASSWORD"); v != "" {
		cfg.Email.SMTPPassword = v
	}
	if v := env("LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if v := env("LOG_FORMAT"); v != "" {
		cfg.Log.Format = v
	}
}

func env(key string) string {
	return strings.TrimSpace(os.Getenv("TPT_IDENTITY_" + key))
}
