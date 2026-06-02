package cmd

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/PhillipC05/tpt-identity/api"
	"github.com/PhillipC05/tpt-identity/internal/bridge"
	bridgeproviders "github.com/PhillipC05/tpt-identity/internal/bridge/providers"
	"github.com/PhillipC05/tpt-identity/internal/resolver"
	"github.com/PhillipC05/tpt-identity/internal/store"
	"github.com/PhillipC05/tpt-identity/oidc"
	"github.com/PhillipC05/tpt-identity/pkg/keystore"
	// Import all core schemas so their init() functions register at startup.
	_ "github.com/PhillipC05/tpt-identity/pkg/schema/core"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func serveCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "serve",
		Short: "Start the tpt-identity server",
		RunE: func(cmd *cobra.Command, args []string) error {
			viper.SetConfigFile(cfgFile)
			viper.SetEnvPrefix("TPT_IDENTITY")
			viper.AutomaticEnv()
			if err := viper.ReadInConfig(); err != nil {
				return fmt.Errorf("read config: %w", err)
			}

			logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

			db, err := store.OpenSQLite(viper.GetString("db_path"))
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer db.Close()

			ks, err := keystore.LoadSigning(
				viper.GetString("identity.signing_key"),
				viper.GetString("identity.passphrase"),
			)
			if err != nil {
				return fmt.Errorf("load signing key: %w", err)
			}

			issuer := viper.GetString("issuer")
			keyID := viper.GetString("identity.key_id")
			if keyID == "" {
				keyID = issuer + "#signing-key-1"
			}

			res := resolver.New(5 * time.Minute)
			oidcProvider := oidc.NewProvider(issuer, ks.SigningPriv, keyID, db)

			// ── Build bridge manager ──────────────────────────────────────
			bridges := bridge.NewManager()

			// OIDC relying-party bridges (e.g. Google, GitHub, Azure AD).
			type oidcBridgeCfg struct {
				Name         string   `mapstructure:"name"`
				Issuer       string   `mapstructure:"issuer"`
				ClientID     string   `mapstructure:"client_id"`
				ClientSecret string   `mapstructure:"client_secret"`
				Scopes       []string `mapstructure:"scopes"`
			}
			var oidcBridges []oidcBridgeCfg
			if err := viper.UnmarshalKey("bridges.oidc", &oidcBridges); err == nil {
				for _, bc := range oidcBridges {
					rp := bridgeproviders.NewOIDCRP(bridgeproviders.OIDCRPConfig{
						Name:            bc.Name,
						Issuer:          bc.Issuer,
						ClientID:        bc.ClientID,
						ClientSecret:    bc.ClientSecret,
						Scopes:          bc.Scopes,
						RedirectBaseURL: issuer,
					})
					bridges.Register(rp)
					logger.Info("bridge registered", "provider", bc.Name, "type", "oidc_rp")
				}
			}

			// Magic link bridge is always available (uses the store for token storage).
			bridges.Register(bridgeproviders.NewMagicLink(db))
			logger.Info("bridge registered", "provider", "magiclink-email", "type", "magic_link")

			// Password bridge — opt-in only.
			if viper.GetBool("bridges.password.enabled") {
				logger.Info("bridge registered", "provider", "password", "type", "password")
				// PasswordBridge wired in api/bridge.go directly via the store.
			}

			// TOTP passphrase — fall back to the signing key passphrase if not set.
			totpPassphrase := viper.GetString("totp_passphrase")
			if totpPassphrase == "" {
				totpPassphrase = viper.GetString("identity.passphrase")
			}

			srv := api.NewServer(api.Config{
				APIKey:         viper.GetString("api_key"),
				Issuer:         issuer,
				TotpPassphrase: totpPassphrase,
				SigningKey:     ks.SigningPriv,
				SigningKeyID:   keyID,
				Store:          db,
				Resolver:       res,
				OIDC:           oidcProvider,
				Bridges:        bridges,
				Logger:         logger,
				RateLimit:      viper.GetFloat64("rate_limit"),
			})

			addr := viper.GetString("listen_addr")
			if addr == "" {
				addr = ":8080"
			}
			logger.Info("tpt-identity server starting", "addr", addr, "issuer", issuer)
			return http.ListenAndServe(addr, srv)
		},
	}
	return c
}
