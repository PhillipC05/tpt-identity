package cmd

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/PhillipC05/tpt-identity/api"
	"github.com/PhillipC05/tpt-identity/internal/auth"
	"github.com/PhillipC05/tpt-identity/internal/bridge"
	"github.com/PhillipC05/tpt-identity/internal/bridge/providers"
	"github.com/PhillipC05/tpt-identity/internal/config"
	"github.com/PhillipC05/tpt-identity/internal/resolver"
	"github.com/PhillipC05/tpt-identity/internal/store"
	"github.com/PhillipC05/tpt-identity/oidc"
	"github.com/PhillipC05/tpt-identity/pkg/keystore"
	// Import all core schemas so their init() functions register at startup.
	_ "github.com/PhillipC05/tpt-identity/pkg/schema/core"
	"github.com/spf13/cobra"
)

func serveCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "serve",
		Short: "Start the tpt-identity server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("read config: %w", err)
			}

			logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

			db, err := store.OpenSQLite(cfg.DBPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer db.Close()

			ks, err := keystore.LoadSigning(
				cfg.Identity.SigningKey,
				cfg.Identity.Passphrase,
			)
			if err != nil {
				return fmt.Errorf("load signing key: %w", err)
			}

			issuer := cfg.Issuer
			keyID := cfg.Identity.KeyID
			if keyID == "" {
				keyID = issuer + "#signing-key-1"
			}

			res := resolver.New(5 * time.Minute)
			oidcProvider := oidc.NewProvider(issuer, ks.SigningPriv, keyID, db)

			// Load any previous (retired) signing keys for the rotation transition window.
			for _, prevPath := range cfg.Identity.PreviousKeys {
				prevKS, err := keystore.LoadSigning(prevPath, cfg.Identity.Passphrase)
				if err != nil {
					return fmt.Errorf("load previous signing key %s: %w", prevPath, err)
				}
				oidcProvider.AddPreviousKey(prevKS.SigningPub)
			}

			ml := providers.NewMagicLink(db)
			mapper := bridge.NewMapper(db)
			emailSender := auth.NewSender(auth.SenderConfig{
				TPTEmailBaseURL: cfg.TPTEmail.BaseURL,
				TPTEmailAPIKey:  cfg.TPTEmail.APIKey,
				SMTPHost:        cfg.Email.SMTPHost,
				SMTPPort:        cfg.Email.SMTPPort,
				SMTPFrom:        cfg.Email.SMTPFrom,
				SMTPPassword:    cfg.Email.SMTPPassword,
				Logger:          logger,
			})
			loginHandler := auth.New(ml, mapper, emailSender, oidcProvider, issuer)

			srv := api.NewServer(api.Config{
				APIKey:       cfg.APIKey,
				Issuer:       issuer,
				Store:        db,
				Resolver:     res,
				OIDC:         oidcProvider,
				LoginHandler: loginHandler,
				Logger:       logger,
			})

			addr := cfg.ListenAddr
			if addr == "" {
				addr = ":8080"
			}
			logger.Info("tpt-identity server starting", "addr", addr, "issuer", issuer)
			return http.ListenAndServe(addr, srv)
		},
	}
	return c
}
