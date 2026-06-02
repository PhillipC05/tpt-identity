package cmd

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/PhillipC05/tpt-identity/api"
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

			srv := api.NewServer(api.Config{
				APIKey:   cfg.APIKey,
				Issuer:   issuer,
				Store:    db,
				Resolver: res,
				OIDC:     oidcProvider,
				Logger:   logger,
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
