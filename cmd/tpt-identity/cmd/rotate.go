package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/PhillipC05/tpt-identity/pkg/keystore"
	"github.com/spf13/cobra"
)

func rotateCmd() *cobra.Command {
	var (
		outSign    string
		passphrase string
		oldKeyPath string
	)
	c := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the signing key",
		Long: `Generate a new Ed25519 signing key for token issuance.

After rotation, update config.yaml:
  identity:
    signing_key: <new key path>
    previous_keys:
      - <old key path>    # keep until all tokens it signed have expired (~1h)

Both keys will be served in /.well-known/jwks.json so existing tokens
remain valid during the transition window. Remove previous_keys once
the old TTL has elapsed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ks, err := keystore.Generate()
			if err != nil {
				return fmt.Errorf("generate keys: %w", err)
			}
			if err := keystore.SaveSigning(ks, outSign, passphrase); err != nil {
				return fmt.Errorf("save signing key: %w", err)
			}
			fmt.Fprintln(os.Stderr, "New signing key saved to", outSign)
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Update config.yaml:")
			fmt.Fprintln(os.Stderr, "  identity:")
			fmt.Fprintln(os.Stderr, "    signing_key:", outSign)
			if oldKeyPath != "" {
				fmt.Fprintln(os.Stderr, "    previous_keys:")
				fmt.Fprintln(os.Stderr, "      -", oldKeyPath)
				fmt.Fprintln(os.Stderr, "")
				fmt.Fprintf(os.Stderr, "Remove previous_keys entry after %s (token TTL expiry).\n", time.Now().Add(time.Hour).Format(time.RFC3339))
			}
			return nil
		},
	}
	c.Flags().StringVar(&outSign, "out", "ed25519-new.pem", "Output path for new Ed25519 signing key")
	c.Flags().StringVar(&passphrase, "passphrase", "", "Passphrase for key encryption")
	c.Flags().StringVar(&oldKeyPath, "old-key", "", "Path to the current signing key (shown in config snippet)")
	return c
}
