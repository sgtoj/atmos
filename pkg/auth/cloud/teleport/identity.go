package teleport

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gravitational/teleport/api/identityfile"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/auth/types"
	"github.com/cloudposse/atmos/pkg/perf"
)

// identityFileDirPerm is the permission applied to the directory that holds a
// bot identity file. The file itself is written 0600 by the SDK.
const identityFileDirPerm = 0o700

// LoadIdentityFile reads a tbot-format identity file from path and returns
// the materialized TeleportCredentials.
//
// A Teleport identity file stores a single private key shared by the TLS and
// SSH certificates, so both TLSKeyPEM and SSHKeyPEM are populated from it.
func LoadIdentityFile(_ context.Context, path string) (*types.TeleportCredentials, error) {
	defer perf.Track(nil, "teleport.LoadIdentityFile")()

	if path == "" {
		return nil, fmt.Errorf("%w: identity file path is empty", errUtils.ErrTeleportBotIdentityRead)
	}

	idFile, err := identityfile.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUtils.ErrTeleportBotIdentityRead, err)
	}

	// A Teleport identity file always carries both an SSH and a TLS cert issued
	// for the same private key (identityfile.ReadFile rejects files without an
	// SSH cert), so both key fields are populated from the single PrivateKey.
	creds := &types.TeleportCredentials{
		TLSCertPEM:       string(idFile.Certs.TLS),
		TLSKeyPEM:        string(idFile.PrivateKey),
		SSHCertPEM:       string(idFile.Certs.SSH),
		SSHKeyPEM:        string(idFile.PrivateKey),
		IdentityFilePath: path,
		IsBot:            true,
	}
	for _, ca := range idFile.CACerts.TLS {
		creds.TLSCAsPEM = append(creds.TLSCAsPEM, string(ca))
	}
	if expiry, ok := idFile.Expiry(); ok {
		creds.ValidUntil = expiry
	}

	return creds, nil
}

// WriteIdentityFile persists TeleportCredentials as a tbot-compatible identity
// file at the given path.
//
// The output format is the standard tbot single-file identity (concatenated
// PEM blocks: TLS key, TLS cert, SSH cert, CA certs), suitable for consumption
// by tsh -i, kubectl exec plugins, and the Teleport API SDK's
// identityfile.ReadFile. The parent directory is created with 0700 permissions
// if it does not exist.
func WriteIdentityFile(_ context.Context, creds *types.TeleportCredentials, path string) error {
	defer perf.Track(nil, "teleport.WriteIdentityFile")()

	if creds == nil {
		return fmt.Errorf("%w: credentials are nil", errUtils.ErrTeleportBotIdentityWrite)
	}
	if path == "" {
		return fmt.Errorf("%w: identity file path is empty", errUtils.ErrTeleportBotIdentityWrite)
	}

	// TLS and SSH certs in a Teleport identity file share one private key.
	privateKey := creds.TLSKeyPEM
	if privateKey == "" {
		privateKey = creds.SSHKeyPEM
	}
	if privateKey == "" {
		return fmt.Errorf("%w: credentials carry no private key", errUtils.ErrTeleportBotIdentityWrite)
	}
	if creds.TLSCertPEM == "" {
		return fmt.Errorf("%w: credentials carry no TLS certificate", errUtils.ErrTeleportBotIdentityWrite)
	}
	// The Teleport identity-file format requires an SSH cert (in OpenSSH
	// authorized-keys format, not PEM); identityfile.ReadFile cannot parse a
	// file that lacks one. Teleport issues SSH and TLS certs together during a
	// bot join, so a well-formed bot credential always has both.
	if creds.SSHCertPEM == "" {
		return fmt.Errorf("%w: credentials carry no SSH certificate (required by the Teleport identity-file format)", errUtils.ErrTeleportBotIdentityWrite)
	}

	idFile := &identityfile.IdentityFile{
		PrivateKey: []byte(privateKey),
		Certs: identityfile.Certs{
			TLS: []byte(creds.TLSCertPEM),
			SSH: []byte(creds.SSHCertPEM),
		},
	}
	for _, ca := range creds.TLSCAsPEM {
		idFile.CACerts.TLS = append(idFile.CACerts.TLS, []byte(ca))
	}

	// Ensure the parent directory exists with restrictive permissions.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, identityFileDirPerm); err != nil {
			return fmt.Errorf("%w: %w", errUtils.ErrTeleportBotIdentityWrite, err)
		}
	}

	if err := identityfile.Write(idFile, path); err != nil {
		return fmt.Errorf("%w: %w", errUtils.ErrTeleportBotIdentityWrite, err)
	}

	return nil
}
