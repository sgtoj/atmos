# Teleport Cloud Package

This package wraps the
[Teleport API SDK](https://pkg.go.dev/github.com/gravitational/teleport/api) for
Atmos.

## Responsibilities

- Issue per-resource certificates (e.g., per-kubernetes-cluster) and Ping the
  cluster via the Teleport API client. See [`client.go`](client.go).
- Read and write tbot-format identity files. See [`identity.go`](identity.go).
- Perform tbot-equivalent join handshakes (GitHub OIDC, AWS IAM) without
  requiring an external `tbot` binary. See [`join.go`](join.go).

Atmos credentials are stored in the Atmos keychain (see
[`pkg/auth/credentials`](../../credentials)), not in `~/.tsh`; this package
never reads a `tsh` profile or shells out to the `tsh` binary.

## Architecture

```
Atmos providers/identities/integrations
                │
                ▼
   pkg/auth/cloud/teleport.Client (interface)
                │
                ▼
   github.com/gravitational/teleport/api/client (SDK)
```

The `Client` interface is mock-generated for unit tests (see the `//go:generate`
directive in [`client.go`](client.go)).

## Why a wrapper instead of using the SDK directly?

1. **Testability**: Mocking a small Atmos-defined interface is cleaner than
   mocking the entire SDK surface.
2. **Stability**: Teleport ships pseudo-versioned API releases
   (`v0.0.0-DATE-COMMIT`). Centralizing SDK usage here makes version bumps a
   one-file change.
3. **Isolation**: Only this package imports the SDK. Other Atmos packages depend
   on the Atmos-owned `TeleportCredentials` type.

## Implementation status

| Layer                                                  | Status      |
| ------------------------------------------------------ | ----------- |
| Type definitions (`Client`, `KubeCert`, `JoinRequest`) | Phase 1     |
| `LoadIdentityFile` / `WriteIdentityFile`               | Implemented |
| `GenerateKubeCert` / `Ping`                            | Phase 3     |
| `Join` (github + iam)                                  | Phase 4     |

`LoadIdentityFile` / `WriteIdentityFile` are implemented on top of
`github.com/gravitational/teleport/api/identityfile`: a bot credential is
persisted as a standard tbot single-file identity (shared private key + TLS cert

- SSH cert + CA certs) and read back into `TeleportCredentials`. The keychain is
  the canonical store; the identity file is a derived artifact materialized on
  demand for `tsh -i` / `kubectl` interop.

Remaining stubs return `errors.ErrNotImplemented` so the package signature is
stable while implementations land in later phases.
