# Teleport Authentication Integration PRD

**Status**: 🟡 In Progress — Phase K (keychain envelope), Phase 3 (Kubernetes
integration + `atmos teleport kube token`), and the Phase 4 bot identity
lifecycle are implemented and unit-tested. The bot join handshake (AWS IAM /
GitHub OIDC) and the interactive SSO web-login (`teleport/user`) require
live-cluster validation.

**Last Updated**: 2026-06-08

**Related PRDs**: [EKS Kubeconfig Authentication](./eks-kubeconfig.md)
(structural template) | [ECR Authentication](./ecr-authentication.md) |
[Keyring Backends](./keyring-backends.md) |
[Auth Realm Architecture](./auth-realm-architecture.md)

## Executive Summary

Teleport is a widely deployed access-plane that sits in front of cloud
infrastructure: Kubernetes clusters, databases, SSH hosts, and applications.
Many organizations already authenticate humans and CI/CD workloads to AWS
resources through Teleport rather than going directly to AWS, because Teleport
provides centralized RBAC, recording, just-in-time access, and short-lived
certificates.

Atmos already authenticates to AWS, Azure, GCP, and GitHub via a layered
provider/identity/integration architecture, and already ships a
fully-implemented `aws/eks` integration that writes kubeconfig files with an
exec credential plugin (`atmos aws eks token`). This PRD extends that
architecture to Teleport, enabling two principal use cases:

1. **Workstation users** who run `atmos terraform plan` / `atmos helmfile apply`
   against Teleport-mediated resources, where Atmos drives the Teleport SSO
   login in-process and caches the credentials in the Atmos keychain.

2. **CI/CD runners** (GitHub Actions, AWS-resident runners such as Spacelift /
   EC2 / Lambda) that need to authenticate to Teleport without static secrets,
   using `tbot`-style bot identities joined via GitHub OIDC or AWS IAM.

To be clear, Atmos does not provision Teleport itself (roles, tokens, bots, kube
clusters); that remains a Teleport admin concern. This PRD is about the
**client-side** integration: reading existing Teleport credentials, performing
machine identity join handshakes, and materializing the resulting certificates
into `KUBECONFIG` (and, in future, database / SSH / app proxies).

**Key Design Decisions:**

- **Teleport is a Provider, not just an integration.** `teleport/proxy`
  represents the cluster itself; `teleport/user` and `teleport/bot` are
  identities that derive credentials from it (or via cross-provider chaining).
- **Teleport Kubernetes is an Integration.** `teleport/kubernetes` is parallel
  to `aws/eks` — it does not own identity, it only materializes kubeconfig for
  an identity that already has Teleport certs.
- **The Atmos native keychain is the source of truth for all Teleport
  credentials.** Atmos does NOT depend on the `~/.tsh` directory or the `tsh`
  binary. The user identity drives interactive SSO login itself and persists the
  resulting certificates in the standard Atmos keyring
  (`pkg/auth/credentials/`), exactly like AWS/GCP/Azure/Atmos-Pro credentials.
  Bot identities likewise persist to the keyring. This decision supersedes the
  earlier two-stage plan that kept `~/.tsh` as the user-identity source of truth
  and deferred the keychain to a later phase.
- **Atmos drives interactive SSO login in-process.** Because we no longer read
  `~/.tsh`, Atmos performs the Teleport web SSO login flow itself (local
  callback redirector + NaCl-box-encrypted response) against the proxy's
  `/webapi` endpoints. This keeps the `/api`-only dependency footprint — we do
  NOT vendor the heavyweight `github.com/gravitational/teleport` `lib/client`
  module (hundreds of MB of server code). See "SDK Approach".
- **Pure-Go SDK for everything else.** Bot join, kube cert generation, and the
  authenticated API client: all via `github.com/gravitational/teleport/api`. No
  external binary required at runtime.

## Goals and Non-Goals

### Goals

- Authenticate to a Teleport cluster as a workstation user by driving the
  interactive SSO login flow in-process and caching certificates in the Atmos
  keychain (no dependency on `~/.tsh` or the `tsh` binary).
- Authenticate to a Teleport cluster as a CI/CD bot (`tbot`-equivalent join via
  GitHub OIDC and AWS IAM).
- Materialize a kubeconfig with auto-refreshing exec credentials for any
  Teleport-registered Kubernetes cluster.
- Coexist with the existing `aws/eks` integration without conflict.
- Surface Teleport context in `atmos auth whoami`, `atmos auth env`,
  `atmos auth list`.
- Provide an exec credential plugin command (`atmos teleport kube token`)
  parallel to `atmos aws eks token`.

### Non-Goals (deferred to follow-ups)

- `teleport/database` integration (tracked as a follow-up GitHub issue).
- `teleport/ssh` and `teleport/app` integrations (follow-ups).
- Kubernetes service-account join method for bots (follow-up).
- Static token join method (intentionally omitted; OIDC/IAM are the modern
  path).
- Refactoring the legacy `components.helmfile.use_eks: true` path to optionally
  route through Teleport.

## Problem Statement

In Teleport-enabled organizations, current Atmos workflows have these gaps:

1. **Workstation users must shell out manually.** Today users install `tsh` and
   run `tsh login` then `tsh kube login <cluster>` for each cluster before any
   Atmos helmfile command works. This is not orchestrated by Atmos and is
   error-prone with multi-cluster setups. Atmos replaces this with an in-process
   SSO login (no `tsh` binary) and automatic kubeconfig generation.

2. **CI/CD has no path through Teleport.** A GitHub Actions runner that wants to
   reach EKS via Teleport currently needs to install `tbot` separately, run a
   join flow outside of Atmos, write identity files, and configure kubeconfig —
   all before any Atmos command. There is no Atmos primitive that owns this
   lifecycle.

3. **The existing `aws/eks` integration does not respect Teleport.** When EKS is
   behind Teleport, direct AWS auth bypasses Teleport's RBAC and audit logging.
   Atmos has no way to express "go through Teleport for this cluster".

4. **`atmos auth whoami` doesn't show Teleport context.** A user who has logged
   in via Atmos has no way to confirm their Teleport role / cluster from Atmos
   itself.

## User-Facing Workflows

### A. Workstation user → EKS via Teleport

```yaml
auth:
  providers:
    company-teleport:
      kind: teleport/proxy
      spec:
        proxy_address: teleport.company.com:443
        auth_connector: okta

  identities:
    teleport-user:
      kind: teleport/user
      default: true
      via:
        provider: company-teleport

  integrations:
    prod-eks:
      kind: teleport/kubernetes
      via:
        identity: teleport-user
      spec:
        teleport_kubernetes:
          name: prod-eks
          alias: prod
          kubeconfig:
            update: merge
```

User flow:

```
$ atmos auth login -i teleport-user   # in-process SSO web-login (browser), cached in keychain
$ atmos helmfile apply nginx -s prod  # Atmos handles the rest
```

### B. GitHub Actions → EKS via Teleport (no AWS at all)

```yaml
auth:
  providers:
    github:
      kind: github/oidc
    company-teleport:
      kind: teleport/proxy
      spec:
        proxy_address: teleport.company.com:443

  identities:
    ci-bot:
      kind: teleport/bot
      via:
        provider: github                  # source of join credentials
      principal:
        teleport_proxy_provider: company-teleport
        bot_name: github-actions
        join_method: github
        join_token: gha-deploy-token
        roles: [terraform-ci]
        ttl: 1h

  integrations:
    prod-eks:
      kind: teleport/kubernetes
      via:
        identity: ci-bot
      spec:
        teleport_kubernetes:
          name: prod-eks
```

### C. AWS-resident runner (EC2 / Spacelift) → EKS via Teleport

```yaml
auth:
  providers:
    aws-sso:
      kind: aws/iam-identity-center
      spec: { region: us-east-1, start_url: https://company.awsapps.com/start }
    company-teleport:
      kind: teleport/proxy
      spec: { proxy_address: teleport.company.com:443 }

  identities:
    runner-aws-role:
      kind: aws/permission-set
      via: { provider: aws-sso }
      principal: { name: RunnerRole, account: { name: ci-account } }

    ci-bot:
      kind: teleport/bot
      via:
        identity: runner-aws-role        # AWS creds for STS sigv4 join
      principal:
        teleport_proxy_provider: company-teleport
        bot_name: aws-runner
        join_method: iam
        join_token: aws-runner-token
        roles: [terraform-ci]
        aws: { region: us-east-1 }

  integrations:
    prod-eks:
      kind: teleport/kubernetes
      via: { identity: ci-bot }
      spec: { teleport_kubernetes: { name: prod-eks } }
```

## Architecture

### Layered Mapping

```
┌─────────────────────────────────────────────────────────────────┐
│  Provider:    teleport/proxy                                    │
│                                                                 │
│    Represents a Teleport cluster: proxy_address, auth_connector,│
│    CA cert. Provides credentials via in-process SSO web-login   │
│    (when the downstream identity is teleport/user) or returns   │
│    an empty sentinel (when the downstream identity is           │
│    teleport/bot, which sources credentials from a diff upstream).│
└─────────────────────────────────────────────────────────────────┘
                              │
                ┌─────────────┴─────────────┐
                ▼                           ▼
┌──────────────────────────┐   ┌──────────────────────────┐
│ Identity: teleport/user  │   │ Identity: teleport/bot   │
│                          │   │                          │
│ SSO web-login → keychain,│   │ Joins via tbot-equivalent│
│ optionally re-issues     │   │ handshake using upstream │
│ certs with selected      │   │ credentials (github/oidc │
│ roles / kube clusters.   │   │ JWT or AWS STS sigv4).   │
└──────────────────────────┘   │ Stores identity file at  │
                               │ $ATMOS_DATA_HOME/teleport│
                               │ /bot/<name>/identity.    │
                               └──────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Integration: teleport/kubernetes                               │
│                                                                 │
│    Issues a per-cluster kube cert via the Teleport SDK          │
│    (api/client.GenerateUserCerts with KubernetesCluster set),   │
│    writes a kubeconfig entry whose user is an exec plugin       │
│    invoking `atmos teleport kube token --cluster=<name>`.       │
│    Sets KUBECONFIG/KUBE_CONFIG_PATH via Environment().          │
└─────────────────────────────────────────────────────────────────┘
```

### Coexistence with `aws/eks`

`teleport/kubernetes` and `aws/eks` are **independent**. The integration
framework in `pkg/auth/manager_integrations.go` already supports multiple
integrations writing to the same kubeconfig file — the `Environment()` returns
of all integrations are merged with `os.PathListSeparator`. Users can have some
clusters managed via `aws/eks` and others via `teleport/kubernetes`. The
kubeconfig manager (`pkg/auth/cloud/kube/config.go`) is reused for both.

### Why a Provider for Teleport?

We considered modeling Teleport purely as an integration (parallel to
`aws/eks`), but a Provider is justified because:

1. **Teleport-issued certificates are themselves credentials**, suitable for the
   chain. Future identities (e.g., `teleport/role`, `teleport/database-role`)
   can chain off `teleport/user` or `teleport/bot` to refine roles / scopes.
2. **The Teleport cluster is a stable reference point** for multiple identities.
   Centralizing `proxy_address`, `ca_cert`, and `auth_connector` in one provider
   matches how AWS SSO, GitHub OIDC, and others are modeled today.
3. **Provider-level concerns** (TLS pinning, regional proxy selection, optional
   client configuration) naturally live on the provider.

### Credential Storage Strategy

**Keychain-canonical from the start.** Per the user's decision, the Atmos
standard keychain (`pkg/auth/credentials/`) is the single source of truth for
all Teleport credentials — both user and bot — handled uniformly with
AWS/GCP/Azure/Atmos-Pro credentials. Atmos does NOT depend on the `~/.tsh`
directory or the `tsh` binary at any point.

#### Keyring envelope (implemented)

A `"teleport"` credential envelope is registered in all three keyring backends
(`keyring_system.go`, `keyring_file.go`, `keyring_memory.go`) — added to each
`Store` type switch and `Retrieve` envelope-type switch. The existing
`TeleportCredentials` struct (already JSON-tagged on every field) serializes as
the envelope `data`. Realm scoping is automatic because the keyring layer keys
by realm. Round-trip + realm-scoping + expiry tests live in
`store_teleport_test.go`, asserting slice-element fidelity per the testing
mandate.

#### Workstation user identity

`Authenticate` resolves credentials in this order:

1. **Keyring hit:** retrieve the `teleport` envelope for the identity's realm;
   if present and not within the refresh threshold of `ValidUntil`, return it.
2. **Keyring miss / expired:** drive the interactive SSO login flow in-process
   (see "SDK Approach"), obtain fresh certificates, store them as a `teleport`
   envelope in the keyring, and return them.

There is no `~/.tsh` read and no `tsh` subprocess. The keyring entry never
out-survives Teleport's own certificate lifetime (`ValidUntil`).

#### Bot identity

The keyring is the canonical store. The bot join handshake (GitHub OIDC / AWS
IAM) produces `TeleportCredentials` that are written to the keyring. For
subprocess interop (`tsh -i`, `kubectl` exec plugins), Atmos materializes a
`tbot`-format identity file on demand from the keyring at
`$ATMOS_DATA_HOME/teleport/bot/<realm>/<bot_name>/identity` (overridable via
`spec.output_dir`), exports its path as `TELEPORT_IDENTITY_FILE`, and removes it
on `Logout`. The file is a derived artifact, not the source of truth.

#### Logout

`atmos auth logout` deletes the realm-scoped keyring entry and removes any
materialized bot identity file. There is no `~/.tsh` state for Atmos to manage.

## SDK Approach

The Teleport API SDK (`github.com/gravitational/teleport/api`, NOT the full
`teleport` server module) is the only external dependency added in v1.

### What the SDK gives us

| Capability                             | SDK surface                                                   |
| -------------------------------------- | ------------------------------------------------------------- |
| Construct API client from TLS creds    | `api/client.New` + `api/client.LoadTLS(tlsConfig)`            |
| Load/write tbot identity file          | `api/identityfile.ReadFile(path)` / `identityfile.Write(...)` |
| Bot join (IAM challenge-response)      | `api/client.JoinServiceClient.RegisterUsingIAMMethod(...)`    |
| Issue user certs (incl. kube routing)  | `client.GenerateUserCerts(ctx, proto.UserCertsRequest{...})`  |
| Proxy ping / discovery                 | `api/client/webclient.Ping` / `client.Ping(ctx)`              |
| ALPN/proxy ping for endpoint discovery | `client.Ping(ctx)`                                            |

### What the SDK does NOT give us

- Interactive browser SSO login. The high-level login flow lives in the
  heavyweight `lib/client` module (the full `github.com/gravitational/teleport`
  server tree), which we deliberately do NOT vendor. Instead Atmos reimplements
  the lightweight web SSO login against the proxy's `/webapi` endpoints:

  1. Generate a client keypair and a NaCl `box` keypair for the response.
  2. Start a localhost callback HTTP server on an ephemeral port.
  3. Open the browser to the proxy's SSO console-login URL, passing the callback
     URL and the box public key.
  4. The proxy authenticates the user against the configured IdP connector and
     redirects to the callback with the login response (TLS cert, SSH cert, CA
     certs) encrypted to the box public key.
  5. Atmos decrypts, materializes `TeleportCredentials`, and stores them in the
     keyring.

  This is the one security-sensitive, custom piece; it is isolated behind the
  `pkg/auth/cloud/teleport` SSO-login interface (mockable, unit-tested) and
  requires validation against a live Teleport cluster (opt-in
  `//go:build teleport_integration`).

- Trusted cluster routing UI. Atmos requires the user to name the leaf Teleport
  cluster, if any, via `principal.teleport_cluster`.

### Why not vendor the full `teleport` module?

The full `github.com/gravitational/teleport` module pulls in the entire auth
server, audit log, etc. — hundreds of MB of dependencies, large enough to
dominate the Atmos binary. The `/api` submodule is purpose-built for SDK
consumers and is what `tctl`, third-party Terraform providers (including
`cruxstack/terraform-provider-teleportconnect`), and `tbot` itself use.

## Schema Additions (`pkg/schema/schema_auth.go`)

```go
// TeleportKubernetesCluster represents a Teleport-mediated Kubernetes cluster
// for teleport/kubernetes integrations.
type TeleportKubernetesCluster struct {
    // Name is the Kubernetes cluster name as registered in Teleport (required).
    Name string `yaml:"name" json:"name" mapstructure:"name"`

    // Alias is the context name in kubeconfig (optional, defaults to "<proxy>/<name>").
    Alias string `yaml:"alias,omitempty" json:"alias,omitempty" mapstructure:"alias"`

    // Kubeconfig contains kubeconfig file settings (optional). Reuses KubeconfigSettings
    // which is shared with the aws/eks integration.
    Kubeconfig *KubeconfigSettings `yaml:"kubeconfig,omitempty" json:"kubeconfig,omitempty" mapstructure:"kubeconfig"`
}

// IntegrationSpec is extended with:
//   TeleportKubernetes *TeleportKubernetesCluster `yaml:"teleport_kubernetes,omitempty" json:"teleport_kubernetes,omitempty" mapstructure:"teleport_kubernetes"`
```

Provider, identity, and integration spec/principal fields parsed via
`mapstructure` from the existing generic `Spec map[string]any` /
`Principal map[string]any` carry-alls — no breaking schema changes to the
top-level `Provider` / `Identity` / `Integration` structs.

## Type Additions (`pkg/auth/types/`)

```go
// teleport_specs.go (new file)
type TeleportProxyProviderSpec struct {
    ProxyAddress  string `mapstructure:"proxy_address"`
    AuthConnector string `mapstructure:"auth_connector,omitempty"` // IdP for SSO web-login
    Insecure      bool   `mapstructure:"insecure,omitempty"`
    CACertPath    string `mapstructure:"ca_cert_path,omitempty"`
    CACertPEM     string `mapstructure:"ca_cert_pem,omitempty"`
}

type TeleportUserIdentityPrincipal struct {
    Roles              []string `mapstructure:"roles,omitempty"`
    KubernetesClusters []string `mapstructure:"kubernetes_clusters,omitempty"`
    TTL                string   `mapstructure:"ttl,omitempty"`
    RequireMFA         bool     `mapstructure:"require_mfa,omitempty"`
    TeleportCluster    string   `mapstructure:"teleport_cluster,omitempty"` // for trusted clusters
}

type TeleportBotIdentityPrincipal struct {
    TeleportProxyProvider string                   `mapstructure:"teleport_proxy_provider"` // required
    BotName               string                   `mapstructure:"bot_name"`                // required
    JoinMethod            string                   `mapstructure:"join_method"`             // "github" | "iam"
    JoinToken             string                   `mapstructure:"join_token"`              // required
    Roles                 []string                 `mapstructure:"roles,omitempty"`
    OutputDir             string                   `mapstructure:"output_dir,omitempty"`
    TTL                   string                   `mapstructure:"ttl,omitempty"`           // default: "1h"
    RenewalInterval       string                   `mapstructure:"renewal_interval,omitempty"`
    AWS                   *TeleportBotAWSJoin      `mapstructure:"aws,omitempty"`
    GitHub                *TeleportBotGitHubJoin   `mapstructure:"github,omitempty"`
}

type TeleportBotAWSJoin struct {
    Region string `mapstructure:"region,omitempty"` // default: us-east-1
}

type TeleportBotGitHubJoin struct {
    Audience string `mapstructure:"audience,omitempty"`
}

// teleport_credentials.go (new file)
type TeleportCredentials struct {
    ProxyAddress     string    `json:"proxy_address,omitempty"`
    ClusterName      string    `json:"cluster_name,omitempty"`     // Teleport cluster name
    Username         string    `json:"username,omitempty"`         // Or bot name for bot identities.
    Roles            []string  `json:"roles,omitempty"`
    TLSCertPEM       string    `json:"tls_cert_pem,omitempty"`
    TLSKeyPEM        string    `json:"tls_key_pem,omitempty"`
    TLSCAsPEM        []string  `json:"tls_cas_pem,omitempty"`
    SSHCertPEM       string    `json:"ssh_cert_pem,omitempty"`     // Optional for SSH access (future).
    SSHKeyPEM        string    `json:"ssh_key_pem,omitempty"`
    KubeClusters     []string  `json:"kube_clusters,omitempty"`    // Allowed kube cluster names from cert.
    ValidUntil       time.Time `json:"valid_until,omitempty"`
    IdentityFilePath string    `json:"identity_file_path,omitempty"` // For bot identities.
    IsBot            bool      `json:"is_bot,omitempty"`
}
// Implements ICredentials: IsExpired, GetExpiration, BuildWhoamiInfo, Validate.
```

## Errors (`errors/errors.go`)

```go
ErrTeleportProfileNotFound       = errors.New("teleport profile not found")
ErrTeleportProfileExpired        = errors.New("teleport profile expired")
ErrTeleportProxyUnreachable      = errors.New("teleport proxy unreachable")
ErrTeleportJoinFailed            = errors.New("teleport bot join failed")
ErrTeleportBotIdentityWrite      = errors.New("failed to write teleport bot identity file")
ErrTeleportBotIdentityRead       = errors.New("failed to read teleport bot identity file")
ErrTeleportKubeClusterNotFound   = errors.New("teleport kubernetes cluster not found")
ErrTeleportKubeCertGeneration    = errors.New("failed to generate teleport kubernetes certificate")
ErrTeleportUnsupportedJoinMethod = errors.New("unsupported teleport bot join method")
ErrTeleportInvalidConfig         = errors.New("invalid teleport configuration")
ErrTeleportIntegrationFailed     = errors.New("teleport integration failed")
ErrTeleportProxyResolution       = errors.New("failed to resolve teleport proxy address")
```

## Implementation Phases

| Phase | Deliverable                                                                                                                                                                                          | CI label |
| ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| **1** | Schema types, kind constants, errors, SDK dep, skeleton with `init()` registration. All kinds recognized; `Authenticate`/`Execute` return `ErrNotImplemented`. Tests for registry wiring.            | `minor`  |
| **K** | **Keychain envelope (foundation).** `"teleport"` envelope in all three keyring backends (system/file/memory) with round-trip / realm-scoping / expiry tests. Pulled ahead of all credential work.    | `minor`  |
| **2** | `teleport/proxy` provider + `teleport/user` identity. In-process interactive SSO web-login; certs cached in the keychain (no `~/.tsh`). `atmos auth whoami -i teleport-user` works. Mockgen for SDK. | `minor`  |
| **3** | `teleport/kubernetes` integration + `atmos teleport kube token` exec plugin. End-to-end: `atmos auth exec -i teleport-user -- kubectl get nodes`.                                                    | `minor`  |
| **4** | `teleport/bot` identity (GitHub OIDC + AWS IAM join methods). Keychain-canonical; identity file is a derived on-demand artifact with logout cleanup.                                                 | `minor`  |
| **6** | Examples (`examples/demo-teleport/`), tutorial doc, blog post, roadmap update.                                                                                                                       | `minor`  |

Phase **K** (keychain envelope) is the foundation and lands first — it is
independent of the login mechanism and is already implemented and tested. Phases
2/4 can run in parallel once phases 1 and K land. Phase 3 depends on phase 2
(needs the user identity to exist). The former "Phase 5" keychain-migration step
is removed: the keychain is canonical from the start, so there is no disk-backed
intermediate stage to migrate from.

## Testing Strategy

Following CLAUDE.md mandates:

- **Interface-driven** SDK wrapper: `pkg/auth/cloud/teleport/client.go` defines
  a `Client` interface; production wires it to the SDK; tests use `mockgen`.
- **Unit tests with mocks** for all `Authenticate` / `Execute` / `Cleanup`
  paths.
- **Negative-path tests** for every recovery scenario: expired profile,
  unreachable proxy, missing identity file.
- **Cross-platform**: identity file paths via `filepath.Join`, no hardcoded `/`;
  tests use `os.UserHomeDir` and `ATMOS_DATA_HOME` overrides.
- **Aliasing/isolation** tests for schema decoders.
- **Compile-time sentinels** for new schema field references in tests.
- **Coverage target**: >80% (CodeCov enforced).
- **No integration tests** against real Teleport in CI. Optional
  `//go:build teleport_integration` tag for opt-in local integration tests
  against the `examples/demo-teleport/` setup.

## Security Considerations

- **Keychain is the canonical credential store.** Teleport certificates and
  private keys are persisted only in the Atmos keyring (the `teleport` envelope
  across the system/file/memory backends), handled uniformly with
  AWS/GCP/Azure/Pro credentials. Atmos does not depend on `~/.tsh` and writes no
  long-lived secrets to disk by default.
- **Short-lived certificates.** Kubernetes certs are issued per-cluster with a
  bounded TTL (`GenerateUserCerts`) and re-minted by the
  `atmos teleport kube token` exec plugin on demand, so the credentials embedded
  in a kubeconfig are ephemeral.
- **No static secrets for machine identities.** `teleport/bot` joins via AWS IAM
  (STS `GetCallerIdentity` sigv4) or GitHub OIDC — Atmos stores no static join
  secret. The derived `tbot` identity file is written `0600`, scoped by realm,
  and removed on `atmos auth logout`.
- **TLS verification.** The proxy connection verifies the cluster CA. `insecure`
  is dev-only (self-signed proxies); production pins via `ca_cert_path` /
  `ca_cert_pem` (mutually exclusive, validated at config-parse time).
- **Realm isolation.** Keyring entries are realm-scoped, so credentials for
  different environments never collide or leak across realms.
- **Secret masking.** Certificate/key material flows through Atmos's existing
  output masking; the exec-plugin output is consumed by kubectl, not logged.

## Documentation Deliverables

- This PRD (`docs/prd/teleport-auth.md`).
- Tutorial: `website/docs/tutorials/teleport-kubeconfig-authentication.mdx`
  (mirrors the `eks-kubeconfig-authentication.mdx` structure).
- Extension of `website/docs/cli/configuration/auth/index.mdx` to include the
  new kinds.
- Per-package READMEs: `pkg/auth/providers/teleport/README.md`,
  `pkg/auth/identities/teleport/README.md`,
  `pkg/auth/integrations/teleport/README.md`,
  `pkg/auth/cloud/teleport/README.md`.
- CLI command docs: `website/docs/cli/commands/teleport/teleport.mdx`,
  `kube/token.mdx`.
- Blog post: `website/blog/YYYY-MM-DD-teleport-auth.mdx` (tags: `feature`,
  `enhancement`).
- Roadmap update: `website/src/data/roadmap.js`.
- JSON schema updates in `pkg/datafetcher/schema/` for IDE autocompletion.

## Follow-Up Issues to File Before Merging V1

Per CLAUDE.md "Follow-up Tracking" requirements, each of these must be a GitHub
issue linked from the blog post / PR:

1. `teleport/database` integration (open in-process database proxy tunnels;
   export `PGHOST`/`PGPORT`/`MYSQL_*` env).
2. `teleport/ssh` integration (inject SSH config / known_hosts).
3. `teleport/app` integration (open application proxy tunnels).
4. Kubernetes service-account join method for `teleport/bot`.
5. Optional Teleport routing for `components.helmfile.use_eks: true` legacy
   path.
6. Static token join method for `teleport/bot` (lower-security; pending real
   demand).

Note: in-process interactive SSO login (no `tsh` dependency) is part of the v1
design (Phase 2), not a follow-up — it requires validation against a live
Teleport cluster.

## Open Questions

1. **Multi-Teleport future-proofing**: v1 design treats
   `principal.teleport_proxy_provider` as required on `teleport/bot`. Acceptable
   forward-compatibility for the single-cluster case the user has today.

2. **Bot identity output directory**: Defaults to
   `$ATMOS_DATA_HOME/.../teleport/bot/<realm>/<bot_name>/identity`
   (realm-scoped). Overridable via `spec.output_dir`. The keychain is canonical;
   this file is a derived artifact materialized on demand for `tsh -i` /
   `kubectl` interop.

3. **Renewal**: v1 does not implement transparent background renewal; bots ask
   Atmos to re-join on each invocation if the identity file is within 20% of TTL
   or already expired. Long-running commands (e.g., `atmos workflow` chains
   lasting hours) may need explicit renewal — tracked as a follow-up.

4. **Trusted clusters**: v1 supports a single Teleport cluster per
   `teleport/proxy` provider with an optional `principal.teleport_cluster` for
   trusted-cluster leaf routing.

## References

- `pkg/auth/integrations/aws/eks.go` — the structural template we are
  paralleling.
- `pkg/auth/cloud/aws/eks.go` — pattern for SDK wrappers (`EKSClient` interface
  \+ `mockgen`).
- `pkg/auth/cloud/kube/config.go` — kubeconfig manager (reused, not duplicated).
- `pkg/auth/manager_integrations.go:integrationTargetKey` — dedup keying for
  integrations.
- [EKS Kubeconfig Authentication PRD](./eks-kubeconfig.md) — the EKS PRD whose
  structure this PRD mirrors.
- External: `cruxstack/terraform-provider-teleportconnect` — reference for how
  this user has modeled Teleport connection settings in another tool. Field
  names align where reasonable.

## Changelog

- **2026-06-08** — Initial PRD. Keychain-canonical credential storage and
  Atmos-driven SSO supersede the earlier `~/.tsh`-as-source-of-truth design and
  the deferred-keyring (former "Phase 5") plan. Phase K (keychain envelope),
  Phase 3 (Kubernetes integration + `atmos teleport kube token`), and the Phase
  4 bot identity lifecycle implemented and unit-tested; the bot join handshake
  and interactive SSO web-login remain pending live-cluster validation.
