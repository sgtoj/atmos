# Teleport Identities

Implements the `teleport/user` and `teleport/bot` identity kinds.

## teleport/user

Workstation user identity backed by Atmos's in-process Teleport SSO web-login
(credentials cached in the Atmos keychain; no `~/.tsh`, no `tsh` binary).

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
      principal:                       # optional
        roles: [editor]                # request subset of roles
        kubernetes_clusters: [prod-eks] # pre-route to specific k8s clusters
        ttl: 1h
```

- Atmos drives the interactive SSO web-login itself (against the proxy's
  `/webapi` endpoints) and caches the issued credentials in the Atmos keychain.
- Atmos re-issues a refined cert via `GenerateUserCerts` only when the principal
  requests it (roles or kube clusters specified).
- The interactive web-login flow requires validation against a live Teleport
  cluster.

## teleport/bot

CI/CD machine identity backed by a tbot-equivalent join handshake. Two join
methods are supported in v1: GitHub OIDC and AWS IAM.

### GitHub OIDC join

```yaml
auth:
  providers:
    github:
      kind: github/oidc
    company-teleport:
      kind: teleport/proxy
      spec: { proxy_address: teleport.company.com:443 }

  identities:
    ci-bot:
      kind: teleport/bot
      via:
        provider: github             # source of join credentials
      principal:
        teleport_proxy_provider: company-teleport  # target Teleport cluster
        bot_name: github-actions
        join_method: github
        join_token: gha-deploy-token
        roles: [terraform-ci]
        ttl: 1h
```

### AWS IAM join

```yaml
auth:
  identities:
    runner-aws-role: { kind: aws/permission-set, ... }
    ci-bot:
      kind: teleport/bot
      via:
        identity: runner-aws-role    # AWS creds for STS sigv4 signature
      principal:
        teleport_proxy_provider: company-teleport
        bot_name: aws-runner
        join_method: iam
        join_token: aws-runner-token
        roles: [terraform-ci]
        aws:
          region: us-east-1
```

## Why `teleport_proxy_provider` and not `via.provider`?

The `via:` chain in Atmos auth is the source of *credentials*. For
`teleport/bot`, those credentials are NOT the Teleport cluster's own creds —
they come from a separate upstream (GitHub OIDC token or AWS sigv4 signature)
that drives the join handshake. The Teleport cluster is the *target*, not the
source, so it's referenced by name in the principal instead of via the chain.

This mirrors how the `aws/eks` integration references an EKS cluster: the
cluster is a target, not a credentials source.

## Credential storage

The Atmos keychain (`pkg/auth/credentials/`) is the canonical store for both
user and bot Teleport credentials (the auth manager persists the credentials a
`teleport/*` identity returns, using the `teleport` keyring envelope). Atmos
does not depend on `~/.tsh`.

For bot identities, a derived `tbot`-format identity file is additionally
materialized on disk for subprocess interop (`tsh -i`, `kubectl` exec plugins).
It defaults to `$ATMOS_DATA_HOME/atmos/teleport/bot/<realm>/<bot_name>/identity`
(override with `principal.output_dir`), is exported as `TELEPORT_IDENTITY_FILE`,
and is removed on `atmos auth logout`. The file is a cache/interop artifact, not
the source of truth.

## Implementation status

- Bot identity **lifecycle** — keychain persistence (via the manager),
  identity-file materialization (`PostAuthenticate`), `CredentialsExist`,
  `LoadCredentials`, `Logout`, and realm-scoped paths — is implemented and
  unit-tested via the `botJoinFn` seam.
- The bot **join handshake** itself (`cloud/teleport.Join`: AWS IAM sigv4 and
  GitHub OIDC) and the resolution of `principal.teleport_proxy_provider` to a
  proxy address are validated against a live Teleport cluster.
