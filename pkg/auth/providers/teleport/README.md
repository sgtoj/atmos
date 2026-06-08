# teleport/proxy Provider

Implements the `teleport/proxy` provider kind: a reference to a Teleport
cluster's proxy endpoint.

## Configuration

```yaml
auth:
  providers:
    company-teleport:
      kind: teleport/proxy
      spec:
        proxy_address: teleport.company.com:443
        auth_connector: okta           # optional SSO connector (IdP) hint
        insecure: false                # optional, dev only
        ca_cert_path: /etc/ssl/teleport-ca.pem  # optional, mutually exclusive with ca_cert_pem
        ca_cert_pem: |                 # optional, mutually exclusive with ca_cert_path
          -----BEGIN CERTIFICATE-----
          ...
          -----END CERTIFICATE-----
```

## Behavior

- For workstation users: the provider's `Authenticate()` drives Atmos's
  in-process Teleport SSO web-login against `proxy_address` (using
  `auth_connector` to select the IdP) and returns the issued credentials, which
  the auth manager caches in the Atmos keychain. Atmos does **not** read
  `~/.tsh` and never shells out to the `tsh` binary. (The interactive web-login
  flow requires validation against a live Teleport cluster.)

- For CI/CD bots: the provider's `Authenticate()` is not called by the bot
  identity. The bot references this provider by name (via its
  `principal.teleport_proxy_provider` field) to know which Teleport cluster to
  join, but the join handshake itself is driven by the bot using credentials
  from a different upstream (github/oidc, aws/\*).

## Environment variables

`Environment()` exports:

- `TELEPORT_PROXY` — the proxy host:port.
