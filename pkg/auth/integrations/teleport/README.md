# teleport/kubernetes Integration

Materializes a kubeconfig for a Teleport-mediated Kubernetes cluster, parallel
to the existing `aws/eks` integration.

## Configuration

```yaml
auth:
  identities:
    teleport-user: { kind: teleport/user, via: { provider: company-teleport } }

  integrations:
    prod-eks:
      kind: teleport/kubernetes
      via:
        identity: teleport-user
      spec:
        teleport_kubernetes:
          name: prod-eks               # Teleport-registered k8s cluster name
          alias: prod                  # optional kubeconfig context name
          kubeconfig:                  # optional, see aws/eks for reference
            path: ~/.kube/config
            mode: "0600"
            update: merge              # merge | replace | error
```

## Behavior

1. `Execute()` issues a per-cluster TLS certificate via the Teleport SDK
   (`GenerateUserCerts` with `KubernetesCluster` set).
2. The kubeconfig is updated with:
   - `cluster.server` pointing at the Teleport proxy's ALPN listener.
   - `user.exec` invoking `atmos teleport kube token --cluster=<name>` so the
     cert auto-refreshes on every kubectl invocation.
   - A context tying them together.
3. `Environment()` exports `KUBECONFIG` (and `KUBE_CONFIG_PATH`) so subsequent
   subprocesses (helmfile, kubectl) read the right file.

## Coexistence with `aws/eks`

Two integrations of either kind can write to the same kubeconfig file. The
kubeconfig manager (`pkg/auth/cloud/kube`) merges entries by context name.
Atmos's `KUBECONFIG` env composition is path-list (`:` / `;`) aware, so
multi-integration setups also work when they prefer separate files.

## When NOT to use this

If the EKS cluster is reachable directly with AWS auth (not behind Teleport),
use `aws/eks` instead. `teleport/kubernetes` requires the cluster to be
registered as a Teleport resource.
