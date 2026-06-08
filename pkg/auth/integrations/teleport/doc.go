// Package teleport implements the teleport/kubernetes integration.
//
// teleport/kubernetes is parallel to aws/eks: it does not own identity, it
// materializes a kubeconfig for an identity that already holds Teleport
// credentials. The kubeconfig user is an exec credential plugin invoking
// `atmos teleport kube token`, so credentials auto-refresh as long as the
// underlying Teleport identity stays valid.
package teleport
