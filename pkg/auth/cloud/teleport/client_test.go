package teleport

import (
	"context"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	errUtils "github.com/cloudposse/atmos/errors"
	"github.com/cloudposse/atmos/pkg/auth/types"
)

// fakeAPIClient is an in-memory apiClient used to unit-test sdkClient's request
// construction and response mapping without dialing a real Teleport cluster.
type fakeAPIClient struct {
	pingResp proto.PingResponse
	pingErr  error
	certs    *proto.Certs
	certsErr error
	gotReq   proto.UserCertsRequest
	closed   bool
}

func (f *fakeAPIClient) Ping(_ context.Context) (proto.PingResponse, error) {
	return f.pingResp, f.pingErr
}

func (f *fakeAPIClient) GenerateUserCerts(_ context.Context, req proto.UserCertsRequest) (*proto.Certs, error) {
	f.gotReq = req
	return f.certs, f.certsErr
}

func (f *fakeAPIClient) Close() error {
	f.closed = true
	return nil
}

func TestNewClient_ValidationErrors(t *testing.T) {
	certPEM, keyPEM, _ := genCertPEM(t, "user")

	tests := []struct {
		name    string
		creds   *types.TeleportCredentials
		wantErr error
	}{
		{
			name:    "nil credentials",
			creds:   nil,
			wantErr: errUtils.ErrTeleportInvalidConfig,
		},
		{
			name:    "missing proxy address",
			creds:   &types.TeleportCredentials{TLSCertPEM: certPEM, TLSKeyPEM: keyPEM},
			wantErr: errUtils.ErrTeleportProxyResolution,
		},
		{
			name:    "missing TLS material",
			creds:   &types.TeleportCredentials{ProxyAddress: "teleport.example.com:443"},
			wantErr: errUtils.ErrTeleportInvalidConfig,
		},
		{
			name:    "invalid TLS key pair",
			creds:   &types.TeleportCredentials{ProxyAddress: "teleport.example.com:443", TLSCertPEM: "not-a-cert", TLSKeyPEM: "not-a-key"},
			wantErr: errUtils.ErrTeleportInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// These all fail before any network dial is attempted.
			_, err := NewClient(context.Background(), tt.creds)
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestSDKClient_Ping_MapsResponse(t *testing.T) {
	fake := &fakeAPIClient{pingResp: proto.PingResponse{
		ClusterName:     "example-cluster",
		ServerVersion:   "16.0.0",
		ProxyPublicAddr: "teleport.example.com:443",
	}}
	c := &sdkClient{api: fake, proxyAddress: "teleport.example.com:443", username: "alice"}

	resp, err := c.Ping(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "example-cluster", resp.ClusterName)
	assert.Equal(t, "16.0.0", resp.ServerVersion)
	assert.Equal(t, "teleport.example.com:443", resp.ProxyPublicAddr)
}

func TestSDKClient_Ping_Error(t *testing.T) {
	fake := &fakeAPIClient{pingErr: errors.New("connection refused")}
	c := &sdkClient{api: fake}

	_, err := c.Ping(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, errUtils.ErrTeleportProxyUnreachable)
}

func TestSDKClient_GenerateKubeCert_MapsCertsAndRequest(t *testing.T) {
	kubeCertPEM, _, _ := genCertPEM(t, "kube")
	ca1, _, _ := genCertPEM(t, "ca-1")
	ca2, _, _ := genCertPEM(t, "ca-2")

	fake := &fakeAPIClient{certs: &proto.Certs{
		TLS:        []byte(kubeCertPEM),
		TLSCACerts: [][]byte{[]byte(ca1), []byte(ca2)},
	}}
	c := &sdkClient{api: fake, proxyAddress: "teleport.example.com:443", username: "alice"}

	out, err := c.GenerateKubeCert(context.Background(), GenerateKubeCertRequest{
		KubernetesCluster: "prod-eks",
		TTL:               "30m",
	})
	require.NoError(t, err)

	// Response mapping.
	assert.Equal(t, kubeCertPEM, out.TLSCertPEM)
	require.Len(t, out.TLSCAsPEM, 2)
	assert.Equal(t, ca1, out.TLSCAsPEM[0])
	assert.Equal(t, ca2, out.TLSCAsPEM[1])
	assert.Equal(t, "teleport.example.com:443", out.KubeProxyAddress)
	// A real private key PEM was generated for the request.
	block, _ := pem.Decode([]byte(out.TLSKeyPEM))
	require.NotNil(t, block, "generated key should be valid PEM")
	assert.WithinDuration(t, time.Now().Add(30*time.Minute), out.Expires, time.Minute)

	// Request construction: kube-routed, kube usage, signed for the username,
	// with a non-empty TLS public key.
	assert.Equal(t, "prod-eks", fake.gotReq.KubernetesCluster)
	assert.Equal(t, proto.UserCertsRequest_Kubernetes, fake.gotReq.Usage)
	assert.Equal(t, "alice", fake.gotReq.Username)
	assert.NotEmpty(t, fake.gotReq.TLSPublicKey)
}

func TestSDKClient_GenerateKubeCert_RequiresCluster(t *testing.T) {
	c := &sdkClient{api: &fakeAPIClient{}}
	_, err := c.GenerateKubeCert(context.Background(), GenerateKubeCertRequest{})
	require.Error(t, err)
	assert.ErrorIs(t, err, errUtils.ErrTeleportKubeCertGeneration)
}

func TestSDKClient_GenerateKubeCert_PropagatesError(t *testing.T) {
	fake := &fakeAPIClient{certsErr: errors.New("access denied")}
	c := &sdkClient{api: fake, username: "alice"}
	_, err := c.GenerateKubeCert(context.Background(), GenerateKubeCertRequest{KubernetesCluster: "prod-eks"})
	require.Error(t, err)
	assert.ErrorIs(t, err, errUtils.ErrTeleportKubeCertGeneration)
}

func TestSDKClient_Close(t *testing.T) {
	fake := &fakeAPIClient{}
	c := &sdkClient{api: fake}
	require.NoError(t, c.Close())
	assert.True(t, fake.closed)

	// Nil api is tolerated.
	empty := &sdkClient{}
	assert.NoError(t, empty.Close())
}

func TestResolveTTL(t *testing.T) {
	assert.Equal(t, defaultKubeCertTTL, resolveTTL(""))
	assert.Equal(t, defaultKubeCertTTL, resolveTTL("garbage"))
	assert.Equal(t, defaultKubeCertTTL, resolveTTL("-5m"))
	assert.Equal(t, 90*time.Minute, resolveTTL("90m"))
}
