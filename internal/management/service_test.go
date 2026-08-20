package management

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/teacat/mcp-execmesh/internal/config"
	"github.com/teacat/mcp-execmesh/internal/security"
	"github.com/teacat/mcp-execmesh/internal/target"
	"golang.org/x/crypto/ssh"
)

type fakeTester struct{}

func (fakeTester) Test(ctx context.Context, tc config.TargetConfig) (*TestResult, error) {
	return &TestResult{Success: true, SSH: true, HostKeyVerified: true, Authenticated: true, DefaultCwdValid: true}, nil
}

func writeOpenSSHPrivateKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0600))
}

func writeKnownHosts(t *testing.T, path, name string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	line := name + " " + string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	require.NoError(t, os.WriteFile(path, []byte(line), 0644))
}

func TestAddDisableRemoveTarget(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	key := filepath.Join(dir, "id_ed25519")
	writeOpenSSHPrivateKey(t, key)
	writeKnownHosts(t, kh, "10.0.0.22")
	targetsPath := filepath.Join(dir, "targets.yaml")
	credsPath := filepath.Join(dir, "credentials.yaml")
	require.NoError(t, os.WriteFile(targetsPath, []byte("version: 1\ntargets: []\n"), 0600))
	require.NoError(t, os.WriteFile(credsPath, []byte("version: 1\ncredentials:\n  - id: test-key\n    type: private_key\n    private_key_file: "+key+"\n"), 0600))

	cfg := config.DefaultConfig()
	cfg.Server.DataDir = dir
	cfg.TargetsFile = targetsPath
	cfg.CredentialsFile = credsPath
	cfg.Security.KnownHostsFile = kh
	cfg.Security.RequireKnownHosts = true
	creds, err := config.LoadCredentialsFile(credsPath)
	require.NoError(t, err)
	cfg.Credentials = creds
	require.NoError(t, config.ResolveAuthRefs(cfg))

	reg, err := target.NewRegistry(cfg)
	require.NoError(t, err)
	live := cfg
	svc := NewService(reg, nil, func() *config.Config { return live }, func() error {
		next := *live
		tg, err := config.LoadTargetsFile(targetsPath)
		if err != nil {
			return err
		}
		next.Targets = tg
		next.Credentials = creds
		if err := config.ResolveAuthRefs(&next); err != nil {
			return err
		}
		config.ApplyTargetDefaults(&next)
		if err := config.Validate(&next, config.ValidationOptions{CheckFilesExist: true}); err != nil {
			return err
		}
		if err := reg.Reload(&next); err != nil {
			return err
		}
		copied := next
		live = &copied
		return nil
	}, fakeTester{})

	admin := &security.Principal{
		ID: "admin", Subject: "admin", AuthType: "capability",
		Scopes:  security.ScopeSet(security.AllScopes),
		Targets: security.TargetSet([]string{"*"}),
	}
	denied := &security.Principal{
		ID: "user", Subject: "user", AuthType: "capability",
		Scopes:  security.ScopeSet(security.DataPlaneScopes),
		Targets: security.TargetSet([]string{"*"}),
	}

	_, err = svc.AddTarget(context.Background(), denied, TargetAddInput{ID: "t1", Host: "10.0.0.22", User: "root", AuthRef: "test-key"})
	require.Error(t, err)

	out, err := svc.AddTarget(context.Background(), admin, TargetAddInput{
		ID: "t1", Name: "T1", Host: "10.0.0.22", User: "root", AuthRef: "test-key", KnownHostRef: "10.0.0.22",
	})
	require.NoError(t, err)
	require.Equal(t, true, out["committed"])

	tgt, err := reg.Get(context.Background(), "t1")
	require.NoError(t, err)
	require.True(t, tgt.Enabled)

	require.NoError(t, svc.DisableTarget(admin, "t1"))
	tgt, err = reg.Get(context.Background(), "t1")
	require.NoError(t, err)
	require.Error(t, tgt.RequireActive())

	require.NoError(t, svc.RemoveTarget(admin, "t1"))
	_, err = reg.Get(context.Background(), "t1")
	require.Error(t, err)
}
