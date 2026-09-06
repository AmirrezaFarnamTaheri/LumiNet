package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/maybeknott/luminet/internal/platform/sshtrust"
)

// SshTunnelClient represents the client establishing TCP connections over an SSH tunnel.
type SshTunnelClient struct {
	Host                 string // e.g. "127.0.0.1:22"
	User                 string
	Password             string
	PrivateKey           string // optional SSH private key content
	PrivateKeyPassphrase string // optional passphrase for encrypted private-key content
	HostKeySHA256        string // required OpenSSH SHA-256 server host-key fingerprint
	DialTimeout          time.Duration
}

// NewSshTunnelClient instantiates a new SSH tunnel proxy client config.
func NewSshTunnelClient(host, user, password, privateKey, hostKeySHA256 string) *SshTunnelClient {
	return &SshTunnelClient{
		Host:          host,
		User:          user,
		Password:      password,
		PrivateKey:    privateKey,
		HostKeySHA256: hostKeySHA256,
		DialTimeout:   10 * time.Second,
	}
}

// SetPrivateKeyPassphrase supplies a passphrase for encrypted SSH private-key
// material. The value is kept on the client only long enough to prepare the
// signer and is never written to logs or host-identity errors.
func (c *SshTunnelClient) SetPrivateKeyPassphrase(passphrase string) *SshTunnelClient {
	c.PrivateKeyPassphrase = passphrase
	return c
}

func (c *SshTunnelClient) buildAuthMethods() ([]ssh.AuthMethod, error) {
	authMethods := []ssh.AuthMethod{}
	if c.PrivateKeyPassphrase != "" && c.PrivateKey == "" {
		return nil, fmt.Errorf("SSH private-key passphrase requires private key material")
	}
	if c.PrivateKey != "" {
		var (
			signer ssh.Signer
			err    error
		)
		if c.PrivateKeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(c.PrivateKey), []byte(c.PrivateKeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(c.PrivateKey))
		}
		if err != nil {
			if c.Password == "" {
				return nil, fmt.Errorf("failed to parse private key and no password fallback is configured: %w", err)
			}
		} else {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}
	if c.Password != "" {
		authMethods = append(authMethods, ssh.Password(c.Password))
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("SSH authentication requires a valid private key or password")
	}
	return authMethods, nil
}

// DialTarget dials the remote target through the SSH tunnel using a direct-tcpip channel.
func (c *SshTunnelClient) DialTarget(ctx context.Context, target string) (net.Conn, error) {
	authMethods, err := c.buildAuthMethods()
	if err != nil {
		return nil, err
	}

	hostIdentity, err := sshtrust.ParseSHA256(c.HostKeySHA256)
	if err != nil {
		return nil, fmt.Errorf("invalid SSH host identity: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            c.User,
		Auth:            authMethods,
		HostKeyCallback: hostIdentity.Callback(),
		Timeout:         c.DialTimeout,
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", c.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH server %s: %w", c.Host, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, c.Host, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to negotiate SSH client session: %w", err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)

	targetConn, err := client.Dial("tcp", target)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to dial target %s via SSH tunnel: %w", target, err)
	}

	return &sshConnWrapper{
		Conn:   targetConn,
		client: client,
	}, nil
}

type sshConnWrapper struct {
	net.Conn
	client *ssh.Client
}

func (w *sshConnWrapper) Close() error {
	err1 := w.Conn.Close()
	err2 := w.client.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
