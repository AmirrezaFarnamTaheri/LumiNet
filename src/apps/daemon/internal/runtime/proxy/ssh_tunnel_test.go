package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHTunneling(t *testing.T) {
	// Create local echo TCP listener
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen for echo service: %v", err)
	}
	defer echoListener.Close()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// Start local mock SSH server
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "testuser" && string(pass) == "testpass" {
				return nil, nil
			}
			return nil, fmt.Errorf("auth failed")
		},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}
	sshConfig.AddHostKey(signer)

	sshListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen for mock SSH: %v", err)
	}
	defer sshListener.Close()

	go func() {
		for {
			conn, err := sshListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sshConn, chans, reqs, err := ssh.NewServerConn(c, sshConfig)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "direct-tcpip" {
						_ = newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}

					type localForward struct {
						DestAddr string
						DestPort uint32
						OrigAddr string
						OrigPort uint32
					}
					var payload localForward
					if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
						_ = newChan.Reject(ssh.ConnectionFailed, "bad payload")
						continue
					}

					channel, requests, err := newChan.Accept()
					if err != nil {
						continue
					}
					go ssh.DiscardRequests(requests)

					dest := net.JoinHostPort(payload.DestAddr, strconv.FormatUint(uint64(payload.DestPort), 10))
					destConn, err := net.Dial("tcp", dest)
					if err != nil {
						_ = channel.Close()
						continue
					}

					go func() {
						defer channel.Close()
						defer destConn.Close()
						_, _ = io.Copy(channel, destConn)
					}()
					go func() {
						defer channel.Close()
						defer destConn.Close()
						_, _ = io.Copy(destConn, channel)
					}()
				}
				_ = sshConn.Close()
			}(conn)
		}
	}()

	client := NewSshTunnelClient(sshListener.Addr().String(), "testuser", "testpass", "", ssh.FingerprintSHA256(signer.PublicKey()))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.DialTarget(ctx, echoListener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial target through SSH tunnel: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello ssh tunnel")
	_, err = conn.Write(payload)
	if err != nil {
		t.Fatalf("Failed to write to SSH tunnel: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read from SSH tunnel: %v", err)
	}

	if string(buf[:n]) != string(payload) {
		t.Errorf("Got message %q, want %q", buf[:n], payload)
	}
}

func TestSSHTunnelRejectsEmptyAuthBeforeNetwork(t *testing.T) {
	client := NewSshTunnelClient("203.0.113.1:22", "user", "", "", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := client.DialTarget(ctx, "example.com:443")
	if err == nil || !strings.Contains(err.Error(), "authentication requires") {
		t.Fatalf("expected pre-network auth admission failure, got %v", err)
	}
}

func TestSSHTunnelRejectsMalformedPrivateKeyWithoutFallbackBeforeNetwork(t *testing.T) {
	client := NewSshTunnelClient("203.0.113.1:22", "user", "", "not-a-private-key", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := client.DialTarget(ctx, "example.com:443")
	if err == nil || !strings.Contains(err.Error(), "no password fallback") {
		t.Fatalf("expected malformed-key admission failure, got %v", err)
	}
}

func TestSSHTunnelMalformedPrivateKeyAllowsExplicitPasswordFallback(t *testing.T) {
	// A malformed key must not erase an independently configured password method.
	// Host identity parsing occurs after auth preparation, so this invalid identity
	// is the expected next failure and proves the password fallback survived.
	client := NewSshTunnelClient("203.0.113.1:22", "user", "password", "not-a-private-key", "not-a-fingerprint")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := client.DialTarget(ctx, "example.com:443")
	if err == nil || !strings.Contains(err.Error(), "invalid SSH host identity") {
		t.Fatalf("expected host-identity failure after password fallback admission, got %v", err)
	}
}

func TestSSHTunnelEncryptedPrivateKeyPassphraseAdmission(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const passphrase = "correct horse battery staple"
	block, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "luminet-test", []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(block))

	client := NewSshTunnelClient("203.0.113.1:22", "user", "", keyPEM, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").SetPrivateKeyPassphrase(passphrase)
	methods, err := client.buildAuthMethods()
	if err != nil {
		t.Fatalf("encrypted private key was not admitted: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("auth method count=%d, want 1 public-key method", len(methods))
	}
}

func TestSSHTunnelRejectsOrphanPrivateKeyPassphraseBeforeNetwork(t *testing.T) {
	client := NewSshTunnelClient("203.0.113.1:22", "user", "password", "", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").SetPrivateKeyPassphrase("orphan-secret")
	if _, err := client.buildAuthMethods(); err == nil || !strings.Contains(err.Error(), "passphrase requires private key") {
		t.Fatalf("orphan passphrase admitted: %v", err)
	}
}
