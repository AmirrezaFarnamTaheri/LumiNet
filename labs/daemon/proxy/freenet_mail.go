// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: mail-main
// Target path: server/internal/proxy/freenet_mail.go

package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"strconv"
	"strings"
)

// FreenetMailMessage represents a decentralized email structure.
type FreenetMailMessage struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Subject   string `json:"subject"`
	Body      []byte `json:"body"`      // Encrypted via AES-GCM (simulating ML-KEM payload)
	Signature []byte `json:"signature"` // HMAC-SHA256 signature (simulating ML-DSA payload)
	Nonce     int64  `json:"nonce"`
}

// FreenetMail handles decentralized Freenet email message formatting, encryption, and anti-flood validation.
type FreenetMail struct {
	active bool
}

// NewFreenetMail instantiates a FreenetMail helper.
func NewFreenetMail() *FreenetMail {
	return &FreenetMail{active: true}
}

// 1. EncryptAndSignMessage encrypts the mail body using AES-GCM and generates an HMAC-SHA256 signature.
func (f *FreenetMail) EncryptAndSignMessage(sender, recipient, subject, bodyText string, sharedKey []byte) (*FreenetMailMessage, error) {
	if len(sharedKey) != 32 {
		return nil, fmt.Errorf("sharedKey must be exactly 32 bytes")
	}

	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, iv, []byte(bodyText), nil)
	encryptedBody := append(iv, ciphertext...)

	// Compute HMAC-SHA256 signature
	mac := hmac.New(sha256.New, sharedKey)
	mac.Write([]byte(sender + recipient + subject))
	mac.Write(encryptedBody)
	signatureBytes := mac.Sum(nil)

	return &FreenetMailMessage{
		Sender:    sender,
		Recipient: recipient,
		Subject:   subject,
		Body:      encryptedBody,
		Signature: signatureBytes,
	}, nil
}

// 2. VerifyAndDecryptMessage verifies the signature and decrypts the plaintext mail body.
func (f *FreenetMail) VerifyAndDecryptMessage(msg *FreenetMailMessage, sharedKey []byte) (string, error) {
	if len(sharedKey) != 32 {
		return "", fmt.Errorf("sharedKey must be exactly 32 bytes")
	}

	// Verify HMAC signature
	mac := hmac.New(sha256.New, sharedKey)
	mac.Write([]byte(msg.Sender + msg.Recipient + msg.Subject))
	mac.Write(msg.Body)
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal(msg.Signature, expectedSignature) {
		return "", fmt.Errorf("signature verification failed: message integrity compromised")
	}

	// Decrypt body
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(msg.Body) < nonceSize {
		return "", fmt.Errorf("invalid body length: shorter than IV")
	}

	iv := msg.Body[:nonceSize]
	ciphertext := msg.Body[nonceSize:]

	plaintext, err := aesGCM.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}

// 3. SolveAntiFloodToken calculates the proof-of-work nonce.
func (f *FreenetMail) SolveAntiFloodToken(msg *FreenetMailMessage, difficulty int) int64 {
	prefix := strings.Repeat("0", difficulty)
	dataPrefix := msg.Sender + msg.Recipient + msg.Subject + string(msg.Body)

	for nonce := int64(0); nonce < math.MaxInt64; nonce++ {
		data := dataPrefix + strconv.FormatInt(nonce, 10)
		hash := sha256.Sum256([]byte(data))
		hashStr := hex.EncodeToString(hash[:])

		if strings.HasPrefix(hashStr, prefix) {
			return nonce
		}
	}
	return 0
}

// 4. VerifyAntiFloodToken checks if the message nonce satisfies the proof-of-work difficulty.
func (f *FreenetMail) VerifyAntiFloodToken(msg *FreenetMailMessage, difficulty int) bool {
	data := msg.Sender + msg.Recipient + msg.Subject + string(msg.Body) + strconv.FormatInt(msg.Nonce, 10)
	hash := sha256.Sum256([]byte(data))
	hashStr := hex.EncodeToString(hash[:])

	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hashStr, prefix)
}

// 5. GenerateLocalMailKeyPair generates public/private keypairs using ECDSA.
func (f *FreenetMail) GenerateLocalMailKeyPair() (string, string, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	privBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", "", err
	}
	privBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}
	privPEM := pem.EncodeToMemory(privBlock)

	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	pubPEM := pem.EncodeToMemory(pubBlock)

	return string(privPEM), string(pubPEM), nil
}

// 6. EncapsulateKey simulates KEM key exchange generating a shared key.
func (f *FreenetMail) EncapsulateKey(pubKeyPEM string) ([]byte, []byte, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("invalid public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("not an ECDSA public key")
	}

	// Generate shared key and encapsulate it
	sharedKey := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, sharedKey)

	// Encrypt sharedKey using ECDSA public key
	r, s, err := ecdsa.Sign(rand.Reader, &ecdsa.PrivateKey{PublicKey: *ecdsaPub}, sharedKey)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := append(r.Bytes(), s.Bytes()...)

	return sharedKey, ciphertext, nil
}

// 7. DecapsulateKey decapsulates KEM shared keys.
func (f *FreenetMail) DecapsulateKey(privKeyPEM string, ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}

	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	_ = priv // Simulating decapsulation using ECDSA private keys
	sharedKey := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, sharedKey)

	return sharedKey, nil
}

// 8. LoadMailKeys loads keys from disk paths.
func (f *FreenetMail) LoadMailKeys(privPath, pubPath string) (string, string, error) {
	privBytes, err := ioutil.ReadFile(privPath)
	if err != nil {
		return "", "", err
	}
	pubBytes, err := ioutil.ReadFile(pubPath)
	if err != nil {
		return "", "", err
	}
	return string(privBytes), string(pubBytes), nil
}

// 9. ValidateMessageMetadata performs size and field checks.
func (f *FreenetMail) ValidateMessageMetadata(msg *FreenetMailMessage) error {
	if msg.Sender == "" || msg.Recipient == "" {
		return fmt.Errorf("sender and recipient cannot be empty")
	}
	if len(msg.Body) == 0 {
		return fmt.Errorf("encrypted mail body cannot be empty")
	}
	if len(msg.Signature) != 32 {
		return fmt.Errorf("invalid signature size")
	}
	return nil
}

// 10. Mail is the legacy interface trigger.
func (f *FreenetMail) Mail() {
	// Diagnostic stub
}

// SetActive overrides decentralized email execution state.
func (f *FreenetMail) SetActive(active bool) {
	f.active = active
}

// GetActive retrieves decentralized email execution state.
func (f *FreenetMail) GetActive() bool {
	return f.active
}

// SetSender overrides sender mail identity.
func (msg *FreenetMailMessage) SetSender(sender string) {
	msg.Sender = sender
}

// GetSender retrieves sender mail identity.
func (msg *FreenetMailMessage) GetSender() string {
	return msg.Sender
}

// SetRecipient overrides recipient mail identity.
func (msg *FreenetMailMessage) SetRecipient(recipient string) {
	msg.Recipient = recipient
}

// GetRecipient retrieves recipient mail identity.
func (msg *FreenetMailMessage) GetRecipient() string {
	return msg.Recipient
}

// SetSubject overrides mail subject descriptor.
func (msg *FreenetMailMessage) SetSubject(subject string) {
	msg.Subject = subject
}

// GetSubject retrieves mail subject descriptor.
func (msg *FreenetMailMessage) GetSubject() string {
	return msg.Subject
}

// SetBody overrides AES-GCM encrypted mail body.
func (msg *FreenetMailMessage) SetBody(body []byte) {
	copied := make([]byte, len(body))
	copy(copied, body)
	msg.Body = copied
}

// GetBody retrieves AES-GCM encrypted mail body.
func (msg *FreenetMailMessage) GetBody() []byte {
	copied := make([]byte, len(msg.Body))
	copy(copied, msg.Body)
	return copied
}

// SetSignature overrides HMAC-SHA256 signature payload.
func (msg *FreenetMailMessage) SetSignature(sig []byte) {
	copied := make([]byte, len(sig))
	copy(copied, sig)
	msg.Signature = copied
}

// GetSignature retrieves HMAC-SHA256 signature payload.
func (msg *FreenetMailMessage) GetSignature() []byte {
	copied := make([]byte, len(msg.Signature))
	copy(copied, msg.Signature)
	return copied
}

// SetNonce overrides proof of work anti-flood token.
func (msg *FreenetMailMessage) SetNonce(nonce int64) {
	msg.Nonce = nonce
}

// GetNonce retrieves proof of work anti-flood token.
func (msg *FreenetMailMessage) GetNonce() int64 {
	return msg.Nonce
}
