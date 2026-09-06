// Package proxy implements proxy server handlers and protocol parsers.
// Ported from: Cloudflare-R2-oss-main (utils/s3.ts)
// Target path: server/internal/proxy/s3_signer.go

package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// S3Signer implements AWS Signature Version 4 signing for S3/R2 endpoints.
type S3Signer struct {
	mu              sync.RWMutex
	AccessKeyId     string
	SecretAccessKey string
	Region          string
	Service         string
	Method          string
	Host            string
	Path            string
	Query           string
	PayloadHash     string
	DateString      string
	Timestamp       string
	Scope           string
}

// Getters & Setters for S3Signer
func (s *S3Signer) GetAccessKeyId() string  { s.mu.RLock(); defer s.mu.RUnlock(); return s.AccessKeyId }
func (s *S3Signer) SetAccessKeyId(v string) { s.mu.Lock(); defer s.mu.Unlock(); s.AccessKeyId = v }
func (s *S3Signer) GetSecretAccessKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.SecretAccessKey
}
func (s *S3Signer) SetSecretAccessKey(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SecretAccessKey = v
}
func (s *S3Signer) GetRegion() string       { s.mu.RLock(); defer s.mu.RUnlock(); return s.Region }
func (s *S3Signer) SetRegion(v string)      { s.mu.Lock(); defer s.mu.Unlock(); s.Region = v }
func (s *S3Signer) GetService() string      { s.mu.RLock(); defer s.mu.RUnlock(); return s.Service }
func (s *S3Signer) SetService(v string)     { s.mu.Lock(); defer s.mu.Unlock(); s.Service = v }
func (s *S3Signer) GetMethod() string       { s.mu.RLock(); defer s.mu.RUnlock(); return s.Method }
func (s *S3Signer) SetMethod(v string)      { s.mu.Lock(); defer s.mu.Unlock(); s.Method = v }
func (s *S3Signer) GetHost() string         { s.mu.RLock(); defer s.mu.RUnlock(); return s.Host }
func (s *S3Signer) SetHost(v string)        { s.mu.Lock(); defer s.mu.Unlock(); s.Host = v }
func (s *S3Signer) GetPath() string         { s.mu.RLock(); defer s.mu.RUnlock(); return s.Path }
func (s *S3Signer) SetPath(v string)        { s.mu.Lock(); defer s.mu.Unlock(); s.Path = v }
func (s *S3Signer) GetQuery() string        { s.mu.RLock(); defer s.mu.RUnlock(); return s.Query }
func (s *S3Signer) SetQuery(v string)       { s.mu.Lock(); defer s.mu.Unlock(); s.Query = v }
func (s *S3Signer) GetPayloadHash() string  { s.mu.RLock(); defer s.mu.RUnlock(); return s.PayloadHash }
func (s *S3Signer) SetPayloadHash(v string) { s.mu.Lock(); defer s.mu.Unlock(); s.PayloadHash = v }
func (s *S3Signer) GetDateString() string   { s.mu.RLock(); defer s.mu.RUnlock(); return s.DateString }
func (s *S3Signer) SetDateString(v string)  { s.mu.Lock(); defer s.mu.Unlock(); s.DateString = v }
func (s *S3Signer) GetTimestamp() string    { s.mu.RLock(); defer s.mu.RUnlock(); return s.Timestamp }
func (s *S3Signer) SetTimestamp(v string)   { s.mu.Lock(); defer s.mu.Unlock(); s.Timestamp = v }
func (s *S3Signer) GetScope() string        { s.mu.RLock(); defer s.mu.RUnlock(); return s.Scope }
func (s *S3Signer) SetScope(v string)       { s.mu.Lock(); defer s.mu.Unlock(); s.Scope = v }

// Builders for S3Signer
func (s *S3Signer) WithAccessKeyId(v string) *S3Signer     { s.SetAccessKeyId(v); return s }
func (s *S3Signer) WithSecretAccessKey(v string) *S3Signer { s.SetSecretAccessKey(v); return s }
func (s *S3Signer) WithRegion(v string) *S3Signer          { s.SetRegion(v); return s }
func (s *S3Signer) WithService(v string) *S3Signer         { s.SetService(v); return s }
func (s *S3Signer) WithMethod(v string) *S3Signer          { s.SetMethod(v); return s }
func (s *S3Signer) WithHost(v string) *S3Signer            { s.SetHost(v); return s }
func (s *S3Signer) WithPath(v string) *S3Signer            { s.SetPath(v); return s }
func (s *S3Signer) WithQuery(v string) *S3Signer           { s.SetQuery(v); return s }
func (s *S3Signer) WithPayloadHash(v string) *S3Signer     { s.SetPayloadHash(v); return s }
func (s *S3Signer) WithDateString(v string) *S3Signer      { s.SetDateString(v); return s }
func (s *S3Signer) WithTimestamp(v string) *S3Signer       { s.SetTimestamp(v); return s }
func (s *S3Signer) WithScope(v string) *S3Signer           { s.SetScope(v); return s }

// Operations
func NewS3Signer(accessKey, secretKey, region string) *S3Signer {
	return &S3Signer{
		AccessKeyId:     accessKey,
		SecretAccessKey: secretKey,
		Region:          region,
		Service:         "s3",
		PayloadHash:     "UNSIGNED-PAYLOAD",
	}
}

func (s *S3Signer) SignRequest(req *http.Request) error {
	t := time.Now().UTC()
	s.SetTimestamp(t.Format("20060102T150405Z"))
	s.SetDateString(s.GetTimestamp()[:8])

	s.SetHost(req.URL.Host)
	s.SetMethod(req.Method)
	s.SetPath(req.URL.EscapedPath())
	s.SetQuery(req.URL.RawQuery)

	scope := fmt.Sprintf("%s/%s/%s/aws4_request", s.GetDateString(), s.GetRegion(), s.GetService())
	s.SetScope(scope)

	req.Header.Set("x-amz-date", s.GetTimestamp())
	req.Header.Set("x-amz-content-sha256", s.GetPayloadHash())
	req.Header.Set("host", s.GetHost())

	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", s.GetHost(), s.GetPayloadHash(), s.GetTimestamp())
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	canonicalRequest := strings.Join([]string{
		s.GetMethod(),
		s.GetPath(),
		s.GetQuery(),
		canonicalHeaders,
		signedHeaders,
		s.GetPayloadHash(),
	}, "\n")

	hashedRequest := s.HashSHA256(canonicalRequest)

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		s.GetTimestamp(),
		s.GetScope(),
		hashedRequest,
	}, "\n")

	signingKey := s.CalculateSigningKey()
	signature := hex.EncodeToString(s.HmacSHA256(signingKey, []byte(stringToSign)))

	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s", s.GetAccessKeyId(), s.GetScope(), signedHeaders, signature)
	req.Header.Set("Authorization", auth)

	return nil
}

func (s *S3Signer) HmacSHA256(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func (s *S3Signer) HashSHA256(data string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *S3Signer) CalculateSigningKey() []byte {
	kDate := s.HmacSHA256([]byte("AWS4"+s.GetSecretAccessKey()), []byte(s.GetDateString()))
	kRegion := s.HmacSHA256(kDate, []byte(s.GetRegion()))
	kService := s.HmacSHA256(kRegion, []byte(s.GetService()))
	signingKey := s.HmacSHA256(kService, []byte("aws4_request"))
	return signingKey
}

func (s *S3Signer) GetAuthStatus(guestEnv string, authHeader string, path string) bool {
	if strings.HasPrefix(path, "_$flaredrive$/thumbnails/") {
		return true
	}
	if guestEnv != "" {
		allowGuest := strings.Split(guestEnv, ",")
		for _, g := range allowGuest {
			if g == "*" || strings.HasPrefix(path, g) {
				return true
			}
		}
	}
	if !strings.HasPrefix(authHeader, "Basic ") {
		return false
	}
	return true
}
