// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: Cloudflare-R2-oss-main
// Target path: server/internal/proxy/r2_storage_gateway.go

package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// R2StorageGateway handles secure object uploading to Cloudflare R2 storage buckets using AWS Signature Version 4.
type R2StorageGateway struct {
	AccountID       string
	AccessKeyID     string
	SecretAccessKey string
	HTTPClient      *http.Client
}

// NewR2StorageGateway instantiates a new R2StorageGateway.
func NewR2StorageGateway(accountID, keyID, secret string) *R2StorageGateway {
	return &R2StorageGateway{
		AccountID:       accountID,
		AccessKeyID:     keyID,
		SecretAccessKey: secret,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// 1. hmacSHA256 calculates the HMAC-SHA256 of a message using the given key.
func (r *R2StorageGateway) hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// 2. getSHA256Hex calculates the SHA256 hex string of a byte slice.
func (r *R2StorageGateway) getSHA256Hex(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// 3. SignRequest applies AWS Signature Version 4 headers to the given http.Request.
func (r *R2StorageGateway) SignRequest(req *http.Request, body []byte, service, region string, t time.Time) {
	amzDate := t.UTC().Format("20060102T150405Z")
	dateStamp := t.UTC().Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	payloadHash := r.getSHA256Hex(body)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	host := req.URL.Host
	req.Header.Set("Host", host)

	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", host, payloadHash, amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQuery := req.URL.Query().Encode()

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	)

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate,
		credentialScope,
		r.getSHA256Hex([]byte(canonicalRequest)),
	)

	kDate := r.hmacSHA256([]byte("AWS4"+r.SecretAccessKey), dateStamp)
	kRegion := r.hmacSHA256(kDate, region)
	kService := r.hmacSHA256(kRegion, service)
	kSigning := r.hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(r.hmacSHA256(kSigning, stringToSign))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		r.AccessKeyID,
		credentialScope,
		signedHeaders,
		signature,
	)
	req.Header.Set("Authorization", authHeader)
}

// 4. UploadObject pushes binary chunks/logs to a targeted R2 bucket signing it with S3 v4 auth.
func (r *R2StorageGateway) UploadObject(bucket string, key string, data []byte) error {
	url := fmt.Sprintf("https://%s.r2.cloudflarestorage.com/%s/%s", r.AccountID, bucket, key)

	req, err := http.NewRequest("PUT", url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	r.SignRequest(req, data, "s3", "us-east-1", time.Now())

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("r2 upload returned status %d", resp.StatusCode)
	}

	return nil
}

// 5. DownloadObject downloads a targeted object from R2 bucket.
func (r *R2StorageGateway) DownloadObject(bucket string, key string) ([]byte, error) {
	url := fmt.Sprintf("https://%s.r2.cloudflarestorage.com/%s/%s", r.AccountID, bucket, key)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	r.SignRequest(req, nil, "s3", "us-east-1", time.Now())

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("r2 download returned status %d", resp.StatusCode)
	}

	return ioutil.ReadAll(resp.Body)
}

// 6. DeleteObject deletes an object from R2 bucket.
func (r *R2StorageGateway) DeleteObject(bucket string, key string) error {
	url := fmt.Sprintf("https://%s.r2.cloudflarestorage.com/%s/%s", r.AccountID, bucket, key)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	r.SignRequest(req, nil, "s3", "us-east-1", time.Now())

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("r2 delete returned status %d", resp.StatusCode)
	}

	return nil
}

// 7. SetTimeout configures http client boundary timeout.
func (r *R2StorageGateway) SetTimeout(t time.Duration) {
	r.HTTPClient.Timeout = t
}

// 8. GetTimeout returns HTTP client timeout setting.
func (r *R2StorageGateway) GetTimeout() time.Duration {
	return r.HTTPClient.Timeout
}

// 9. SetCredentials updates client OAuth settings.
func (r *R2StorageGateway) SetCredentials(accountID, keyID, secret string) {
	r.AccountID = accountID
	r.AccessKeyID = keyID
	r.SecretAccessKey = secret
}

// 10. HeadObject retrieves metadata parameters.
func (r *R2StorageGateway) HeadObject(bucket, key string) (int64, error) {
	url := fmt.Sprintf("https://%s.r2.cloudflarestorage.com/%s/%s", r.AccountID, bucket, key)

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return 0, err
	}

	r.SignRequest(req, nil, "s3", "us-east-1", time.Now())

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("r2 head returned status %d", resp.StatusCode)
	}

	return resp.ContentLength, nil
}

// 11. ObjectExists checks if target object exists.
func (r *R2StorageGateway) ObjectExists(bucket, key string) (bool, error) {
	_, err := r.HeadObject(bucket, key)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// 12. CreateBucket registers a new storage bucket (PUT /bucket).
func (r *R2StorageGateway) CreateBucket(bucket string) error {
	url := fmt.Sprintf("https://%s.r2.cloudflarestorage.com/%s", r.AccountID, bucket)

	req, err := http.NewRequest("PUT", url, nil)
	if err != nil {
		return err
	}

	r.SignRequest(req, nil, "s3", "us-east-1", time.Now())

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("r2 create bucket returned status %d", resp.StatusCode)
	}

	return nil
}

// 13. DeleteBucket deletes an active storage bucket.
func (r *R2StorageGateway) DeleteBucket(bucket string) error {
	url := fmt.Sprintf("https://%s.r2.cloudflarestorage.com/%s", r.AccountID, bucket)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	r.SignRequest(req, nil, "s3", "us-east-1", time.Now())

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("r2 delete bucket returned status %d", resp.StatusCode)
	}

	return nil
}

// 14. ListObjects lists object keys within bucket.
func (r *R2StorageGateway) ListObjects(bucket string) ([]string, error) {
	url := fmt.Sprintf("https://%s.r2.cloudflarestorage.com/%s", r.AccountID, bucket)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	r.SignRequest(req, nil, "s3", "us-east-1", time.Now())

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("r2 list objects returned status %d", resp.StatusCode)
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var res struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal(respBytes, &res); err != nil {
		return nil, err
	}

	var keys []string
	for _, c := range res.Contents {
		keys = append(keys, c.Key)
	}
	return keys, nil
}

// 15. Upload is the legacy diagnostic interface trigger.
func (r *R2StorageGateway) Upload() {
	// Diagnostic stub
}
