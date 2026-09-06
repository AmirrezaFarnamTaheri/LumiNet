package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/maybeknott/luminet/internal/foundation/remoteaction"
)

const googleDriveUploadURL = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id"

// uploadGoogleDriveFile owns safe replay for Drive file creation. Drive lets a
// caller pre-generate a file ID and reuse that ID when creating a file. Keeping
// one generated ID across all attempts makes the create replay-safe at the
// provider boundary; a 409 after an ambiguous earlier attempt is accepted only
// after exact payload readback proves that the desired file was created.
func uploadGoogleDriveFile(
	ctx context.Context,
	client *http.Client,
	action string,
	accessToken string,
	folderID string,
	fileName string,
	mediaType string,
	expectedPayload []byte,
) error {
	fileID, err := generateGoogleDriveFileID(ctx, client, accessToken)
	if err != nil {
		return fmt.Errorf("Google Drive action %q generate ID: %w", action, err)
	}

	boundary := "luminet_drive_upload_boundary"
	requestBody, err := buildGoogleDriveMultipart(boundary, fileID, fileName, folderID, mediaType, expectedPayload)
	if err != nil {
		return fmt.Errorf("Google Drive action %q build multipart: %w", action, err)
	}

	policy := remoteaction.DefaultPolicy(action, remoteaction.Idempotent)
	policy.RateLimitScope = "provider.google-drive"
	outcome, err := remoteaction.Do(ctx, client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleDriveUploadURL, bytes.NewReader(requestBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "multipart/related; boundary="+boundary)
		return req, nil
	}, nil)
	if err != nil {
		return err
	}
	if outcome.Response == nil {
		return fmt.Errorf("Google Drive action %q completed without response", action)
	}
	defer outcome.Response.Body.Close()

	if outcome.Response.StatusCode == http.StatusConflict {
		matched, matchErr := googleDriveFilePayloadMatches(ctx, client, accessToken, fileID, expectedPayload)
		if matchErr != nil {
			return fmt.Errorf("Google Drive action %q conflict readback: %w", action, matchErr)
		}
		if !matched {
			return fmt.Errorf("Google Drive action %q conflict for file %q but payload differs", action, fileID)
		}
		return nil
	}

	if outcome.Response.StatusCode != http.StatusOK && outcome.Response.StatusCode != http.StatusCreated {
		body, readErr := readBoundedProxyHTTPBody(outcome.Response.Body, maxProxyControlHTTPBodyBytes, "Google Drive control response")
		if readErr != nil {
			return fmt.Errorf("Google Drive action %q returned status %d and unreadable body: %w", action, outcome.Response.StatusCode, readErr)
		}
		return fmt.Errorf("Google Drive action %q returned status %d: %s", action, outcome.Response.StatusCode, string(body))
	}
	return nil
}

func generateGoogleDriveFileID(ctx context.Context, client *http.Client, accessToken string) (string, error) {
	params := url.Values{}
	params.Set("count", "1")
	params.Set("space", "drive")
	params.Set("type", "files")
	requestURL := "https://www.googleapis.com/drive/v3/files/generateIds?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, readErr := readBoundedProxyHTTPBody(resp.Body, maxProxyControlHTTPBodyBytes, "Google Drive generated-ID response")
	if readErr != nil {
		return "", readErr
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	var generated struct {
		IDs []string `json:"ids"`
	}
	if err := json.Unmarshal(body, &generated); err != nil {
		return "", err
	}
	if len(generated.IDs) != 1 || strings.TrimSpace(generated.IDs[0]) == "" {
		return "", fmt.Errorf("provider returned no usable file ID")
	}
	return generated.IDs[0], nil
}

func buildGoogleDriveMultipart(boundary, fileID, fileName, folderID, mediaType string, payload []byte) ([]byte, error) {
	metadata, err := json.Marshal(struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Parents []string `json:"parents"`
	}{ID: fileID, Name: fileName, Parents: []string{folderID}})
	if err != nil {
		return nil, err
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.SetBoundary(boundary); err != nil {
		return nil, err
	}

	metadataHeader := make(textproto.MIMEHeader)
	metadataHeader.Set("Content-Type", "application/json; charset=UTF-8")
	metadataPart, err := writer.CreatePart(metadataHeader)
	if err != nil {
		return nil, err
	}
	if _, err := metadataPart.Write(metadata); err != nil {
		return nil, err
	}

	mediaHeader := make(textproto.MIMEHeader)
	mediaHeader.Set("Content-Type", mediaType)
	mediaPart, err := writer.CreatePart(mediaHeader)
	if err != nil {
		return nil, err
	}
	if _, err := mediaPart.Write(payload); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func googleDriveFilePayloadMatches(ctx context.Context, client *http.Client, accessToken, fileID string, expectedPayload []byte) (bool, error) {
	downloadURL := fmt.Sprintf("https://www.googleapis.com/drive/v3/files/%s?alt=media", url.PathEscape(fileID))
	downloadReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return false, err
	}
	downloadReq.Header.Set("Authorization", "Bearer "+accessToken)
	downloadResp, err := client.Do(downloadReq)
	if err != nil {
		return false, err
	}
	defer downloadResp.Body.Close()
	if downloadResp.StatusCode != http.StatusOK {
		body, _ := readBoundedProxyHTTPBody(downloadResp.Body, maxProxyControlHTTPBodyBytes, "Google Drive conflict readback")
		return false, fmt.Errorf("download returned status %d: %s", downloadResp.StatusCode, string(body))
	}
	payload, err := readBoundedProxyHTTPBody(downloadResp.Body, maxCovertEncodedChunkBodyBytes, "Google Drive conflict payload")
	if err != nil {
		return false, err
	}
	return bytes.Equal(payload, expectedPayload), nil
}

func deleteGoogleDriveFileBestEffort(ctx context.Context, client *http.Client, action, accessToken, fileID string) {
	policy := remoteaction.DefaultPolicy(action, remoteaction.Idempotent)
	policy.RateLimitScope = "provider.google-drive"
	outcome, err := remoteaction.Do(ctx, client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "https://www.googleapis.com/drive/v3/files/"+url.PathEscape(fileID), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		return req, nil
	}, nil)
	if err != nil || outcome.Response == nil {
		return
	}
	defer outcome.Response.Body.Close()
	// DELETE is idempotent for this owner: 2xx and 404 both mean the file is no
	// longer present. Cleanup remains best-effort, so other final failures are
	// intentionally not promoted to the read path.
	_, _ = io.CopyN(io.Discard, outcome.Response.Body, 4<<10)
}

func escapeDriveQueryLiteral(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `'`, `\'`)
}
