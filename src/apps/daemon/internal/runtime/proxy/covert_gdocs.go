package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GDocsTransport represents a covert transport using the Google Drive REST API.
// Construction requires real credentials; product code has no simulator mode.
type GDocsTransport struct {
	FolderID    string
	AccessToken string
	HTTPClient  *http.Client
}

// NewGDocsTransport creates a credentialed Google Drive covert transport.
func NewGDocsTransport(folderID, accessToken string) (*GDocsTransport, error) {
	if strings.TrimSpace(folderID) == "" {
		return nil, fmt.Errorf("gdocs transport requires a folder ID")
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("gdocs transport requires an access token")
	}
	return &GDocsTransport{
		FolderID:    folderID,
		AccessToken: accessToken,
		HTTPClient:  &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// SendChunk uploads a chunk of SOCKS5 data to Google Drive as a file or document revision.
func (t *GDocsTransport) SendChunk(ctx context.Context, sessionID string, chunkIdx int, data []byte) error {
	if len(data) > maxCovertRawChunkBytes {
		return fmt.Errorf("Google Drive chunk exceeds %d bytes", maxCovertRawChunkBytes)
	}
	if len(data) == 0 {
		return nil
	}

	payloadB64 := base64.StdEncoding.EncodeToString(data)
	fileName := fmt.Sprintf("%s_chunk_%d.txt", sessionID, chunkIdx)

	return uploadGoogleDriveFile(
		ctx,
		t.HTTPClient,
		"gdocs.chunk.upload",
		t.AccessToken,
		t.FolderID,
		fileName,
		"text/plain",
		[]byte(payloadB64),
	)
}

// ReadChunk downloads a specific chunk of data from the shared Google Drive folder.
func (t *GDocsTransport) ReadChunk(ctx context.Context, sessionID string, chunkIdx int) ([]byte, error) {
	// Production Mode: Query Google Drive API for the specific file name
	fileName := fmt.Sprintf("%s_chunk_%d.txt", sessionID, chunkIdx)
	query := fmt.Sprintf("name = '%s' and '%s' in parents and trashed = false", fileName, t.FolderID)

	// Escape the query for URL
	queryEscaped := url.QueryEscape(query)
	listURL := fmt.Sprintf("https://www.googleapis.com/drive/v3/files?q=%s&fields=files(id,name)", queryEscaped)

	req, err := http.NewRequestWithContext(ctx, "GET", listURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)

	resp, err := t.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := readBoundedProxyHTTPBody(resp.Body, maxProxyControlHTTPBodyBytes, "Google Drive control response")
		return nil, fmt.Errorf("google api list returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var listResp struct {
		Files []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"files"`
	}

	body, err := readBoundedProxyHTTPBody(resp.Body, maxProxyControlHTTPBodyBytes, "Google Drive list response")
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &listResp); err != nil {
		return nil, err
	}

	if len(listResp.Files) == 0 {
		return nil, nil // Not found yet, poll again
	}

	fileID := listResp.Files[0].ID

	// Download file media content
	downloadURL := fmt.Sprintf("https://www.googleapis.com/drive/v3/files/%s?alt=media", fileID)
	downloadReq, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, err
	}
	downloadReq.Header.Set("Authorization", "Bearer "+t.AccessToken)

	downloadResp, err := t.HTTPClient.Do(downloadReq)
	if err != nil {
		return nil, err
	}
	defer downloadResp.Body.Close()

	if downloadResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google api download returned status %d", downloadResp.StatusCode)
	}

	bodyBytes, err := readBoundedProxyHTTPBody(downloadResp.Body, maxCovertEncodedChunkBodyBytes, "Google Drive chunk")
	if err != nil {
		return nil, err
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(string(bodyBytes))
	if err != nil {
		return nil, err
	}

	deleteGoogleDriveFileBestEffort(ctx, t.HTTPClient, "gdocs.chunk.delete", t.AccessToken, fileID)

	return decodedBytes, nil
}

// VirtualConnection creates a net.Conn wrapper that routes reads and writes via Google Docs API calls.
func (t *GDocsTransport) VirtualConnection(ctx context.Context, sessionID string) net.Conn {
	return &gdocsConn{
		transport: t,
		sessionID: sessionID,
		readBuf:   nil,
		chunkIdx:  0,
		writeIdx:  0,
		ctx:       ctx,
	}
}

type gdocsConn struct {
	transport *GDocsTransport
	sessionID string
	readBuf   []byte
	chunkIdx  int
	writeIdx  int
	ctx       context.Context
}

func (c *gdocsConn) Read(b []byte) (int, error) {
	if len(c.readBuf) == 0 {
		// Polling for the next chunk
		for {
			data, err := c.transport.ReadChunk(c.ctx, c.sessionID, c.chunkIdx)
			if err != nil {
				return 0, err // might be io.EOF or other errors
			}
			if data != nil {
				c.readBuf = data
				c.chunkIdx++
				break
			}
			// If data is nil, it means the file wasn't found yet or is empty. Poll again.
			select {
			case <-c.ctx.Done():
				return 0, c.ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	}

	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *gdocsConn) Write(b []byte) (int, error) {
	err := c.transport.SendChunk(c.ctx, c.sessionID, c.writeIdx, b)
	if err != nil {
		return 0, err
	}
	c.writeIdx++
	return len(b), nil
}

func (c *gdocsConn) Close() error                       { return nil }
func (c *gdocsConn) LocalAddr() net.Addr                { return nil }
func (c *gdocsConn) RemoteAddr() net.Addr               { return nil }
func (c *gdocsConn) SetDeadline(t time.Time) error      { return nil }
func (c *gdocsConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *gdocsConn) SetWriteDeadline(t time.Time) error { return nil }
