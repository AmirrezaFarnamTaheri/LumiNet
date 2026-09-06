package captchaclient

import (
	"fmt"
	"io"
)

const maxCaptchaResponseBytes int64 = 1 << 20

func readBoundedCaptchaResponse(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxCaptchaResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxCaptchaResponseBytes {
		return nil, fmt.Errorf("captcha provider response exceeds %d bytes", maxCaptchaResponseBytes)
	}
	return body, nil
}
