package proxy

import "github.com/maybeknott/luminet/internal/cleanipprobe"

type CloudflareCleanIPProber = cleanipprobe.CloudflareCleanIPProber

func NewCloudflareCleanIPProber() *CloudflareCleanIPProber {
	return cleanipprobe.NewCloudflareCleanIPProber()
}
