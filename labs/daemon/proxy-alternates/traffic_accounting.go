package proxy

import "github.com/maybeknott/luminet/internal/trafficstats"

var AddUploadBytes = trafficstats.AddUploadBytes
var AddDownloadBytes = trafficstats.AddDownloadBytes
var GetEvasionTrafficStats = trafficstats.GetEvasionTrafficStats
var ResetEvasionTrafficStats = trafficstats.ResetEvasionTrafficStats
