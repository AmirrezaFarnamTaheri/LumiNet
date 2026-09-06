package mobile

type AppInfo struct {
    Name        string `json:"name"`
    PackageName string `json:"packageName"`
    IsSystem    bool   `json:"isSystemApp"`
    IconBase64  string `json:"icon"` // PNG base64 for dashboard rendering
}
