package proxy

import (
	"crypto/rand"
	"fmt"
	"sync"
)

type DeviceProfile struct {
	DeviceModel string `json:"device_model"`
	OSVersion   string `json:"os_version"`
	HardwareID  string `json:"hardware_id"`
	AndroidID   string `json:"android_id"`
	CpuInfo     string `json:"cpu_info"`
}

type DeviceProfileEmulator struct {
	mu      sync.RWMutex
	profile DeviceProfile

	// HTTP Spoofing fields
	UserAgent      string
	AcceptLanguage string

	// JS Injection fields for browser fingerprinting evasion
	AudioSeed  float64
	RectOffset float64
}

func NewDeviceProfileEmulator() *DeviceProfileEmulator {
	b := make([]byte, 8)
	rand.Read(b)

	bAndroid := make([]byte, 8)
	rand.Read(bAndroid)
	androidID := fmt.Sprintf("%x", bAndroid)

	// Generate random offsets for fingerprint spoofing
	bAudio := make([]byte, 8)
	rand.Read(bAudio)
	audioSeed := float64(bAudio[0]) / 255.0

	bRect := make([]byte, 8)
	rand.Read(bRect)
	rectOffset := (float64(bRect[0])/255.0)*0.01 - 0.005 // -0.005 to +0.005

	return &DeviceProfileEmulator{
		profile: DeviceProfile{
			DeviceModel: "LumiNet Generic Workstation",
			OSVersion:   "10.0.19045",
			HardwareID:  fmt.Sprintf("%x", b),
			AndroidID:   androidID,
			CpuInfo:     "processor\t: 0\nmodel name\t: Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz\ncpu MHz\t\t: 2900.000\ncache size\t: 16384 KB\nbogomips\t: 5800.00\n",
		},
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		AcceptLanguage: "en-US,en;q=0.9",
		AudioSeed:      audioSeed,
		RectOffset:     rectOffset,
	}
}

func (e *DeviceProfileEmulator) GetProfile() DeviceProfile {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.profile
}

// SpoofHeaders returns headers to override the client's original headers
func (e *DeviceProfileEmulator) SpoofHeaders() map[string]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return map[string]string{
		"User-Agent":      e.UserAgent,
		"Accept-Language": e.AcceptLanguage,
	}
}

// InjectionScript returns the JavaScript to inject into HTML responses to spoof client-side fingerprinting
func (e *DeviceProfileEmulator) InjectionScript() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return fmt.Sprintf(`
<script>
(function() {
    // 1. Spoof getBoundingClientRect (Client-Rects fingerprint protection)
    var originalGetBoundingClientRect = Element.prototype.getBoundingClientRect;
    Element.prototype.getBoundingClientRect = function() {
        var rect = originalGetBoundingClientRect.call(this);
        return {
            x: rect.x + %f,
            y: rect.y + %f,
            width: rect.width + %f,
            height: rect.height + %f,
            top: rect.top + %f,
            right: rect.right + %f,
            bottom: rect.bottom + %f,
            left: rect.left + %f
        };
    };

    // 2. Spoof Web Audio API
    var originalCreateOscillator = AudioContext.prototype.createOscillator;
    AudioContext.prototype.createOscillator = function() {
        var osc = originalCreateOscillator.call(this);
        var originalStart = osc.start;
        osc.start = function() {
            osc.frequency.value += %f;
            return originalStart.apply(osc, arguments);
        };
        return osc;
    };

    // 3. Spoof HTML5 Canvas (Clearcote-Browser style seed-based farbling)
    var originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function() {
        var ctx = this.getContext('2d');
        if (ctx) {
            try {
                var w = this.width, h = this.height;
                if (w > 0 && h > 0) {
                    var imgData = ctx.getImageData(0, 0, w, h);
                    // Add subtle deterministic noise based on hostname hash
                    var hash = 0;
                    var host = window.location.hostname || "local";
                    for (var i = 0; i < host.length; i++) {
                        hash = (hash << 5) - hash + host.charCodeAt(i);
                        hash |= 0;
                    }
                    var idx = Math.abs(hash) %% (imgData.data.length / 4) * 4;
                    imgData.data[idx] = (imgData.data[idx] ^ 1) & 0xFF;
                    ctx.putImageData(imgData, 0, 0);
                }
            } catch (e) {}
        }
        return originalToDataURL.apply(this, arguments);
    };

    var originalToBlob = HTMLCanvasElement.prototype.toBlob;
    HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {
        var ctx = this.getContext('2d');
        if (ctx) {
            try {
                var w = this.width, h = this.height;
                if (w > 0 && h > 0) {
                    var imgData = ctx.getImageData(0, 0, w, h);
                    var hash = 0;
                    var host = window.location.hostname || "local";
                    for (var i = 0; i < host.length; i++) {
                        hash = (hash << 5) - hash + host.charCodeAt(i);
                        hash |= 0;
                    }
                    var idx = Math.abs(hash) %% (imgData.data.length / 4) * 4;
                    imgData.data[idx] = (imgData.data[idx] ^ 1) & 0xFF;
                    ctx.putImageData(imgData, 0, 0);
                }
            } catch (e) {}
        }
        return originalToBlob.apply(this, arguments);
    };

    var originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh) {
        var imgData = originalGetImageData.apply(this, arguments);
        if (imgData && imgData.data && imgData.data.length > 0) {
            var hash = 0;
            var host = window.location.hostname || "local";
            for (var i = 0; i < host.length; i++) {
                hash = (hash << 5) - hash + host.charCodeAt(i);
                hash |= 0;
            }
            var idx = Math.abs(hash) %% (imgData.data.length / 4) * 4;
            imgData.data[idx] = (imgData.data[idx] ^ 1) & 0xFF;
        }
        return imgData;
    };

    // 4. Spoof Navigator and Screen properties (from clearcote-browser and device_faker)
    try {
        Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
        Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
        Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });

        Object.defineProperty(Screen.prototype, 'width', { get: () => 1920 });
        Object.defineProperty(Screen.prototype, 'height', { get: () => 1080 });
        Object.defineProperty(Screen.prototype, 'availWidth', { get: () => 1920 });
        Object.defineProperty(Screen.prototype, 'availHeight', { get: () => 1040 });
        Object.defineProperty(Screen.prototype, 'colorDepth', { get: () => 24 });
        Object.defineProperty(Screen.prototype, 'pixelDepth', { get: () => 24 });
    } catch (e) {}
})();
</script>
`, e.RectOffset, e.RectOffset, e.RectOffset, e.RectOffset, e.RectOffset, e.RectOffset, e.RectOffset, e.RectOffset, e.AudioSeed)
}

// GetSpoofedSystemProperties returns key Android system properties to spoof (inspired by COPG-JSON and device_faker)
func (e *DeviceProfileEmulator) GetSpoofedSystemProperties() map[string]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return map[string]string{
		"ro.product.model":         "Pixel 7 Pro",
		"ro.product.brand":         "google",
		"ro.product.name":          "cheetah",
		"ro.product.device":        "cheetah",
		"ro.product.board":         "cheetah",
		"ro.product.manufacturer":  "Google",
		"ro.build.version.sdk":     "33",
		"ro.build.version.release": "13",
		"ro.hardware":              "google_pixel",
		"ro.serialno":              e.profile.HardwareID,
		"ro.android_id":            e.profile.AndroidID,
	}
}

func (e *DeviceProfileEmulator) UpdateProfile(deviceModel, osVersion, hardwareID, androidID, cpuInfo string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if deviceModel != "" {
		e.profile.DeviceModel = deviceModel
	}
	if osVersion != "" {
		e.profile.OSVersion = osVersion
	}
	if hardwareID != "" {
		e.profile.HardwareID = hardwareID
	}
	if androidID != "" {
		e.profile.AndroidID = androidID
	}
	if cpuInfo != "" {
		e.profile.CpuInfo = cpuInfo
	}
}
