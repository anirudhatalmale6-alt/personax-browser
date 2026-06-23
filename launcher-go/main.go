package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Embedded dashboard
// ---------------------------------------------------------------------------

//go:embed dashboard.html
var dashboardHTML string

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

type Profile struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	FolderID     string          `json:"folder_id"`
	FolderName   string          `json:"folder_name"`
	Proxy        string          `json:"proxy"`
	WindowWidth  int             `json:"window_width"`
	WindowHeight int             `json:"window_height"`
	UserAgent    string          `json:"user_agent"`
	Notes        string          `json:"notes"`
	StartupURL   string          `json:"startup_url"`
	Fingerprint  json.RawMessage `json:"fingerprint"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
	LastLaunched string          `json:"last_launched"`
}

type Folder struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ProfileCount int    `json:"profile_count"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type RunningProfile struct {
	ProfileID string `json:"profile_id"`
	PID       int    `json:"pid"`
}

type StatusResponse struct {
	Running          []RunningProfile `json:"running"`
	ChromiumReady    bool             `json:"chromium_ready"`
	ChromiumPath     string           `json:"chromium_path"`
	Downloading      bool             `json:"downloading"`
	DownloadProgress float64          `json:"download_progress"`
	DownloadError    string           `json:"download_error"`
	ServerURL        string           `json:"server_url"`
	ServerConnected  bool             `json:"server_connected"`
}

type LaunchRequest struct {
	ProfileID string `json:"profile_id"`
}

type StopRequest struct {
	ProfileID string `json:"profile_id"`
}

type ConnectRequest struct {
	Server string `json:"server"`
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

var (
	mu               sync.Mutex
	processes        = make(map[string]*os.Process)
	chromiumReady    bool
	chromiumPath     string
	downloading      bool
	downloadProgress float64
	downloadError    string
	dataDir          string
	serverURL        string
	httpClient       = &http.Client{Timeout: 20 * time.Second}
)

func init() {
	home := os.Getenv("USERPROFILE")
	if home == "" {
		home = os.Getenv("APPDATA")
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	dataDir = filepath.Join(home, ".antidetect")
}

// ---------------------------------------------------------------------------
// Proxy encryption (hide PROXY.csv from install folder)
// ---------------------------------------------------------------------------

var proxyEncKey = []byte("B00R4T-PR0XY-S3CR3T-K3Y!2026!!")

func encryptData(data []byte) ([]byte, error) {
	hash := sha256.Sum256(proxyEncKey)
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decryptData(data []byte) ([]byte, error) {
	hash := sha256.Sum256(proxyEncKey)
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("data too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func encryptedProxyPath() string {
	return filepath.Join(dataDir, "proxies", "proxy.dat")
}

func ensureEncryptedProxy() {
	csvPath := filepath.Join(dataDir, "proxies", "PROXY.csv")
	encPath := encryptedProxyPath()

	if _, err := os.Stat(encPath); err == nil {
		return
	}

	data, err := os.ReadFile(csvPath)
	if err != nil {
		return
	}

	encrypted, err := encryptData(data)
	if err != nil {
		log.Printf("Failed to encrypt proxy: %v", err)
		return
	}

	os.WriteFile(encPath, encrypted, 0644)
	os.Remove(csvPath)
	log.Printf("Proxy list encrypted and CSV removed")
}

func loadDecryptedProxies() []string {
	encPath := encryptedProxyPath()
	csvPath := filepath.Join(dataDir, "proxies", "PROXY.csv")

	var rawData []byte
	var err error

	rawData, err = os.ReadFile(encPath)
	if err == nil {
		rawData, err = decryptData(rawData)
		if err != nil {
			log.Printf("Failed to decrypt proxy: %v", err)
			return nil
		}
	} else {
		rawData, err = os.ReadFile(csvPath)
		if err != nil {
			return nil
		}
	}

	var proxies []string
	lines := strings.Split(string(rawData), "\n")
	for i, line := range lines {
		if i == 0 {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 3)
		if len(parts) >= 2 {
			proxy := strings.TrimSpace(parts[1])
			if proxy != "" && strings.Contains(proxy, ":") {
				proxies = append(proxies, proxy)
			}
		}
	}
	return proxies
}

// ---------------------------------------------------------------------------
// CORS middleware
// ---------------------------------------------------------------------------

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// Chromium management
// ---------------------------------------------------------------------------

func chromiumExePath() string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(dataDir, "chromium", "chrome-mac", "Chromium.app", "Contents", "MacOS", "Chromium")
	}
	return filepath.Join(dataDir, "chromium", "chrome-win", "chrome.exe")
}

func checkChromium() {
	p := chromiumExePath()
	if _, err := os.Stat(p); err == nil {
		mu.Lock()
		chromiumReady = true
		chromiumPath = p
		mu.Unlock()
	}
}

func downloadChromium() {
	mu.Lock()
	if downloading {
		mu.Unlock()
		return
	}
	downloading = true
	downloadProgress = 0
	downloadError = ""
	mu.Unlock()

	go func() {
		defer func() {
			mu.Lock()
			downloading = false
			mu.Unlock()
		}()

		setErr := func(msg string) {
			mu.Lock()
			downloadError = msg
			mu.Unlock()
			log.Printf("Chromium download error: %s", msg)
		}

		setProgress := func(pct float64) {
			mu.Lock()
			downloadProgress = pct
			mu.Unlock()
		}

		dlClient := &http.Client{Timeout: 10 * time.Minute}
		metaClient := &http.Client{Timeout: 30 * time.Second}

		var platform, zipName string
		switch runtime.GOOS {
		case "darwin":
			if runtime.GOARCH == "arm64" {
				platform = "Mac_Arm"
			} else {
				platform = "Mac"
			}
			zipName = "chrome-mac.zip"
		default:
			platform = "Win_x64"
			zipName = "chrome-win.zip"
		}

		log.Printf("Fetching latest Chromium revision for %s...", platform)
		resp, err := metaClient.Get("https://storage.googleapis.com/chromium-browser-snapshots/" + platform + "/LAST_CHANGE")
		if err != nil {
			setErr(fmt.Sprintf("Failed to fetch revision: %v", err))
			return
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			setErr(fmt.Sprintf("Failed to read revision: %v", err))
			return
		}
		revision := strings.TrimSpace(string(body))
		log.Printf("Latest Chromium revision: %s", revision)

		setProgress(5)

		zipURL := fmt.Sprintf("https://storage.googleapis.com/chromium-browser-snapshots/%s/%s/%s", platform, revision, zipName)
		destDir := filepath.Join(dataDir, "chromium")
		os.MkdirAll(destDir, 0755)
		zipPath := filepath.Join(destDir, zipName)

		maxRetries := 3
		var lastErr error
		for attempt := 1; attempt <= maxRetries; attempt++ {
			if attempt > 1 {
				log.Printf("Retry %d/%d for Chromium download...", attempt, maxRetries)
				setProgress(5)
				mu.Lock()
				downloadError = ""
				mu.Unlock()
				time.Sleep(3 * time.Second)
			}

			lastErr = downloadChromiumZip(dlClient, zipURL, zipPath, setProgress)
			if lastErr == nil {
				break
			}
			log.Printf("Download attempt %d failed: %v", attempt, lastErr)
		}

		if lastErr != nil {
			os.Remove(zipPath)
			setErr(fmt.Sprintf("Download failed after %d attempts: %v", maxRetries, lastErr))
			return
		}

		setProgress(87)
		log.Println("Extracting Chromium...")

		if err := extractZip(zipPath, destDir); err != nil {
			setErr(fmt.Sprintf("Extract failed: %v", err))
			return
		}

		os.Remove(zipPath)

		if runtime.GOOS == "darwin" {
			chromeBin := chromiumExePath()
			os.Chmod(chromeBin, 0755)
			helpersDir := filepath.Join(dataDir, "chromium", "chrome-mac", "Chromium.app", "Contents", "Frameworks")
			filepath.Walk(helpersDir, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() && strings.Contains(path, "MacOS") {
					os.Chmod(path, 0755)
				}
				return nil
			})
		}

		setProgress(100)
		checkChromium()
		log.Println("Chromium ready!")
	}()
}

func downloadChromiumZip(client *http.Client, zipURL, zipPath string, setProgress func(float64)) error {
	log.Printf("Downloading: %s", zipURL)

	req, err := http.NewRequest("GET", zipURL, nil)
	if err != nil {
		return fmt.Errorf("request creation failed: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	totalSize := resp.ContentLength
	log.Printf("Chromium zip size: %d bytes (%.1f MB)", totalSize, float64(totalSize)/1048576)

	out, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("cannot create zip: %v", err)
	}
	defer out.Close()

	type readResult struct {
		n   int
		err error
	}

	var downloaded int64
	buf := make([]byte, 256*1024)
	stallTimeout := 60 * time.Second

	for {
		ch := make(chan readResult, 1)
		go func() {
			n, err := resp.Body.Read(buf)
			ch <- readResult{n, err}
		}()

		select {
		case res := <-ch:
			if res.n > 0 {
				_, writeErr := out.Write(buf[:res.n])
				if writeErr != nil {
					return fmt.Errorf("write error: %v", writeErr)
				}
				downloaded += int64(res.n)
				if totalSize > 0 {
					pct := 5.0 + (float64(downloaded)/float64(totalSize))*80.0
					setProgress(pct)
				}
			}
			if res.err != nil {
				if res.err == io.EOF {
					log.Printf("Downloaded %d bytes", downloaded)
					if totalSize > 0 && downloaded < totalSize {
						return fmt.Errorf("incomplete: got %d of %d bytes", downloaded, totalSize)
					}
					return nil
				}
				return fmt.Errorf("read error after %d bytes: %v", downloaded, res.err)
			}
		case <-time.After(stallTimeout):
			return fmt.Errorf("download stalled at %d bytes (no data for %v)", downloaded, stallTimeout)
		}
	}
}

func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		target := filepath.Join(destDir, f.Name)

		// Prevent zip slip
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0755)
			continue
		}

		os.MkdirAll(filepath.Dir(target), 0755)

		rc, err := f.Open()
		if err != nil {
			return err
		}

		w, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			return err
		}
		io.Copy(w, rc)
		w.Close()
		rc.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Fingerprint extension (MV3)
// ---------------------------------------------------------------------------

func ensureFPExtension() (string, error) {
	extDir := filepath.Join(dataDir, "fp-extension")
	os.MkdirAll(extDir, 0755)

	manifest := `{
  "manifest_version": 3,
  "name": "Fingerprint Guard",
  "version": "1.0",
  "description": "Browser fingerprint management",
  "permissions": ["storage"],
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["inject.js"],
    "run_at": "document_start",
    "world": "MAIN"
  }]
}`

	inject := `(function() {
  'use strict';
  try {
    var cfgEl = document.getElementById('__fp_config__');
    var config;
    if (cfgEl) {
      config = JSON.parse(cfgEl.textContent);
    } else {
      var xhr = new XMLHttpRequest();
      xhr.open('GET', chrome.runtime.getURL ? chrome.runtime.getURL('config.json') : 'config.json', false);
      try { xhr.send(); config = JSON.parse(xhr.responseText); } catch(e) {}
    }
    if (!config) {
      try {
        var fs = require('fs');
        config = JSON.parse(fs.readFileSync(__dirname + '/config.json', 'utf8'));
      } catch(e2) {}
    }
    if (!config) return;

    // ── Advanced cloaking ──────────────────────────────────────────────
    var _toString = Function.prototype.toString;
    var _map = new WeakMap();
    Function.prototype.toString = function() {
      if (_map.has(this)) return _map.get(this);
      return _toString.call(this);
    };
    _map.set(Function.prototype.toString, 'function toString() { [native code] }');

    function cloak(fn, nativeName) {
      _map.set(fn, 'function ' + (nativeName || '') + '() { [native code] }');
      return fn;
    }

    // Make defineProperty overrides look native to getOwnPropertyDescriptor checks
    var _origDefProp = Object.defineProperty;
    var _origGetOwnPropDesc = Object.getOwnPropertyDescriptor;
    var _hiddenDescs = new Map();

    function stealthDefineProperty(obj, prop, descriptor) {
      var origDesc = _origGetOwnPropDesc.call(Object, obj, prop);
      _origDefProp.call(Object, obj, prop, descriptor);
      if (origDesc) {
        _hiddenDescs.set(obj + '::' + prop, origDesc);
      }
    }

    function stealthGetter(obj, prop, getter, nativeName) {
      cloak(getter, nativeName || ('get ' + prop));
      _origDefProp.call(Object, obj, prop, {
        get: getter,
        configurable: true,
        enumerable: true
      });
    }

    // ── PRNG ───────────────────────────────────────────────────────────
    function mulberry32(a) {
      return function() {
        a |= 0; a = a + 0x6D2B79F5 | 0;
        var t = Math.imul(a ^ a >>> 15, 1 | a);
        t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
        return ((t ^ t >>> 14) >>> 0) / 4294967296;
      };
    }

    // ── Canvas fingerprint noise ───────────────────────────────────────
    if (config.canvas && config.canvas.noise_seed) {
      var rng = mulberry32(config.canvas.noise_seed);

      var origToDataURL = HTMLCanvasElement.prototype.toDataURL;
      HTMLCanvasElement.prototype.toDataURL = cloak(function() {
        try {
          var ctx = this.getContext('2d');
          if (ctx && this.width > 0 && this.height > 0) {
            var imageData = ctx.getImageData(0, 0, this.width, this.height);
            var d = imageData.data;
            for (var i = 0; i < d.length; i += 4) {
              d[i] = Math.max(0, Math.min(255, d[i] + Math.floor((rng() - 0.5) * 2)));
            }
            ctx.putImageData(imageData, 0, 0);
          }
        } catch(e) {}
        return origToDataURL.apply(this, arguments);
      }, 'toDataURL');

      var origToBlob = HTMLCanvasElement.prototype.toBlob;
      HTMLCanvasElement.prototype.toBlob = cloak(function(cb, type, quality) {
        try {
          var ctx = this.getContext('2d');
          if (ctx && this.width > 0 && this.height > 0) {
            var imageData = ctx.getImageData(0, 0, this.width, this.height);
            var d = imageData.data;
            for (var i = 0; i < d.length; i += 4) {
              d[i] = Math.max(0, Math.min(255, d[i] + Math.floor((rng() - 0.5) * 2)));
            }
            ctx.putImageData(imageData, 0, 0);
          }
        } catch(e) {}
        return origToBlob.call(this, cb, type, quality);
      }, 'toBlob');

      // Also patch getImageData to add noise for fingerprint reads
      var origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
      CanvasRenderingContext2D.prototype.getImageData = cloak(function() {
        var imageData = origGetImageData.apply(this, arguments);
        var d = imageData.data;
        for (var i = 0; i < d.length; i += 4) {
          d[i] = Math.max(0, Math.min(255, d[i] + Math.floor((rng() - 0.5) * 2)));
        }
        return imageData;
      }, 'getImageData');
    }

    // ── WebGL spoofing ─────────────────────────────────────────────────
    if (config.webgl) {
      var patchWebGL = function(proto) {
        var origGetParam = proto.getParameter;
        proto.getParameter = cloak(function(param) {
          var ext = this.getExtension('WEBGL_debug_renderer_info');
          if (ext) {
            if (param === ext.UNMASKED_VENDOR_WEBGL && config.webgl.vendor) return config.webgl.vendor;
            if (param === ext.UNMASKED_RENDERER_WEBGL && config.webgl.renderer) return config.webgl.renderer;
          }
          return origGetParam.call(this, param);
        }, 'getParameter');
      };
      patchWebGL(WebGLRenderingContext.prototype);
      if (typeof WebGL2RenderingContext !== 'undefined') patchWebGL(WebGL2RenderingContext.prototype);
    }

    // ── Audio context noise ────────────────────────────────────────────
    if (config.audio && config.audio.noise_seed) {
      var audioRng = mulberry32(config.audio.noise_seed);
      if (AudioContext.prototype.createAnalyser) {
        var _origCA = AudioContext.prototype.createAnalyser;
        AudioContext.prototype.createAnalyser = cloak(function() {
          var analyser = _origCA.call(this);
          var origGetFloat = analyser.getFloatFrequencyData.bind(analyser);
          analyser.getFloatFrequencyData = cloak(function(array) {
            origGetFloat(array);
            for (var i = 0; i < array.length; i++) array[i] += audioRng() * 0.0001;
          }, 'getFloatFrequencyData');
          var origGetByte = analyser.getByteFrequencyData.bind(analyser);
          analyser.getByteFrequencyData = cloak(function(array) {
            origGetByte(array);
            for (var i = 0; i < array.length; i++) array[i] = Math.max(0, Math.min(255, array[i] + Math.floor((audioRng() - 0.5) * 2)));
          }, 'getByteFrequencyData');
          return analyser;
        }, 'createAnalyser');
      }
      // Noise on OfflineAudioContext destination
      if (typeof OfflineAudioContext !== 'undefined') {
        var origStartRendering = OfflineAudioContext.prototype.startRendering;
        OfflineAudioContext.prototype.startRendering = cloak(function() {
          return origStartRendering.call(this).then(function(buffer) {
            for (var ch = 0; ch < buffer.numberOfChannels; ch++) {
              var d = buffer.getChannelData(ch);
              for (var i = 0; i < d.length; i++) d[i] += audioRng() * 0.0001;
            }
            return buffer;
          });
        }, 'startRendering');
      }
    }

    // ── Navigator properties (stealth) ─────────────────────────────────
    if (config.navigator) {
      var np = config.navigator;
      if (np.hardware_concurrency !== undefined) stealthGetter(navigator, 'hardwareConcurrency', function() { return np.hardware_concurrency; });
      if (np.device_memory !== undefined) stealthGetter(navigator, 'deviceMemory', function() { return np.device_memory; });
      if (np.platform !== undefined) stealthGetter(navigator, 'platform', function() { return np.platform; });
      if (np.language !== undefined) stealthGetter(navigator, 'language', function() { return np.language; });
      if (np.languages !== undefined) stealthGetter(navigator, 'languages', function() { return Object.freeze(np.languages.slice()); });
      if (np.max_touch_points !== undefined) stealthGetter(navigator, 'maxTouchPoints', function() { return np.max_touch_points; });
      if (np.user_agent !== undefined) stealthGetter(navigator, 'userAgent', function() { return np.user_agent; });
      if (np.app_version !== undefined) stealthGetter(navigator, 'appVersion', function() { return np.app_version; });
      if (np.vendor !== undefined) stealthGetter(navigator, 'vendor', function() { return np.vendor; });
    }

    // ── Screen override (stealth) ──────────────────────────────────────
    if (config.screen) {
      var scr = config.screen;
      if (scr.width !== undefined) {
        stealthGetter(screen, 'width', function() { return scr.width; });
        stealthGetter(screen, 'availWidth', function() { return scr.width; });
      }
      if (scr.height !== undefined) {
        stealthGetter(screen, 'height', function() { return scr.height; });
        stealthGetter(screen, 'availHeight', function() { return scr.height - 40; });
      }
      if (scr.color_depth !== undefined) {
        stealthGetter(screen, 'colorDepth', function() { return scr.color_depth; });
        stealthGetter(screen, 'pixelDepth', function() { return scr.color_depth; });
      }
    }

    // ── Timezone override (full) ───────────────────────────────────────
    if (config.timezone && config.timezone.name) {
      var tz = config.timezone;
      // Timezone offset map (name -> offset in minutes, negative = ahead of UTC)
      var tzOffsets = {
        'America/New_York': 300, 'America/Chicago': 360, 'America/Denver': 420,
        'America/Los_Angeles': 480, 'America/Anchorage': 540, 'Pacific/Honolulu': 600,
        'America/Phoenix': 420, 'America/Toronto': 300, 'America/Vancouver': 480,
        'America/Sao_Paulo': 180, 'America/Argentina/Buenos_Aires': 180, 'America/Mexico_City': 360,
        'Europe/London': 0, 'Europe/Paris': -60, 'Europe/Berlin': -60, 'Europe/Madrid': -60,
        'Europe/Rome': -60, 'Europe/Amsterdam': -60, 'Europe/Brussels': -60,
        'Europe/Moscow': -180, 'Europe/Istanbul': -180, 'Europe/Athens': -120,
        'Europe/Bucharest': -120, 'Europe/Warsaw': -60, 'Europe/Zurich': -60,
        'Asia/Tokyo': -540, 'Asia/Shanghai': -480, 'Asia/Hong_Kong': -480,
        'Asia/Singapore': -480, 'Asia/Seoul': -540, 'Asia/Kolkata': -330,
        'Asia/Dubai': -240, 'Asia/Bangkok': -420, 'Asia/Jakarta': -420,
        'Asia/Taipei': -480, 'Asia/Manila': -480,
        'Australia/Sydney': -660, 'Australia/Melbourne': -660, 'Australia/Perth': -480,
        'Pacific/Auckland': -780, 'Africa/Cairo': -120, 'Africa/Lagos': -60,
        'Africa/Johannesburg': -120, 'UTC': 0, 'GMT': 0,
      };
      var targetOffset = tzOffsets[tz.name];
      if (targetOffset === undefined) targetOffset = 0;

      // Override Date.prototype.getTimezoneOffset
      var origGTZO = Date.prototype.getTimezoneOffset;
      Date.prototype.getTimezoneOffset = cloak(function() { return targetOffset; }, 'getTimezoneOffset');

      // Override Intl.DateTimeFormat
      var origDTF = Intl.DateTimeFormat;
      var newDTF = cloak(function(loc, opts) {
        opts = Object.assign({}, opts || {});
        if (!opts.timeZone) opts.timeZone = tz.name;
        return new origDTF(loc, opts);
      }, 'DateTimeFormat');
      newDTF.prototype = origDTF.prototype;
      newDTF.supportedLocalesOf = origDTF.supportedLocalesOf;
      cloak(newDTF.supportedLocalesOf, 'supportedLocalesOf');
      Intl.DateTimeFormat = newDTF;

      var origResolvedOptions = origDTF.prototype.resolvedOptions;
      origDTF.prototype.resolvedOptions = cloak(function() {
        var r = origResolvedOptions.call(this);
        r.timeZone = tz.name;
        return r;
      }, 'resolvedOptions');

      // Override Date.prototype.toString and toTimeString to reflect correct timezone
      var origDateToString = Date.prototype.toString;
      Date.prototype.toString = cloak(function() {
        try {
          var fmt = new origDTF('en-US', { timeZone: tz.name, weekday:'short', year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false, timeZoneName:'long' });
          var parts = fmt.formatToParts(this);
          var get = function(t) { for (var i=0;i<parts.length;i++) if(parts[i].type===t) return parts[i].value; return ''; };
          var sign = targetOffset <= 0 ? '+' : '-';
          var absOff = Math.abs(targetOffset);
          var offH = String(Math.floor(absOff/60)).padStart(2,'0');
          var offM = String(absOff%60).padStart(2,'0');
          return get('weekday') + ' ' + get('month') + ' ' + get('day') + ' ' + get('year') + ' ' + get('hour') + ':' + get('minute') + ':' + get('second') + ' GMT' + sign + offH + offM + ' (' + get('timeZoneName') + ')';
        } catch(e) { return origDateToString.call(this); }
      }, 'toString');
    }

    // ── WebRTC IP leak protection ──────────────────────────────────────
    if (config.webrtc !== false) {
      var origRTCPC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
      if (origRTCPC) {
        var patchedRTC = cloak(function(cfg, constraints) {
          cfg = cfg || {};
          cfg.iceServers = [];
          var pc = new origRTCPC(cfg, constraints);
          var origCreateOffer = pc.createOffer.bind(pc);
          pc.createOffer = cloak(function(opts) {
            return origCreateOffer(opts).then(function(offer) {
              offer.sdp = offer.sdp.replace(/a=candidate:.+typ srflx.+\r\n/g, '');
              offer.sdp = offer.sdp.replace(/a=candidate:.+typ relay.+\r\n/g, '');
              return offer;
            });
          }, 'createOffer');
          return pc;
        }, 'RTCPeerConnection');
        window.RTCPeerConnection = patchedRTC;
        if (window.webkitRTCPeerConnection) window.webkitRTCPeerConnection = patchedRTC;
      }
    }

    // ── Plugin masking ─────────────────────────────────────────────────
    try {
      stealthGetter(navigator, 'plugins', function() {
        return { length: 5,
          0: { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
          1: { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
          2: { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' },
          3: { name: 'Chromium PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
          4: { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: '' },
          item: function(i) { return this[i] || null; },
          namedItem: function(n) { for (var i=0;i<this.length;i++) if(this[i].name===n) return this[i]; return null; },
          refresh: function() {}
        };
      }, 'get plugins');
    } catch(e) {}

    // ── Hide automation flags ──────────────────────────────────────────
    try {
      stealthGetter(navigator, 'webdriver', function() { return false; }, 'get webdriver');
    } catch(e) {}
    try { delete navigator.__proto__.webdriver; } catch(e) {}

    // Hide chrome.runtime from non-extension pages (detection vector)
    try {
      if (window.chrome && window.chrome.runtime && !window.chrome.runtime.id) {
        delete window.chrome.runtime;
        window.chrome.runtime = undefined;
      }
    } catch(e) {}

    // ── Permissions API spoof ──────────────────────────────────────────
    try {
      var origQuery = navigator.permissions.query;
      navigator.permissions.query = cloak(function(desc) {
        if (desc && desc.name === 'notifications') {
          return Promise.resolve({ state: Notification.permission });
        }
        return origQuery.call(this, desc);
      }, 'query');
    } catch(e) {}

    console.log('[FP Guard] v2 active');
  } catch(err) {
    console.error('[FP Guard] Init error:', err);
  }
})();`

	if err := os.WriteFile(filepath.Join(extDir, "manifest.json"), []byte(manifest), 0644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(extDir, "inject.js"), []byte(inject), 0644); err != nil {
		return "", err
	}
	return extDir, nil
}

func writeFPConfig(extDir string, fingerprint json.RawMessage) error {
	// Parse the raw fingerprint JSON to extract individual fields
	var fpData map[string]interface{}
	if err := json.Unmarshal(fingerprint, &fpData); err != nil {
		// If fingerprint is empty or invalid, write an empty config
		return os.WriteFile(filepath.Join(extDir, "config.json"), []byte("{}"), 0644)
	}

	cfg := make(map[string]interface{})
	for _, key := range []string{"canvas", "webgl", "audio", "navigator", "screen", "timezone"} {
		if val, ok := fpData[key]; ok {
			cfg[key] = val
		}
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(extDir, "config.json"), data, 0644)
}

// ---------------------------------------------------------------------------
// Proxy auth extension (MV2 — webRequest.onAuthRequired needs MV2)
// ---------------------------------------------------------------------------

func addProxyAuthToFPExtension(fpDir, user, pass string) {
	manifest := `{
  "manifest_version": 3,
  "name": "Fingerprint Guard",
  "version": "1.0",
  "description": "Browser fingerprint management",
  "permissions": ["storage", "webRequest", "webRequestAuthProvider"],
  "host_permissions": ["<all_urls>"],
  "background": {
    "service_worker": "bg.js"
  },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["inject.js"],
    "run_at": "document_start",
    "world": "MAIN"
  }]
}`
	os.WriteFile(filepath.Join(fpDir, "manifest.json"), []byte(manifest), 0644)

	bg := fmt.Sprintf(`
chrome.webRequest.onAuthRequired.addListener(
  function(details, asyncCallback) {
    asyncCallback({
      authCredentials: { username: %q, password: %q }
    });
  },
  { urls: ["<all_urls>"] },
  ["asyncBlocking"]
);
`, user, pass)
	os.WriteFile(filepath.Join(fpDir, "bg.js"), []byte(bg), 0644)
	log.Printf("Added proxy auth to FP extension for user %s", user)
}

func ensureProxyAuthExtension(profileID, proxyStr string) (string, error) {
	parts := strings.SplitN(proxyStr, ":", 4)
	if len(parts) < 4 {
		return "", nil
	}
	user := parts[2]
	pass := parts[3]

	extDir := filepath.Join(dataDir, "proxy-auth", profileID)
	os.MkdirAll(extDir, 0755)

	manifest := `{
  "manifest_version": 2,
  "name": "Proxy Auth Helper",
  "version": "2.0",
  "permissions": ["webRequest", "webRequestBlocking", "<all_urls>"],
  "background": {
    "scripts": ["background.js"],
    "persistent": true
  }
}`

	bg := fmt.Sprintf(`
chrome.webRequest.onAuthRequired.addListener(
  function(details) {
    return {
      authCredentials: {
        username: %q,
        password: %q
      }
    };
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);
`, user, pass)

	if err := os.WriteFile(filepath.Join(extDir, "manifest.json"), []byte(manifest), 0644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(extDir, "background.js"), []byte(bg), 0644); err != nil {
		return "", err
	}
	return extDir, nil
}

// ---------------------------------------------------------------------------
// Marketplace extensions (purchased/installed via API)
// ---------------------------------------------------------------------------

type MarketplaceExt struct {
	Name string
	Path string
}

func loadMarketplaceExtensions() []MarketplaceExt {
	keyBytes, err := os.ReadFile(licenseFilePath())
	if err != nil {
		return nil
	}
	licKey := strings.TrimSpace(string(keyBytes))
	if licKey == "" {
		return nil
	}

	url := licenseAPIBase + "/api/extensions/purchased?license_key=" + licKey
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Failed to check purchased extensions: %v", err)
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Purchased []string `json:"purchased"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("Failed to parse purchased extensions: %v", err)
		return nil
	}

	if len(result.Purchased) == 0 {
		return nil
	}

	builtinDir := findBuiltinExtDir()
	if builtinDir == "" {
		log.Printf("Could not find builtin-extensions directory")
		return nil
	}

	userExtDir := extensionsDir()
	var exts []MarketplaceExt
	for _, extID := range result.Purchased {
		// Skip if already installed in user extensions dir (avoid duplicate loading)
		if _, err := os.Stat(filepath.Join(userExtDir, extID, "manifest.json")); err == nil {
			log.Printf("Marketplace ext %s already in user extensions, skipping builtin", extID)
			continue
		}
		extPath := filepath.Join(builtinDir, extID)
		if _, err := os.Stat(filepath.Join(extPath, "manifest.json")); err != nil {
			log.Printf("Marketplace ext %s not found at %s", extID, extPath)
			continue
		}
		name := extID
		data, _ := os.ReadFile(filepath.Join(extPath, "manifest.json"))
		var m map[string]interface{}
		if json.Unmarshal(data, &m) == nil {
			if n, ok := m["name"].(string); ok {
				name = n
			}
		}
		exts = append(exts, MarketplaceExt{Name: name, Path: extPath})
	}

	log.Printf("Loaded %d marketplace extensions for license %s...", len(exts), licKey[:min(12, len(licKey))])
	return exts
}

func findBuiltinExtDir() string {
	candidates := []string{
		filepath.Join(dataDir, "builtin-extensions"),
		filepath.Join(filepath.Dir(os.Args[0]), "builtin-extensions"),
	}
	if runtime.GOOS == "windows" {
		resDir := filepath.Join(filepath.Dir(os.Args[0]), "..", "resources")
		candidates = append(candidates, filepath.Join(resDir, "builtin-extensions"))
	} else {
		resDir := filepath.Join(filepath.Dir(os.Args[0]), "..", "Resources")
		candidates = append(candidates, filepath.Join(resDir, "builtin-extensions"))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Marketplace install/uninstall handlers
// ---------------------------------------------------------------------------

func handleMarketplaceInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}
	var req struct {
		ExtID       string `json:"ext_id"`
		DownloadURL string `json:"download_url"`
		FolderName  string `json:"folder_name"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.ExtID == "" || req.DownloadURL == "" {
		jsonError(w, "ext_id and download_url required", 400)
		return
	}
	folderName := req.FolderName
	if folderName == "" {
		folderName = req.ExtID
	}

	downloadURL := "https://personax.work" + req.DownloadURL
	log.Printf("Downloading extension %s from %s", req.ExtID, downloadURL)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(downloadURL)
	if err != nil {
		jsonError(w, fmt.Sprintf("Download failed: %v", err), 500)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		jsonError(w, fmt.Sprintf("Download failed: HTTP %d", resp.StatusCode), 500)
		return
	}

	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		jsonError(w, fmt.Sprintf("Read failed: %v", err), 500)
		return
	}

	extDir := filepath.Join(extensionsDir(), folderName)
	os.RemoveAll(extDir)
	os.MkdirAll(extDir, 0755)

	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		jsonError(w, fmt.Sprintf("Invalid zip: %v", err), 500)
		return
	}

	for _, f := range zipReader.File {
		fpath := filepath.Join(extDir, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(fpath), 0755)
		outFile, err := os.Create(fpath)
		if err != nil {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
	}

	log.Printf("Extension %s installed to %s", req.ExtID, extDir)
	jsonOK(w, map[string]interface{}{"status": "ok", "path": extDir})
}

func handleMarketplaceUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}
	var req struct {
		ExtID      string `json:"ext_id"`
		FolderName string `json:"folder_name"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.ExtID == "" {
		jsonError(w, "ext_id required", 400)
		return
	}
	folderName := req.FolderName
	if folderName == "" {
		folderName = req.ExtID
	}

	extDir := filepath.Join(extensionsDir(), folderName)
	if _, err := os.Stat(extDir); os.IsNotExist(err) {
		jsonOK(w, map[string]interface{}{"status": "ok", "message": "already removed"})
		return
	}

	os.RemoveAll(extDir)
	log.Printf("Extension %s uninstalled from %s", req.ExtID, extDir)
	jsonOK(w, map[string]interface{}{"status": "ok"})
}

// ---------------------------------------------------------------------------
// User extensions management
// ---------------------------------------------------------------------------

func extensionsDir() string {
	return filepath.Join(dataDir, "extensions")
}

type UserExtension struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Version string `json:"version"`
	Enabled bool   `json:"enabled"`
}

func findManifestInDir(dir string) string {
	manifest := filepath.Join(dir, "manifest.json")
	if _, err := os.Stat(manifest); err == nil {
		return dir
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sub := filepath.Join(dir, entry.Name())
		manifest = filepath.Join(sub, "manifest.json")
		if _, err := os.Stat(manifest); err == nil {
			return sub
		}
	}
	return ""
}

func listUserExtensions() []UserExtension {
	extDir := extensionsDir()
	os.MkdirAll(extDir, 0755)

	entries, err := os.ReadDir(extDir)
	if err != nil {
		log.Printf("Cannot read extensions dir %s: %v", extDir, err)
		return nil
	}

	log.Printf("Scanning extensions dir: %s (%d entries)", extDir, len(entries))

	var exts []UserExtension
	for _, entry := range entries {
		if !entry.IsDir() {
			log.Printf("  Skipping non-dir: %s", entry.Name())
			continue
		}
		extPath := filepath.Join(extDir, entry.Name())
		resolved := findManifestInDir(extPath)
		if resolved == "" {
			log.Printf("  No manifest.json found in %s (or one level deeper)", entry.Name())
			continue
		}
		manifestPath := filepath.Join(resolved, "manifest.json")
		name := entry.Name()
		version := ""
		data, err := os.ReadFile(manifestPath)
		if err == nil {
			var m map[string]interface{}
			if json.Unmarshal(data, &m) == nil {
				if n, ok := m["name"].(string); ok && n != "" {
					name = n
				}
				if v, ok := m["version"].(string); ok {
					version = v
				}
			}
		}
		log.Printf("  Found extension: %s v%s at %s", name, version, resolved)
		exts = append(exts, UserExtension{
			Name:    name,
			Path:    resolved,
			Version: version,
			Enabled: true,
		})
	}
	log.Printf("Total user extensions found: %d", len(exts))
	return exts
}

// ---------------------------------------------------------------------------
// Profile launching
// ---------------------------------------------------------------------------

type LaunchResult struct {
	ExtensionsLoaded []string `json:"extensions_loaded"`
}

type PrepareLaunchResult struct {
	ChromePath       string   `json:"chrome_path"`
	Args             []string `json:"args"`
	ExtensionsLoaded []string `json:"extensions_loaded"`
	ProfileID        string   `json:"profile_id"`
}

func downloadProfileSync(profileID, profileDir string) {
	srvURL := serverURL
	if srvURL == "" {
		return
	}
	fastClient := &http.Client{Timeout: 3 * time.Second}
	resp, err := fastClient.Get(srvURL + "/api/profiles/" + profileID + "/sync")
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	tmpFile := filepath.Join(profileDir, "_sync_download.zip")
	f, err := os.Create(tmpFile)
	if err != nil {
		return
	}
	io.Copy(f, resp.Body)
	f.Close()

	_ = extractZip(tmpFile, filepath.Join(profileDir, "Default"))
	os.Remove(tmpFile)
	log.Printf("Downloaded sync data for profile %s", profileID)
}

func uploadProfileSync(profileID, profileDir string) {
	srvURL := serverURL
	if srvURL == "" {
		return
	}
	defaultDir := filepath.Join(profileDir, "Default")
	if _, err := os.Stat(defaultDir); os.IsNotExist(err) {
		return
	}

	syncFiles := []string{
		"Cookies", "Cookies-journal",
		"Login Data", "Login Data-journal",
		"Web Data", "Web Data-journal",
		"Preferences", "Secure Preferences",
	}
	syncDirs := []string{"Local Storage", "Session Storage", "IndexedDB"}

	tmpFile := filepath.Join(profileDir, "_sync_upload.zip")
	zf, err := os.Create(tmpFile)
	if err != nil {
		return
	}
	zw := zip.NewWriter(zf)

	for _, name := range syncFiles {
		fp := filepath.Join(defaultDir, name)
		if data, err := os.ReadFile(fp); err == nil {
			w, _ := zw.Create(name)
			w.Write(data)
		}
	}
	for _, dir := range syncDirs {
		dirPath := filepath.Join(defaultDir, dir)
		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(defaultDir, path)
			w, _ := zw.Create(filepath.ToSlash(rel))
			data, _ := os.ReadFile(path)
			w.Write(data)
			return nil
		})
	}
	zw.Close()
	zf.Close()

	f, _ := os.Open(tmpFile)
	defer f.Close()
	defer os.Remove(tmpFile)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", profileID+".zip")
	io.Copy(part, f)
	writer.Close()

	req, _ := http.NewRequest("POST", srvURL+"/api/profiles/"+profileID+"/sync", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := httpClient.Do(req)
	if err == nil {
		resp.Body.Close()
		log.Printf("Uploaded sync data for profile %s", profileID)
	}
}

// extractZip already defined above

func findBuiltinDistribte() string {
	userCopy := filepath.Join(dataDir, "builtin-extensions", "distribte")

	sources := []string{
		filepath.Join(filepath.Dir(os.Args[0]), "builtin-extensions", "distribte"),
	}
	if resDir := os.Getenv("PERSONAX_RESOURCES"); resDir != "" {
		sources = append(sources, filepath.Join(resDir, "builtin-extensions", "distribte"))
	}
	if installDir := os.Getenv("PROGRAMFILES"); installDir != "" {
		sources = append(sources, filepath.Join(installDir, "PERSONAX", "builtin-extensions", "distribte"))
	}
	if installDir := os.Getenv("PROGRAMFILES(X86)"); installDir != "" {
		sources = append(sources, filepath.Join(installDir, "PERSONAX", "builtin-extensions", "distribte"))
	}

	for _, src := range sources {
		if _, err := os.Stat(filepath.Join(src, "manifest.json")); err == nil {
			os.MkdirAll(filepath.Dir(userCopy), 0755)
			copyDir(src, userCopy)
			log.Printf("Copied built-in Distribte from %s to %s", src, userCopy)
			return userCopy
		}
	}
	return ""
}

func copyDir(src, dst string) {
	filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			os.MkdirAll(target, 0755)
		} else {
			os.MkdirAll(filepath.Dir(target), 0755)
			data, err := os.ReadFile(path)
			if err == nil {
				os.WriteFile(target, data, 0644)
			}
		}
		return nil
	})
}

func updateDistribteConfig(extensionPaths []string) {
	srvURL := serverURL
	if srvURL == "" {
		return
	}
	fastClient := &http.Client{Timeout: 3 * time.Second}
	resp, err := fastClient.Get(srvURL + "/api/distribte/config")
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	var cfg struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil || cfg.Email == "" {
		return
	}

	jsContent := fmt.Sprintf(`const AUTOLOGIN_CONFIG = {
  email: %q,
  password: %q,
  enabled: %v
};
`, cfg.Email, cfg.Password, cfg.Enabled)

	for _, extPath := range extensionPaths {
		configPath := filepath.Join(extPath, "js", "autologin-config.js")
		if _, err := os.Stat(filepath.Join(extPath, "js")); err == nil {
			manifestPath := filepath.Join(extPath, "manifest.json")
			if data, err := os.ReadFile(manifestPath); err == nil {
				manifest := string(data)
				if strings.Contains(strings.ToLower(manifest), "distribte") {
					os.WriteFile(configPath, []byte(jsContent), 0644)
					log.Printf("Updated Distribte config in %s", extPath)

					if !strings.Contains(manifest, "personax.work") {
						manifest = strings.Replace(manifest,
							`"https://*.multiloginapp.com/*"`,
							`"https://*.multiloginapp.com/*",`+"\n"+`            "https://personax.work/*"`,
							1)
						os.WriteFile(manifestPath, []byte(manifest), 0644)
						log.Printf("Patched Distribte manifest to include personax.work")
					}
				}
			}
		}
	}
}

func prepareLaunch(profileID string) (*PrepareLaunchResult, error) {
	mu.Lock()
	if _, ok := processes[profileID]; ok {
		mu.Unlock()
		return nil, fmt.Errorf("profile %s is already running", profileID)
	}
	if !chromiumReady {
		mu.Unlock()
		return nil, fmt.Errorf("chromium is not downloaded yet")
	}
	srvURL := serverURL
	mu.Unlock()

	if srvURL == "" {
		return nil, fmt.Errorf("not connected to server")
	}

	profileURL := srvURL + "/api/profiles/" + profileID
	log.Printf("Fetching profile from %s", profileURL)

	resp, err := httpClient.Get(profileURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch profile: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile response: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var envelope struct {
		Profile Profile `json:"profile"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("invalid profile JSON: %v", err)
	}
	profile := envelope.Profile
	if profile.ID == "" {
		if err := json.Unmarshal(body, &profile); err != nil {
			return nil, fmt.Errorf("could not parse profile: %v", err)
		}
	}

	profileDir := filepath.Join(dataDir, "profiles", profile.ID)
	os.MkdirAll(profileDir, 0755)

	downloadProfileSync(profile.ID, profileDir)

	fpDir, err := ensureFPExtension()
	if err != nil {
		return nil, fmt.Errorf("fp extension: %v", err)
	}
	if len(profile.Fingerprint) > 0 && string(profile.Fingerprint) != "null" {
		if err := writeFPConfig(fpDir, profile.Fingerprint); err != nil {
			return nil, fmt.Errorf("fp config: %v", err)
		}
	}

	// Clean up lock files from previous crashed sessions
	for _, lockFile := range []string{"SingletonLock", "SingletonCookie", "SingletonSocket"} {
		os.Remove(filepath.Join(profileDir, lockFile))
	}

	// Remove old MV2 proxy-auth extensions (unsupported in latest Chromium)
	os.RemoveAll(filepath.Join(dataDir, "proxy-auth", profile.ID))

	// Clean Chrome's cached extension state to prevent loading old extensions
	os.RemoveAll(filepath.Join(profileDir, "Default", "Extensions"))
	os.RemoveAll(filepath.Join(profileDir, "Default", "Extension State"))
	os.RemoveAll(filepath.Join(profileDir, "Default", "Local Extension Settings"))

	args := []string{
		"--user-data-dir=" + profileDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-sync",
		"--disable-translate",
		"--disable-infobars",
		"--disable-features=MediaRouter",
		"--disable-gpu-shader-disk-cache",
		"--disable-session-crashed-bubble",
		"--hide-crash-restore-bubble",
	}

	if profile.WindowWidth > 0 && profile.WindowHeight > 0 {
		args = append(args, fmt.Sprintf("--window-size=%d,%d", profile.WindowWidth, profile.WindowHeight))
	}

	if profile.UserAgent != "" {
		args = append(args, "--user-agent="+profile.UserAgent)
	}

	// If proxy has auth credentials, add proxy auth service worker to FP extension
	if profile.Proxy != "" {
		parts := strings.SplitN(profile.Proxy, ":", 4)
		if len(parts) >= 2 {
			args = append(args, fmt.Sprintf("--proxy-server=%s:%s", parts[0], parts[1]))
		}
		if len(parts) == 4 {
			addProxyAuthToFPExtension(fpDir, parts[2], parts[3])
		}
	}

	extensions := []string{fpDir}
	var loadedExtNames []string

	userExts := listUserExtensions()
	for _, ext := range userExts {
		if ext.Enabled {
			extensions = append(extensions, ext.Path)
			loadedExtNames = append(loadedExtNames, ext.Name)
			log.Printf("Loading user extension: %s (%s)", ext.Name, ext.Path)
		}
	}

	marketExts := loadMarketplaceExtensions()
	for _, mext := range marketExts {
		extensions = append(extensions, mext.Path)
		loadedExtNames = append(loadedExtNames, mext.Name)
		log.Printf("Loading marketplace extension: %s (%s)", mext.Name, mext.Path)
	}

	args = append(args, "--load-extension="+strings.Join(extensions, ","))

	// Write license key to each extension dir for validation
	licKeyBytes, _ := os.ReadFile(licenseFilePath())
	licKey := strings.TrimSpace(string(licKeyBytes))
	if licKey != "" {
		for _, extPath := range extensions {
			os.WriteFile(filepath.Join(extPath, ".px_license"), []byte(licKey), 0644)
		}
	}

	// Clean ALL session restore data to prevent duplicate tabs
	prefsDir := filepath.Join(profileDir, "Default")
	os.MkdirAll(prefsDir, 0755)
	os.Remove(filepath.Join(prefsDir, "Preferences"))
	os.Remove(filepath.Join(prefsDir, "Secure Preferences"))
	os.Remove(filepath.Join(prefsDir, "Current Session"))
	os.Remove(filepath.Join(prefsDir, "Current Tabs"))
	os.Remove(filepath.Join(prefsDir, "Last Session"))
	os.Remove(filepath.Join(prefsDir, "Last Tabs"))
	os.RemoveAll(filepath.Join(prefsDir, "Sessions"))
	// Write sentinel so Chrome doesn't show first-run experience
	os.WriteFile(filepath.Join(profileDir, "First Run"), []byte(""), 0644)

	startupURL := profile.StartupURL
	if startupURL == "" {
		startupURL = "https://personax.work"
	}

	args = append(args, startupURL)

	log.Printf("Prepared profile %s (%s) with %d user extensions: %s %v", profile.ID, profile.Name, len(loadedExtNames), chromiumPath, args)

	return &PrepareLaunchResult{
		ChromePath:       chromiumPath,
		Args:             args,
		ExtensionsLoaded: loadedExtNames,
		ProfileID:        profile.ID,
	}, nil
}

func launchProfile(profileID string) (*LaunchResult, error) {
	prepared, err := prepareLaunch(profileID)
	if err != nil {
		return nil, err
	}

	profileDir := filepath.Join(dataDir, "profiles", prepared.ProfileID)

	cmd := exec.Command(prepared.ChromePath, prepared.Args...)
	setProcAttrs(cmd)

	var cleanEnv []string
	for _, e := range os.Environ() {
		upper := strings.ToUpper(e)
		if strings.HasPrefix(upper, "ELECTRON") ||
			strings.HasPrefix(upper, "CHROME_") ||
			strings.HasPrefix(upper, "NODE_") ||
			strings.HasPrefix(upper, "ORIGINAL_XDG") ||
			strings.HasPrefix(upper, "PERSONAX_") {
			continue
		}
		cleanEnv = append(cleanEnv, e)
	}
	cmd.Env = append(cleanEnv,
		"GOOGLE_API_KEY=no",
		"GOOGLE_DEFAULT_CLIENT_ID=no",
		"GOOGLE_DEFAULT_CLIENT_SECRET=no",
	)

	chromeLogPath := filepath.Join(profileDir, "chrome-output.log")
	chromeLog, err := os.Create(chromeLogPath)
	if err == nil {
		cmd.Stdout = chromeLog
		cmd.Stderr = chromeLog
	}

	if err := cmd.Start(); err != nil {
		if chromeLog != nil {
			chromeLog.Close()
		}
		return nil, fmt.Errorf("start chrome: %v", err)
	}

	mu.Lock()
	processes[prepared.ProfileID] = cmd.Process
	mu.Unlock()

	pID := prepared.ProfileID
	pDir := profileDir
	go func() {
		err := cmd.Wait()
		if chromeLog != nil {
			chromeLog.Close()
		}
		if err != nil {
			log.Printf("Profile %s exited with error: %v", pID, err)
		}
		mu.Lock()
		delete(processes, pID)
		mu.Unlock()
		log.Printf("Profile %s closed, syncing data...", pID)
		uploadProfileSync(pID, pDir)
		log.Printf("Profile %s sync complete", pID)
	}()

	return &LaunchResult{ExtensionsLoaded: prepared.ExtensionsLoaded}, nil
}

func stopProfile(profileID string) error {
	mu.Lock()
	proc, ok := processes[profileID]
	mu.Unlock()
	if !ok {
		return fmt.Errorf("profile %s is not running", profileID)
	}

	// On Windows use taskkill /F /T /PID to kill the process tree
	if runtime.GOOS == "windows" {
		kill := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(proc.Pid))
		setProcAttrs(kill)
		kill.Stdout = os.Stdout
		kill.Stderr = os.Stderr
		if err := kill.Run(); err != nil {
			// Fallback: direct kill
			proc.Kill()
		}
	} else {
		proc.Kill()
	}

	mu.Lock()
	delete(processes, profileID)
	mu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// HTTP handlers — local endpoints
// ---------------------------------------------------------------------------

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := dashboardHTML
	settingsFile := filepath.Join(dataDir, "ui-settings.json")
	if data, err := os.ReadFile(settingsFile); err == nil {
		var s map[string]interface{}
		if json.Unmarshal(data, &s) == nil {
			if panel, ok := s["panel"].(string); ok && panel != "" && panel != "profiles" {
				inject := `<script>window.__savedPanel="` + panel + `";</script>`
				html = strings.Replace(html, "</head>", inject+"</head>", 1)
			}
		}
	}
	w.Write([]byte(html))
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}

	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", 400)
		return
	}

	server := strings.TrimRight(req.Server, "/")
	if server == "" {
		jsonError(w, "server field required", 400)
		return
	}

	statsURL := server + "/api/stats"
	log.Printf("Testing connection to %s", statsURL)

	resp, err := httpClient.Get(statsURL)
	if err != nil {
		jsonError(w, fmt.Sprintf("Failed to connect: %v", err), 502)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		jsonError(w, fmt.Sprintf("Failed to read response: %v", err), 502)
		return
	}

	if resp.StatusCode != 200 {
		jsonError(w, fmt.Sprintf("Server returned %d: %s", resp.StatusCode, string(body)), resp.StatusCode)
		return
	}

	var stats interface{}
	json.Unmarshal(body, &stats)

	mu.Lock()
	serverURL = server
	mu.Unlock()

	log.Printf("Connected to server: %s", server)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":    true,
		"stats": stats,
	})
}

func handleLaunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}

	var req LaunchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", 400)
		return
	}

	if req.ProfileID == "" {
		jsonError(w, "profile_id required", 400)
		return
	}

	result, err := launchProfile(req.ProfileID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	reportActivity("profile_launched", "Profile "+req.ProfileID+" launched")

	extNames := []string{}
	if result != nil && result.ExtensionsLoaded != nil {
		extNames = result.ExtensionsLoaded
	}
	jsonOK(w, map[string]interface{}{
		"status":            "launched",
		"profile_id":        req.ProfileID,
		"extensions_loaded": extNames,
	})
}

func handlePrepareLaunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}

	var req LaunchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", 400)
		return
	}

	if req.ProfileID == "" {
		jsonError(w, "profile_id required", 400)
		return
	}

	result, err := prepareLaunch(req.ProfileID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	jsonOK(w, map[string]interface{}{
		"chrome_path":       result.ChromePath,
		"args":              result.Args,
		"extensions_loaded": result.ExtensionsLoaded,
		"profile_id":        result.ProfileID,
	})
}

func handleElectronNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}

	var req struct {
		ProfileID string `json:"profile_id"`
		PID       int    `json:"pid"`
		Action    string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", 400)
		return
	}

	if req.Action == "launched" && req.PID > 0 {
		p, _ := os.FindProcess(req.PID)
		if p != nil {
			mu.Lock()
			processes[req.ProfileID] = p
			mu.Unlock()
			log.Printf("Electron launched profile %s with PID %d", req.ProfileID, req.PID)
			reportActivity("profile_launched", "Profile "+req.ProfileID+" launched (PID "+strconv.Itoa(req.PID)+")")
		}
	} else if req.Action == "stopped" {
		mu.Lock()
		delete(processes, req.ProfileID)
		mu.Unlock()
		reportActivity("profile_stopped", "Profile "+req.ProfileID+" stopped")
		profileDir := filepath.Join(dataDir, "profiles", req.ProfileID)
		go uploadProfileSync(req.ProfileID, profileDir)
	}

	jsonOK(w, map[string]string{"status": "ok"})
}

func handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}

	var req StopRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request body", 400)
		return
	}

	if err := stopProfile(req.ProfileID); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	reportActivity("profile_stopped", "Profile "+req.ProfileID+" stopped")
	jsonOK(w, map[string]string{"status": "stopped", "profile_id": req.ProfileID})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	running := make([]RunningProfile, 0, len(processes))
	for id, proc := range processes {
		running = append(running, RunningProfile{ProfileID: id, PID: proc.Pid})
	}
	status := StatusResponse{
		Running:          running,
		ChromiumReady:    chromiumReady,
		ChromiumPath:     chromiumPath,
		Downloading:      downloading,
		DownloadProgress: downloadProgress,
		DownloadError:    downloadError,
		ServerURL:        serverURL,
		ServerConnected:  serverURL != "",
	}
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func handleProxyList(w http.ResponseWriter, r *http.Request) {
	proxies := loadDecryptedProxies()
	if proxies == nil {
		proxies = []string{}
	}
	log.Printf("Loaded %d proxies (encrypted storage)", len(proxies))
	jsonOK(w, map[string]interface{}{"proxies": proxies})
}

func handleDownloadChromium(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}
	downloadChromium()
	jsonOK(w, map[string]string{"status": "download_started"})
}

func handleExtensions(w http.ResponseWriter, r *http.Request) {
	exts := listUserExtensions()
	if exts == nil {
		exts = []UserExtension{}
	}
	jsonOK(w, map[string]interface{}{
		"extensions":      exts,
		"extensions_path": extensionsDir(),
	})
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	settingsFile := filepath.Join(dataDir, "ui-settings.json")
	if r.Method == http.MethodGet {
		data, err := os.ReadFile(settingsFile)
		if err != nil {
			jsonOK(w, map[string]interface{}{})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		body, _ := io.ReadAll(r.Body)
		os.WriteFile(settingsFile, body, 0644)
		jsonOK(w, map[string]string{"status": "ok"})
		return
	}
	jsonError(w, "Method not allowed", 405)
}

func handleOpenExtensionsFolder(w http.ResponseWriter, r *http.Request) {
	dir := extensionsDir()
	os.MkdirAll(dir, 0755)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer", dir)
		setProcAttrs(cmd)
	case "darwin":
		cmd = exec.Command("open", dir)
	default:
		cmd = exec.Command("xdg-open", dir)
	}
	cmd.Start()
	jsonOK(w, map[string]string{"status": "opened", "path": dir})
}

// ---------------------------------------------------------------------------
// License validation
// ---------------------------------------------------------------------------

const licenseAPIBase = "https://personax.work"

const chingAPIBase = "https://personax.work"

func reportActivity(action, details string) {
	key := ""
	keyBytes, err := os.ReadFile(licenseFilePath())
	if err == nil {
		key = strings.TrimSpace(string(keyBytes))
	}
	if key == "" {
		return
	}
	machineID := getMachineID()
	payload, _ := json.Marshal(map[string]string{
		"license_key": key,
		"machine_id":  machineID,
		"action":      action,
		"details":     details,
	})
	go func() {
		resp, err := http.Post(chingAPIBase+"/api/activity", "application/json", bytes.NewReader(payload))
		if err != nil {
			log.Printf("Activity report failed: %v", err)
			return
		}
		resp.Body.Close()
	}()
}

func sendHeartbeat() {
	key := ""
	keyBytes, err := os.ReadFile(licenseFilePath())
	if err == nil {
		key = strings.TrimSpace(string(keyBytes))
	}
	if key == "" {
		return
	}
	machineID := getMachineID()
	mu.Lock()
	activeCount := len(processes)
	mu.Unlock()
	payload, _ := json.Marshal(map[string]interface{}{
		"license_key":     key,
		"machine_id":      machineID,
		"profiles_active": activeCount,
		"app_version":     "1.4.0",
	})
	resp, err := http.Post(chingAPIBase+"/api/heartbeat", "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("Heartbeat failed: %v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		OK              bool   `json:"ok"`
		ForceDisconnect bool   `json:"force_disconnect"`
		Reason          string `json:"reason"`
	}
	if json.Unmarshal(body, &result) == nil && result.ForceDisconnect {
		log.Printf("Force disconnect received: %s", result.Reason)
		mu.Lock()
		for pid, proc := range processes {
			log.Printf("Force-stopping profile %s", pid)
			if runtime.GOOS == "windows" {
				kill := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(proc.Pid))
				setProcAttrs(kill)
				kill.Run()
			} else {
				proc.Kill()
			}
		}
		processes = make(map[string]*os.Process)
		mu.Unlock()
		os.Remove(licenseFilePath())
		log.Printf("License revoked, all profiles stopped, license file removed")
	}
}

func startHeartbeatLoop() {
	sendHeartbeat()
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for range ticker.C {
			sendHeartbeat()
		}
	}()
}

func reportSessionClose() {
	key := ""
	keyBytes, err := os.ReadFile(licenseFilePath())
	if err == nil {
		key = strings.TrimSpace(string(keyBytes))
	}
	if key == "" {
		return
	}
	machineID := getMachineID()
	payload, _ := json.Marshal(map[string]string{
		"license_key": key,
		"machine_id":  machineID,
	})
	resp, err := http.Post(chingAPIBase+"/api/session/close", "application/json", bytes.NewReader(payload))
	if err != nil {
		return
	}
	resp.Body.Close()
}

func licenseFilePath() string {
	return filepath.Join(dataDir, ".license")
}

func handleLicenseActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST only", 405)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req map[string]string
	json.Unmarshal(body, &req)
	key := req["license_key"]
	if key == "" {
		jsonError(w, "license_key required", 400)
		return
	}

	machineID := getMachineID()
	payload, _ := json.Marshal(map[string]string{"license_key": key, "machine_id": machineID})
	resp, err := http.Post(licenseAPIBase+"/api/validate", "application/json", bytes.NewReader(payload))
	if err != nil {
		jsonError(w, "Cannot reach license server: "+err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	if valid, ok := result["valid"].(bool); ok && valid {
		os.WriteFile(licenseFilePath(), []byte(key), 0600)
		log.Printf("License activated: %s", key)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func handleLicenseStatus(w http.ResponseWriter, r *http.Request) {
	keyBytes, err := os.ReadFile(licenseFilePath())
	if err != nil || len(keyBytes) == 0 {
		jsonOK(w, map[string]interface{}{"activated": false})
		return
	}
	key := strings.TrimSpace(string(keyBytes))
	machineID := getMachineID()
	payload, _ := json.Marshal(map[string]string{"license_key": key, "machine_id": machineID})
	resp, err := http.Post(licenseAPIBase+"/api/validate", "application/json", bytes.NewReader(payload))
	if err != nil {
		jsonOK(w, map[string]interface{}{"activated": true, "license_key": key, "offline": true})
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	result["activated"] = true
	result["license_key"] = key

	w.Header().Set("Content-Type", "application/json")
	w.Write(mustJSON(result))
}

func handleLicenseDeactivate(w http.ResponseWriter, r *http.Request) {
	os.Remove(licenseFilePath())
	jsonOK(w, map[string]string{"status": "deactivated"})
}

func handleLicensePlans(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(licenseAPIBase + "/api/plans")
	if err != nil {
		jsonError(w, "Cannot reach license server", 502)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

var cachedMachineID string

func getMachineID() string {
	if cachedMachineID != "" {
		return cachedMachineID
	}
	if runtime.GOOS == "windows" {
		wmicCmd := exec.Command("wmic", "csproduct", "get", "UUID")
		setProcAttrs(wmicCmd)
		out, err := wmicCmd.Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && line != "UUID" {
					cachedMachineID = line
				return cachedMachineID
				}
			}
		}
	}
	hostname, _ := os.Hostname()
	return hostname
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func trackProxyActivity(method, path string, body []byte) {
	var action, details string
	if strings.Contains(path, "/profiles") {
		switch method {
		case http.MethodPost:
			action = "profile_created"
			var d map[string]interface{}
			if json.Unmarshal(body, &d) == nil {
				if name, ok := d["name"].(string); ok {
					details = "Created profile: " + name
				} else {
					details = "Created new profile"
				}
			}
		case http.MethodDelete:
			action = "profile_deleted"
			parts := strings.Split(path, "/")
			if len(parts) > 0 {
				details = "Deleted profile: " + parts[len(parts)-1]
			}
		case http.MethodPut, http.MethodPatch:
			action = "profile_moved"
			var d map[string]interface{}
			if json.Unmarshal(body, &d) == nil {
				if fid, ok := d["folder_id"].(string); ok && fid != "" {
					details = "Moved profile to folder"
				} else {
					details = "Updated profile"
				}
			}
		}
	} else if strings.Contains(path, "/folders") {
		switch method {
		case http.MethodPost:
			action = "folder_created"
			details = "Created new folder"
		case http.MethodDelete:
			action = "folder_deleted"
			details = "Deleted folder"
		}
	}
	if action != "" {
		reportActivity(action, details)
	}
}

// ---------------------------------------------------------------------------
// Proxy handler — forwards unmatched /api/* requests to remote server
// ---------------------------------------------------------------------------

func handleProxy(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	srvURL := serverURL
	mu.Unlock()

	if srvURL == "" {
		jsonError(w, "Not connected to server", 503)
		return
	}

	// Build the target URL: serverURL + original path + query string
	targetURL := srvURL + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	log.Printf("Proxy %s %s -> %s", r.Method, r.URL.Path, targetURL)

	// Track DELETE operations for activity logging
	if r.Method == http.MethodDelete {
		path := r.URL.Path
		if strings.Contains(path, "/profiles") || strings.Contains(path, "/folders") {
			go trackProxyActivity(r.Method, path, nil)
		}
	}

	// Read full body so we can set Content-Length properly
	var bodyBytes []byte
	var bodyReader io.Reader
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			jsonError(w, fmt.Sprintf("Failed to read body: %v", err), 500)
			return
		}
		bodyReader = bytes.NewReader(bodyBytes)

		path := r.URL.Path
		if strings.Contains(path, "/profiles") || strings.Contains(path, "/folders") {
			go trackProxyActivity(r.Method, path, bodyBytes)
		}
	}

	proxyReq, err := http.NewRequest(r.Method, targetURL, bodyReader)
	if err != nil {
		jsonError(w, fmt.Sprintf("Proxy request error: %v", err), 500)
		return
	}

	// Forward relevant headers
	if ct := r.Header.Get("Content-Type"); ct != "" {
		proxyReq.Header.Set("Content-Type", ct)
	}

	proxyClient := &http.Client{Timeout: 60 * time.Second}
	resp, err := proxyClient.Do(proxyReq)
	if err != nil {
		jsonError(w, fmt.Sprintf("Proxy error: %v", err), 502)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, vals := range resp.Header {
		for _, val := range vals {
			w.Header().Add(key, val)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// ---------------------------------------------------------------------------
// Open browser in app mode (no tabs, no address bar — looks like native app)
// ---------------------------------------------------------------------------

func findAppBrowser() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	if chromiumPath != "" {
		if _, err := os.Stat(chromiumPath); err == nil {
			return chromiumPath
		}
	}
	candidates := []string{
		filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("PROGRAMFILES(X86)"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "Application", "chrome.exe"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func openBrowser(url string) {
	if runtime.GOOS == "windows" {
		browser := findAppBrowser()
		if browser != "" {
			appDataDir := filepath.Join(dataDir, "app-window")
			os.MkdirAll(appDataDir, 0755)

			prefsDir := filepath.Join(appDataDir, "Default")
			os.MkdirAll(prefsDir, 0755)
			prefs := `{"browser":{"check_default_browser":false},"profile":{"name":"PERSONAX"}}`
			prefsPath := filepath.Join(prefsDir, "Preferences")
			if _, err := os.Stat(prefsPath); os.IsNotExist(err) {
				os.WriteFile(prefsPath, []byte(prefs), 0644)
			}

			cmd := exec.Command(browser,
				"--app="+url,
				"--user-data-dir="+appDataDir,
				"--window-size=1440,900",
				"--window-position=100,50",
				"--disable-extensions",
				"--disable-infobars",
				"--disable-features=TranslateUI,MediaRouter",
				"--disable-background-networking",
				"--disable-sync",
				"--disable-default-apps",
				"--no-default-browser-check",
				"--no-first-run",
				"--new-window",
			)
			cmd.Env = append(os.Environ(),
				"GOOGLE_API_KEY=no",
				"GOOGLE_DEFAULT_CLIENT_ID=no",
				"GOOGLE_DEFAULT_CLIENT_SECRET=no",
			)
			cmd.Start()

			go func() {
				cmd.Wait()
				log.Println("App window closed")
				os.Exit(0)
			}()
			return
		}
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
		setProcAttrs(cmd)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func setupFileLogging() {
	logPath := filepath.Join(dataDir, "personax.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	log.SetOutput(f)
}

func main() {
	serverMode := false
	for _, arg := range os.Args[1:] {
		if arg == "--server" {
			serverMode = true
		}
	}

	os.MkdirAll(dataDir, 0755)
	os.MkdirAll(extensionsDir(), 0755)
	setupFileLogging()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("PERSONAX starting...")
	log.Printf("Data directory: %s", dataDir)
	log.Printf("Server mode: %v", serverMode)

	checkChromium()
	startHeartbeatLoop()

	mux := http.NewServeMux()

	// Local handlers (registered first — specific paths take priority)
	// Encrypt proxy file on startup (hides PROXY.csv)
	ensureEncryptedProxy()

	mux.HandleFunc("/api/connect", withCORS(handleConnect))
	mux.HandleFunc("/api/launch", withCORS(handleLaunch))
	mux.HandleFunc("/api/prepare-launch", withCORS(handlePrepareLaunch))
	mux.HandleFunc("/api/electron-notify", withCORS(handleElectronNotify))
	mux.HandleFunc("/api/stop", withCORS(handleStop))
	mux.HandleFunc("/api/status", withCORS(handleStatus))
	mux.HandleFunc("/api/download-chromium", withCORS(handleDownloadChromium))
	mux.HandleFunc("/api/proxy-list", withCORS(handleProxyList))
	mux.HandleFunc("/api/extensions", withCORS(handleExtensions))
	mux.HandleFunc("/api/open-extensions", withCORS(handleOpenExtensionsFolder))
	mux.HandleFunc("/ui-settings", withCORS(handleSettings))
	mux.HandleFunc("/api/marketplace/install", withCORS(handleMarketplaceInstall))
	mux.HandleFunc("/api/marketplace/uninstall", withCORS(handleMarketplaceUninstall))
	mux.HandleFunc("/api/license/activate", withCORS(handleLicenseActivate))
	mux.HandleFunc("/api/license/status", withCORS(handleLicenseStatus))
	mux.HandleFunc("/api/license/deactivate", withCORS(handleLicenseDeactivate))
	mux.HandleFunc("/api/license/plans", withCORS(handleLicensePlans))
	mux.HandleFunc("/api/quit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
		go func() {
			reportSessionClose()
			time.Sleep(500 * time.Millisecond)
			log.Println("App window closed, shutting down...")
			os.Exit(0)
		}()
	})
	mux.HandleFunc("/", handleIndex)

	// Catch-all proxy for /api/* (anything not matched above)
	mux.HandleFunc("/api/", withCORS(handleProxy))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to bind: %v", err)
	}
	addr := listener.Addr().String()
	url := "http://" + addr
	log.Printf("GUI available at %s", url)

	if serverMode {
		_, portStr, _ := net.SplitHostPort(addr)
		portFile := filepath.Join(dataDir, ".port")
		os.WriteFile(portFile, []byte(portStr), 0644)
		fmt.Fprintf(os.Stdout, "PORT:%s\n", portStr)
		log.Printf("Server mode: port %s written to %s", portStr, portFile)
	} else {
		go func() {
			time.Sleep(500 * time.Millisecond)
			openBrowser(url)
		}()
	}

	server := &http.Server{Handler: mux}
	if err := server.Serve(listener); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
