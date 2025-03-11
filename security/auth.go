package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

const (
	keyLength = 32 // 256-bit key
	keyFile   = "api_keys"
)

var (
	keyStore map[string]bool
	mu       sync.RWMutex
)

func GetAPIKeys() map[string]bool {
	mu.RLock()
	defer mu.RUnlock()
	return keyStore
}

func APIKeyAuth(validKeys map[string]bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip preflight requests and health checks
		if c.Request.Method == "OPTIONS" || c.Request.URL.Path == "/" {
			c.Next()
			return
		}

		// Get API Key from Header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "missing Authorization header"})
			return
		}

		// Verify format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "invalid Authorization format"})
			return
		}

		// Add prefix verification after format check
		if !strings.HasPrefix(parts[1], "ss-") {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "invalid API key format"})
			return
		}

		// Securely compare API Key
		isValid := false
		for key := range validKeys {
			if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(key)) == 1 {
				isValid = true
				break
			}
		}

		if !isValid {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "invalid API key"})
			return
		}

		c.Next()

		// Add security log
		slog.Info("API Key access record",
			"path", c.Request.URL.Path,
			"clientIP", c.ClientIP(),
			"key", parts[1][:4]+"****") // Only log the first 4 characters
	}
}

func init() {
	loadKeys()

	// Ensure there is at least one valid key
	if len(keyStore) == 0 {
		panic("API key initialization failed : no valid API keys found")
	}
}

func loadKeys() {
	keyStore = make(map[string]bool)

	// Get key file path
	home, _ := os.UserHomeDir()
	keyPath := filepath.Join(home, ".ollama", keyFile)

	// Create directory if key file does not exist
	if _, err := os.Stat(filepath.Dir(keyPath)); os.IsNotExist(err) {
		os.MkdirAll(filepath.Dir(keyPath), 0700)
	}

	// Read existing keys
	data, _ := os.ReadFile(keyPath)
	for _, key := range strings.Split(string(data), "\n") {
		if len(key) > 0 {
			keyStore[key] = true
		}
	}

	// Automatic default key creation logic
	if len(keyStore) == 0 {
		mu.Lock()
		defer mu.Unlock()

		// Generate random key
		b := make([]byte, keyLength)
		if _, err := rand.Read(b); err != nil {
			panic("failed to generate default API key: " + err.Error())
		}
		defaultKey := "ss-" + base64.URLEncoding.EncodeToString(b)

		// Write to file
		f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			panic("failed to create API key file: " + err.Error())
		}
		defer f.Close()

		if _, err := f.WriteString(defaultKey + "\n"); err != nil {
			panic("failed to write default API key: " + err.Error())
		}

		// Output key to log
		slog.Info("Auto-generated default API Key",
			"key", defaultKey,
			"notice", "This key should be rotated in production environments")

		keyStore[defaultKey] = true
	}
}

func GenerateAPIKey() (string, error) {
	b := make([]byte, keyLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	key := "ss-" + base64.URLEncoding.EncodeToString(b)

	mu.Lock()
	defer mu.Unlock()

	// Write to file
	path := filepath.Join(os.Getenv("HOME"), ".ollama", keyFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := f.WriteString(key + "\n"); err != nil {
		return "", err
	}

	keyStore[key] = true
	return key, nil
}

func ValidateAPIKey(key string) bool {
	mu.RLock()
	defer mu.RUnlock()
	// API key format validation
	if !strings.HasPrefix(key, "ss-") {
		return false
	}
	return keyStore[key]
}