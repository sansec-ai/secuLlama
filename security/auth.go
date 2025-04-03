package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

/*
apikey文件存储：~/.ollama/api_keys
格式：[密文]$[明文]
说明：1.没有$分隔符，表示是明文

	2.可以只保留密文，但需要保留$
*/
const (
	keyLength = 32 // 256-bit key(include 'ss-' prefix)
	keyFile   = "api_keys"
)

var (
	keyStore map[string]bool
	mu       sync.RWMutex
)

const KeySeparator = "$"

func initKeyStore(crypto Crypto) {
	loadKeys(crypto)

	// Ensure there is at least one valid key
	if len(keyStore) == 0 {
		panic("API key initialization failed : no valid API keys found")
	}
}

func APIKeyAuth(crypto Crypto) gin.HandlerFunc {
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
		{
			mu.RLock()
			defer mu.RUnlock()
			for key := range keyStore {
				if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(key)) == 1 {
					isValid = true
					break
				}
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

func loadKeys(crypto Crypto) {
	keyStore = make(map[string]bool)

	// Get key file path
	home, _ := os.UserHomeDir()
	keyPath := filepath.Join(home, ".ollama", keyFile)

	// Create directory if key file does not exist
	if _, err := os.Stat(filepath.Dir(keyPath)); os.IsNotExist(err) {
		os.MkdirAll(filepath.Dir(keyPath), 0700)
	}

	var migratedKeys []string
	// Read existing keys
	data, _ := os.ReadFile(keyPath)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 分割密文和明文
		parts := strings.SplitN(line, KeySeparator, 2)
		var encryptedKey string
		var plainKey string

		if len(parts) == 1 {
			// 没有":"分隔符,则key就是明文，需要加密
			plainKey = parts[0]
			// 去掉ss-前缀后base64解码
			if !strings.HasPrefix(line, "ss-") {
				slog.Error("未加密的API密钥格式错误",
					"key", line[:4]+"****")
				continue
			}
			keyBin, err := base64.URLEncoding.DecodeString(plainKey[3:])
			if err != nil {
				slog.Error("base64解码失败", "error", err)
				continue
			}
			encrypted, err := crypto.Encrypt([]byte(keyBin))
			if err != nil {
				slog.Error("api key加密失败", "key", plainKey[:4]+"****", "error", err)
				continue
			}
			encryptedKey = base64.URLEncoding.EncodeToString(encrypted)
			migratedKeys = append(migratedKeys, fmt.Sprintf("%s%s%s", encryptedKey, KeySeparator, plainKey))
		} else {
			// 有分隔符，则第1个是密文
			encryptedKey = parts[0]
			if parts[1] != "" {
				plainKey = parts[1]
			} else {
				encryptedBin, err := base64.URLEncoding.DecodeString(encryptedKey)
				if err != nil {
					slog.Error("base64解码失败", "error", err)
					continue
				}
				plainKeyBytes, err := crypto.Decrypt(encryptedBin)
				if err != nil {
					slog.Error("api key解密失败", "error", err)
					continue
				}
				plainKey = "ss-" + base64.URLEncoding.EncodeToString(plainKeyBytes)
			}
		}

		keyStore[plainKey] = true
	}

	// 写回加密后的密钥
	if len(migratedKeys) > 0 {
		f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			panic("无法更新密钥文件: " + err.Error())
		}
		defer f.Close()

		for _, key := range migratedKeys {
			if _, err := f.WriteString(key + "\n"); err != nil {
				panic("写入密钥失败: " + err.Error())
			}
		}
	}

	// Automatic default key creation logic
	if len(keyStore) == 0 {
		defaultKey, err := GenerateAPIKey(crypto)
		if err != nil {
			panic("failed to generate default API key: " + err.Error())
		}

		// Output key to log
		slog.Info("Auto-generated default API Key",
			"key", defaultKey[:4]+"****",
			"notice", "This key should be rotated in production environments (only first 4 characters logged)")
	}
}

func GenerateAPIKey(crypto Crypto) (string, error) {
	// 生成明文密钥
	keyBytes := make([]byte, keyLength)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", err
	}

	// 加密存储
	encrypted, err := crypto.Encrypt([]byte(keyBytes))
	if err != nil {
		return "", fmt.Errorf("加密失败: %w", err)
	}
	encryptedKey := base64.URLEncoding.EncodeToString(encrypted)
	plainKey := "ss-" + base64.URLEncoding.EncodeToString(keyBytes)

	// 写入文件
	mu.Lock()
	defer mu.Unlock()

	path := filepath.Join(os.Getenv("HOME"), ".ollama", keyFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := f.WriteString(fmt.Sprintf("%s%s%s\n", encryptedKey, KeySeparator, plainKey)); err != nil {
		return "", err
	}

	keyStore[plainKey] = true
	return plainKey, nil
}
