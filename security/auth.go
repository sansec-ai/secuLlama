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

const (
	KeySeparator        = "$"
	UserKeyPrefix       = "ss-"
	ManagementKeyPrefix = "sm-"
	MaxUserKeys         = 10
)

func initKeyStore(crypto Crypto) {
	loadKeys(crypto)

	// Ensure there is at least one valid key
	if len(keyStore) == 0 {
		panic("API key initialization failed : no valid API keys found")
	}
}

func ManagementAPIKeyAuth(crypto Crypto) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		parts := strings.SplitN(authHeader, " ", 2)

		// Require management key prefix
		if len(parts) != 2 || !strings.HasPrefix(parts[1], ManagementKeyPrefix) {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "management operation requires management API key"})
			return
		}

		// Reuse existing validation logic
		APIKeyAuth(crypto)(c)
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
		if !strings.HasPrefix(parts[1], UserKeyPrefix) && !strings.HasPrefix(parts[1], ManagementKeyPrefix) {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "invalid API key format"})
			return
		}

		// Securely compare API Key
		isValid := false
		{
			mu.RLock()
			for key := range keyStore {
				if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(key)) == 1 {
					isValid = true
					break
				}
			}
			mu.RUnlock()
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
			if !strings.HasPrefix(plainKey, UserKeyPrefix) && !strings.HasPrefix(plainKey, ManagementKeyPrefix) {
				slog.Error("invalid plaintext key format", "key", plainKey[:4]+"****")
				continue
			}
			// Determine key type from plaintext prefix
			isManagement := strings.HasPrefix(plainKey, ManagementKeyPrefix)
			keyTypePrefix := ManagementKeyPrefix
			if !isManagement {
				keyTypePrefix = UserKeyPrefix
			}

			keyBin, err := base64.URLEncoding.DecodeString(strings.TrimPrefix(plainKey, keyTypePrefix))
			if err != nil {
				slog.Error("base64 decode failed", "error", err)
				continue
			}
			// Encrypt and add prefix to encrypted version
			encrypted, err := crypto.Encrypt(keyBin)
			if err != nil {
				slog.Error("api key encryption failed", "error", err)
				continue
			}
			encryptedKey = fmt.Sprintf("%s%s", keyTypePrefix, base64.URLEncoding.EncodeToString(encrypted))
			migratedKeys = append(migratedKeys, fmt.Sprintf("%s%s%s", encryptedKey, KeySeparator, plainKey))
		} else {
			// 有分隔符，则第1个是密文，需要通过密文解密后得到明文
			encryptedKey = parts[0]

			// Validate prefixes
			if !strings.HasPrefix(encryptedKey, UserKeyPrefix) &&
				!strings.HasPrefix(encryptedKey, ManagementKeyPrefix) {
				slog.Error("invalid encrypted key prefix", "key", encryptedKey[:4]+"****")
				continue
			}

			// Decrypt the key
			keyTypePrefix := UserKeyPrefix
			if strings.HasPrefix(encryptedKey, ManagementKeyPrefix) {
				keyTypePrefix = ManagementKeyPrefix
			}

			encryptedBin, err := base64.URLEncoding.DecodeString(strings.TrimPrefix(encryptedKey, keyTypePrefix))
			if err != nil {
				slog.Error("base64 decode failed", "error", err)
				continue
			}

			plainKeyBytes, err := crypto.Decrypt(encryptedBin)
			if err != nil {
				slog.Error("api key解密失败", "error", err)
				continue
			}
			plainKey = fmt.Sprintf("%s%s", keyTypePrefix, base64.URLEncoding.EncodeToString(plainKeyBytes))

			migratedKeys = append(migratedKeys, line)
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
	var hasManagementKey bool
	for k := range keyStore {
		if strings.HasPrefix(k, ManagementKeyPrefix) {
			hasManagementKey = true
			break
		}
	}

	if !hasManagementKey {
		mgmtKey, err := GenerateAPIKey(crypto, true)
		if err != nil {
			panic("failed to generate management API key: " + err.Error())
		}
		slog.Info("Auto-generated management API Key",
			"key", mgmtKey[:4]+"****",
			"notice", "This management key should be securely stored")
	}
}

func GenerateAPIKey(crypto Crypto, isManagement bool) (string, error) {
	if !isManagement {
		// 限制最多10个api key
		if len(keyStore) >= MaxUserKeys {
			return "", fmt.Errorf("maximum number of user keys reached (%d)", MaxUserKeys)
		}
	}
	// Generate plain key
	keyBytes := make([]byte, keyLength)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", err
	}

	// Encrypt storage
	encrypted, err := crypto.Encrypt([]byte(keyBytes))
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}
	encryptedKey := base64.URLEncoding.EncodeToString(encrypted)

	prefix := UserKeyPrefix
	if isManagement {
		prefix = ManagementKeyPrefix
	}
	plainKey := prefix + base64.URLEncoding.EncodeToString(keyBytes)

	// Write to file
	mu.Lock()
	defer mu.Unlock()

	path := filepath.Join(os.Getenv("HOME"), ".ollama", keyFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := f.WriteString(fmt.Sprintf("%s%s%s%s\n", prefix, encryptedKey, KeySeparator, plainKey)); err != nil {
		return "", err
	}

	keyStore[plainKey] = true
	return plainKey, nil
}
