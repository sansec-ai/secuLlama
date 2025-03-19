//go:build !hsm

package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/tjfoc/gmsm/sm3"

	"github.com/ollama/ollama/envconfig"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

type SoftCrypto struct {
	sm2Key  *sm2.PrivateKey
	hmacKey []byte
}

func NewCrypto() (Crypto, error) {
	// 检查sm2key文件是否有效的sm2文件
	var sm2Key *sm2.PrivateKey = nil
	var err error
	sm2Key, err = LoadSM2PrivateKey()
	if err != nil {
		return nil, err
	}
	hmacKey, _ := GetHmacKey()
	if len(hmacKey) != 16 {
		// 未配置环境变量，返回错误
		return nil, fmt.Errorf("HMAC密钥未配置，或者不是16字节")
	}
	return &SoftCrypto{sm2Key: sm2Key, hmacKey: hmacKey}, nil
}

func (c *SoftCrypto) Hmac(message []byte) ([]byte, error) {
	if len(c.hmacKey) == 0 || len(message) == 0 {
		return nil, errors.New("key and message must not be empty")
	}
	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write(message)
	return mac.Sum(nil), nil
}

func (c *SoftCrypto) Sign(message []byte) ([]byte, error) {
	if c.sm2Key == nil {
		return nil, nil
	}
	value, err := c.sm2Key.Sign(rand.Reader, message, nil)
	return value, err
}

func (c *SoftCrypto) Verify(message []byte, signed []byte) bool {
	if c.sm2Key == nil {
		return false
	}
	return c.sm2Key.Verify(message, signed)
}
func (c *SoftCrypto) HmacFile(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	hash := sm3.New()
	// 逐块读取文件并更新HMAC
	buffer := make([]byte, 64*1024) // 64KB的缓冲区
	for {
		n, err := f.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("读取文件失败: %v", err)
		}
		if n == 0 {
			break
		}

		hash.Write(buffer[:n])
	}
	hashSum := hash.Sum(nil)

	// 创建HMAC计算器
	h := hmac.New(sm3.New, c.hmacKey)
	// 计算并返回HMAC的十六进制表示
	hmacSum := h.Sum(hashSum)
	return hmacSum, nil
}
func (c *SoftCrypto) Encrypt(plaintext []byte) ([]byte, error) {
	// 软模块不支持加解密
	return plaintext, nil
}

func (c *SoftCrypto) Decrypt(ciphertext []byte) ([]byte, error) {
	// 软模块不支持加解密
	return ciphertext, nil
}

// LoadSM2PrivateKey 加载并解析SM2私钥
func LoadSM2PrivateKey() (*sm2.PrivateKey, error) {
	sm2File := envconfig.SM2Key()
	if sm2File == "" {
		return nil, nil
	}

	// 读取密钥文件
	keyBytes, err := os.ReadFile(sm2File)
	if err != nil {
		return nil, fmt.Errorf("failed to read SM2 key file: %v", err)
	}

	// 解码PEM格式
	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// 解析SM2私钥
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SM2 private key: %v", err)
	}

	return privKey, nil
}
