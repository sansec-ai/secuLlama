package security

import (
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ollama/ollama/api"
	"github.com/ollama/ollama/envconfig"
	"github.com/tjfoc/gmsm/x509"
)

type Crypto interface {
	Hmac(message []byte) ([]byte, error)
	Sign(message []byte) ([]byte, error)
	Verify(message []byte, signed []byte) bool
	HmacFile(filePath string) ([]byte, error)
}

// 检查安全相关配置的有效性
func LoadSecurityConfig() (string, string, Crypto, error) {
	certFile := envconfig.SSLCert()
	keyFile := envconfig.SSLKey()
	if (certFile == "" && keyFile != "") || (certFile != "" && keyFile == "") {
		return "", "", nil, fmt.Errorf("SSL requires both cert and key")
	}

	// 检查sm2key文件是否有效的sm2文件
	crypto, err := NewCrypto()
	if err != nil {
		return "", "", nil, err
	}
	return certFile, keyFile, crypto, nil
}

func SignResponse(crypto Crypto, sm3Sum []byte, signatory string, resp *api.ChatResponse) error {

	// 对"sm3 hex值+时间戳+签名人"进行sm2签名
	sm3Hex := fmt.Sprintf("%x", sm3Sum)
	timeStr := time.Now().UTC().String()
	signData := append([]byte(sm3Hex), []byte(timeStr)...)
	signData = append(signData, []byte(signatory)...)
	// signData := []byte("test111")

	value, err := crypto.Sign(signData)
	if err != nil {
		slog.Error("sm2 signature error", "error", err)
		return err
	}

	if value == nil {
		slog.Warn("输出消息未签名, 请检查私钥是否正确")
		return nil
	}

	resp.Signature = api.Signature{
		Time:      timeStr,
		Value:     fmt.Sprintf("%x", value),
		SM3:       sm3Hex,
		Signatory: signatory,
	}
	// slog.Info("signPlain in hex", "hex", fmt.Sprintf("%x", signData))
	// slog.Info("signValue in hex", "hex", fmt.Sprintf("%x", value), " len=", len(value))
	return err
}

// 检查是否国密证书
func IsGMSSLCertFile(certFile string) bool {
	if certFile == "" {
		return false
	}
	data, _ := os.ReadFile(certFile)
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}

	// 检测证书类型
	if strings.Contains(block.Type, "SM2") {
		return true
	}
	if strings.Contains(block.Type, "CERTIFICATE") {
		cert, _ := x509.ParseCertificate(block.Bytes)
		return cert.SignatureAlgorithm == x509.SM2WithSM3
	}
	return false
}
