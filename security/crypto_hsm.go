//go:build hsm && cgo

package security

import (
	"encoding/asn1"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strconv"

	"github.com/ollama/ollama/envconfig"
	"github.com/tjfoc/gmsm/sm3"
)

type HSMCrypto struct {
	sm2KeyIndex uint32
	hmacKey     []byte
}

func NewCrypto() (Crypto, error) {
	// 获取环境变量中的密钥索引
	keyIndex, err := strconv.Atoi(envconfig.SM2Key())
	if err != nil {
		slog.Warn("SM2_KEY_INDEX not found, use default key index--1")
		keyIndex = 1
	}
	hmacKey, _ := GetHmacKey()

	return &HSMCrypto{uint32(keyIndex), hmacKey}, nil
}

func (c *HSMCrypto) Hmac(message []byte) ([]byte, error) {
	handler, err := SDF_OpenDevice()
	if err != nil {
		return nil, err
	}
	session, err := SDF_OpenSession(handler)
	if err != nil {
		return nil, err
	}
	defer SDF_CloseSession(session)
	defer SDF_CloseDevice(handler)

	keyHandle, err := SDF_ImportKey(session, c.hmacKey)
	if err != nil {
		return nil, err
	}
	defer SDF_DestroyKey(session, keyHandle)

	pucMac, err := SDF_HMAC(session, keyHandle, SGD_SM3, message)
	if err != nil {
		return nil, fmt.Errorf("计算HMAC失败: %v", err)
	}
	return pucMac, nil
}

func (c *HSMCrypto) HmacFile(filePath string) ([]byte, error) {
	handler, err := SDF_OpenDevice()
	if err != nil {
		return nil, err
	}
	session, err := SDF_OpenSession(handler)
	if err != nil {
		return nil, err
	}
	defer SDF_CloseSession(session)
	defer SDF_CloseDevice(handler)

	keyHandle, err := SDF_ImportKey(session, c.hmacKey)
	if err != nil {
		return nil, err
	}
	defer SDF_DestroyKey(session, keyHandle)

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
	pucMac, err := SDF_HMAC(session, keyHandle, SGD_SM3, hashSum)
	if err != nil {
		return nil, fmt.Errorf("计算HMAC失败: %v", err)
	}
	return pucMac, nil
}

func (c *HSMCrypto) Sign(message []byte) ([]byte, error) {
	handler, err := SDF_OpenDevice()
	if err != nil {
		return nil, err
	}
	session, err := SDF_OpenSession(handler)
	if err != nil {
		return nil, err
	}
	defer SDF_CloseSession(session)
	defer SDF_CloseDevice(handler)
	// 导出公钥
	pubkey, err := SDF_ExportSignPublicKey_ECC(session, c.sm2KeyIndex)
	if err != nil {
		return nil, err
	}
	// hash公钥预处理
	hashRes, err := SDF_Hash(session, SGD_SM3, pubkey, []byte("1234567812345678"), message)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	// 内部密钥签名
	ecc, err := SDF_InternalSign_ECC(session, c.sm2KeyIndex, hashRes)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	toGo := convertECCSignatureToGo(ecc)
	return asn1.Marshal(toGo)
}

func (c *HSMCrypto) Verify(message []byte, signed []byte) bool {
	return false
}

func GetHmacKey() ([]byte, bool) {
	hmacKeyData := envconfig.HMACKey()
	if hmacKeyData == "" {
		// default hmac key
		return []byte("1234567812345678"), false
	}
	return []byte(hmacKeyData), true
}
