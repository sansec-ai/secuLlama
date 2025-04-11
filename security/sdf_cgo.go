//go:build hsm && cgo

package security

//
/*
#cgo CFLAGS: -I./
#cgo linux LDFLAGS: -L. -lhsm_0018 -Wl,-rpath,${SRCDIR}

#if defined(__linux__) || defined(linux)
    #include <pthread.h>
#endif

#include<stdlib.h>
#include<string.h>
#include "sdf.h"
*/
import "C"
import (
	"fmt"
	"math/big"
	"unsafe"
)

type CTypeAlgorithm C.SGD_UINT32
type CTypeSGDHandle C.SGD_HANDLE

const MAX_INT int = 2147483647
const SGD_SM3 CTypeAlgorithm = 0x00000001
const SGD_SMS4_CBC CTypeAlgorithm = 0x00000402
const SGD_SMS4_ECB CTypeAlgorithm = 0x00000401

func ConvertInt64toError(result int64) error {
	if result == 0 {
		return nil
	}
	return fmt.Errorf("[error code:0x%X]", result)
}

func SDF_OpenDevice() (handler CTypeSGDHandle, err error) {
	var sgdHandle C.SGD_HANDLE
	result := C.SDF_OpenDevice(&sgdHandle)

	err = ConvertInt64toError(int64(result))
	handler = CTypeSGDHandle(sgdHandle)
	return
}

// SDF_CloseDevice 关闭设备
func SDF_CloseDevice(handler CTypeSGDHandle) (err error) {

	result := C.SDF_CloseDevice(C.SGD_HANDLE(handler))
	err = ConvertInt64toError(int64(result))
	return
}

// SDF_OpenSession 打开session
func SDF_OpenSession(handler CTypeSGDHandle) (session CTypeSGDHandle, err error) {

	var sgdSession C.SGD_HANDLE
	result := C.SDF_OpenSession(C.SGD_HANDLE(handler), &sgdSession)

	err = ConvertInt64toError(int64(result))
	session = CTypeSGDHandle(sgdSession)
	return
}

// SDF_CloseSession 关闭session
func SDF_CloseSession(session CTypeSGDHandle) (err error) {

	result := C.SDF_CloseSession(C.SGD_HANDLE(session))
	err = ConvertInt64toError(int64(result))
	return
}

func SDF_GenerateRandom(session CTypeSGDHandle, len int) (data []byte, err error) {

	charArr := make([]C.SGD_UCHAR, len)
	result := C.SDF_GenerateRandom(C.SGD_HANDLE(session), C.SGD_UINT32(len), &charArr[0])
	data = SgdUCHARArrToByteArr(charArr)
	err = ConvertInt64toError(int64(result))
	return
}

// SGD_RV SDF_ImportKey (SGD_HANDLE hSessionHandle, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength,SGD_HANDLE *phKeyHandle);
func SDF_ImportKey(session CTypeSGDHandle, key []byte) (hKeyHandle CTypeSGDHandle, err error) {

	pucKey := ByteArrToSgdUCHARArr(key)
	uiKeyLength := C.SGD_UINT32(len(key))
	var handle C.SGD_HANDLE
	result := C.SDF_ImportKey(C.SGD_HANDLE(session), &pucKey[0], uiKeyLength, &handle)
	hKeyHandle = CTypeSGDHandle(handle)
	err = ConvertInt64toError(int64(result))
	return

}

func SDF_DestroyKey(session CTypeSGDHandle, hKeyHandle CTypeSGDHandle) (err error) {

	result := C.SDF_DestroyKey(C.SGD_HANDLE(session), C.SGD_HANDLE(hKeyHandle))
	err = ConvertInt64toError(int64(result))
	return
}

func SDF_Encrypt(session CTypeSGDHandle, hKeyHandle CTypeSGDHandle, alg CTypeAlgorithm, pucIV []byte, pucData []byte) (pucEncData []byte, err error) {

	pucIVs := ByteArrToSgdUCHARArr(pucIV)
	pucDatas := ByteArrToSgdUCHARArr(pucData)
	uiDataLength := C.SGD_UINT32(len(pucData))
	pucEncDatas := make([]C.SGD_UCHAR, len(pucData))
	var puiEncDataLength C.SGD_UINT32
	var result C.SGD_RV
	if pucIVs == nil {
		result = C.SDF_Encrypt(C.SGD_HANDLE(session), C.SGD_HANDLE(hKeyHandle), C.SGD_UINT32(alg), nil, &pucDatas[0], uiDataLength, &pucEncDatas[0], &puiEncDataLength)
	} else {
		result = C.SDF_Encrypt(C.SGD_HANDLE(session), C.SGD_HANDLE(hKeyHandle), C.SGD_UINT32(alg), &pucIVs[0], &pucDatas[0], uiDataLength, &pucEncDatas[0], &puiEncDataLength)
	}
	pucEncData = SgdUCHARArrToByteArr(pucEncDatas)
	err = ConvertInt64toError(int64(result))
	return
}

func SDF_Decrypt(session CTypeSGDHandle, hKeyHandle CTypeSGDHandle, alg CTypeAlgorithm, pucIV []byte, pucEncData []byte) (pucData []byte, err error) {

	pucIVs := ByteArrToSgdUCHARArr(pucIV)
	pucEncDatas := ByteArrToSgdUCHARArr(pucEncData)
	uiEncDataLength := C.SGD_UINT32(len(pucEncData))
	pucDatas := make([]C.SGD_UCHAR, len(pucEncData))
	var puiDataLength C.SGD_UINT32
	var result C.SGD_RV
	if pucIVs == nil {
		result = C.SDF_Decrypt(C.SGD_HANDLE(session), C.SGD_HANDLE(hKeyHandle), C.SGD_UINT32(alg), nil, &pucEncDatas[0], uiEncDataLength, &pucDatas[0], &puiDataLength)
	} else {
		result = C.SDF_Decrypt(C.SGD_HANDLE(session), C.SGD_HANDLE(hKeyHandle), C.SGD_UINT32(alg), &pucIVs[0], &pucEncDatas[0], uiEncDataLength, &pucDatas[0], &puiDataLength)
	}
	pucData = SgdUCHARArrToByteArr(pucDatas)
	err = ConvertInt64toError(int64(result))
	return
}

func SDF_HMAC(session CTypeSGDHandle, hKeyHandle CTypeSGDHandle, alg CTypeAlgorithm, pucData []byte) ([]byte, error) {
	pucDatas := C.CBytes(pucData)
	defer C.free(pucDatas)
	uiDataLength := C.SGD_UINT32(len(pucData))
	var hmacLen C.SGD_UINT32
	hmacResult := make([]byte, 64)

	var result C.SGD_RV
	result = C.SDF_HMAC(C.SGD_HANDLE(session), C.SGD_HANDLE(hKeyHandle), C.SGD_UINT32(alg), (*C.SGD_UCHAR)(pucDatas), uiDataLength, (*C.SGD_UCHAR)(unsafe.Pointer(&hmacResult[0])), &hmacLen)
	err := ConvertInt64toError(int64(result))
	return hmacResult[:hmacLen], err
}

func SDF_InternalSign_ECC(session CTypeSGDHandle, iskIndex uint32, data []byte) (signature C.ECCSignature, err error) {

	pucDatas := C.CBytes(data)
	defer C.free(pucDatas)

	rv := C.SDF_InternalSign_ECC(C.SGD_HANDLE(session), C.SGD_UINT32(iskIndex), (*C.SGD_UCHAR)(pucDatas), C.SGD_UINT32(len(data)), &signature)
	if rv != 0 {
		err = ConvertInt64toError(int64(rv))
		return
	}
	return signature, nil
}

func SDF_ExportSignPublicKey_ECC(session CTypeSGDHandle, iskIndex uint32) (publicKey C.ECCrefPublicKey, err error) {

	rv := C.SDF_ExportSignPublicKey_ECC(C.SGD_HANDLE(session), C.SGD_UINT32(iskIndex), &publicKey)
	if rv != 0 {
		err = ConvertInt64toError(int64(rv))
		return
	}
	return publicKey, nil
}
func SDF_ExportEncPublicKey_ECC(session CTypeSGDHandle, iskIndex uint32) (publicKey C.ECCrefPublicKey, err error) {

	rv := C.SDF_ExportEncPublicKey_ECC(C.SGD_HANDLE(session), C.SGD_UINT32(iskIndex), &publicKey)
	if rv != 0 {
		err = ConvertInt64toError(int64(rv))
		return
	}
	return publicKey, nil
}

func SDF_InternalVerify_ECC(session CTypeSGDHandle, iskIndex uint32, data []byte, signature C.ECCSignature) (verifyRes bool, err error) {

	pucDatas := C.CBytes(data)
	defer C.free(pucDatas)

	rv := C.SDF_InternalVerify_ECC(C.SGD_HANDLE(session), C.SGD_UINT32(iskIndex), (*C.SGD_UCHAR)(pucDatas), C.SGD_UINT32(len(data)), &signature)
	if rv != 0 {
		return false, ConvertInt64toError(int64(rv))
	}
	return true, nil
}

func SDF_ExternalVerify_ECC(session CTypeSGDHandle, alg CTypeAlgorithm, eccRefPublicKey C.ECCrefPublicKey, data []byte, signature C.ECCSignature) (verifyRes bool, err error) {

	pucDatas := C.CBytes(data)
	defer C.free(pucDatas)

	rv := C.SDF_ExternalVerify_ECC(C.SGD_HANDLE(session), C.SGD_UINT32(alg), &eccRefPublicKey, (*C.SGD_UCHAR)(pucDatas), C.SGD_UINT32(len(data)), &signature)
	if rv != 0 {
		return false, ConvertInt64toError(int64(rv))
	}
	return true, nil
}

// 单段式hash
func SDF_Hash(session CTypeSGDHandle, alg CTypeAlgorithm, eccRefPublicKey C.ECCrefPublicKey, pucID []byte, data []byte) (hashData []byte, err error) {

	pucDatas := C.CBytes(data)
	defer C.free(pucDatas)
	pucIDs := C.CBytes(pucID)
	defer C.free(pucIDs)
	hashResult := make([]byte, 64)
	var hashLen C.SGD_UINT32

	rv := C.SDF_Hash(C.SGD_HANDLE(session), C.SGD_UINT32(alg), &eccRefPublicKey, (*C.SGD_UCHAR)(pucIDs), C.SGD_UINT32(len(pucID)), (*C.SGD_UCHAR)(pucDatas), C.SGD_UINT32(len(data)), (*C.SGD_UCHAR)(unsafe.Pointer(&hashResult[0])), &hashLen)
	if rv != 0 {
		err = ConvertInt64toError(int64(rv))
		return nil, err
	}
	return hashResult[:hashLen], nil
}

// --- c 语言转换go
func ConvertSgdUCharPtrToString(uChars *C.SGD_UCHAR, len int) string {
	if uChars == nil {
		return ""
	}
	bytes := ConvertSgdUCharPtrToBytes(uChars, len)
	return string(bytes)
}
func ConvertSgdUCharPtrToBytes(uChars *C.SGD_UCHAR, len int) []byte {
	var bytes []byte
	if uChars == nil {
		return bytes
	}
	uCharSlice := (*[MAX_INT]C.uchar)(unsafe.Pointer(uChars))[:len]
	for _, b := range uCharSlice {
		bytes = append(bytes, byte(b))
	}
	return bytes
}

func UcharArrToByteArr(buf []C.uchar) []byte {
	var ret []byte
	if buf == nil {
		return nil
	}
	for i := 0; i < len(buf); i++ {
		ret = append(ret, byte(buf[i]))
	}
	return ret
}
func ByteArrToUcharArr(buf []byte) []C.uchar {
	var ret []C.uchar
	if buf == nil {
		return nil
	}
	for i := 0; i < 32; i++ {
		if i < len(buf) {
			ret = append(ret, C.uchar(buf[i]))
		} else {
			ret = append(ret, C.uchar([]byte("0")[0]))
		}
	}
	return ret
}
func ByteArrToSgdUCHARArr32(buf []byte) []C.SGD_UCHAR {
	var ret []C.SGD_UCHAR
	if buf == nil {
		return nil
	}
	for i := 0; i < 32; i++ {
		if i < len(buf) {
			ret = append(ret, C.SGD_UCHAR(buf[i]))
		} else {
			ret = append(ret, C.SGD_UCHAR([]byte("0")[0]))
		}
	}
	return ret
}

func ByteArrToSgdUCHARArr(buf []byte) []C.SGD_UCHAR {
	var ret []C.SGD_UCHAR
	if buf == nil {
		return nil
	}
	for i := 0; i < len(buf); i++ {
		if i < len(buf) {
			ret = append(ret, C.SGD_UCHAR(buf[i]))
		} else {
			ret = append(ret, C.SGD_UCHAR([]byte("0")[0]))
		}
	}
	return ret
}

func SgdUCHARArrToByteArr(buf []C.SGD_UCHAR) []byte {
	var ret []byte
	if buf == nil {
		return nil
	}
	for i := 0; i < len(buf); i++ {
		ret = append(ret, byte(buf[i]))
	}
	return ret
}

// 将 64 字节 ECC 公钥转换为 C 结构体 ECCrefPublicKey
func ConvertToECCrefPublicKey(pubKey64 []byte) (*C.ECCrefPublicKey, error) {
	if len(pubKey64) != 64 {
		return nil, fmt.Errorf("公钥长度必须为 64 字节")
	}

	//申请 C 结构体的内存
	eccPub := (*C.ECCrefPublicKey)(C.malloc(C.size_t(unsafe.Sizeof(C.ECCrefPublicKey{}))))
	if eccPub == nil {
		return nil, fmt.Errorf("malloc 失败")
	}

	// 设定密钥位数（通常 256 位）
	eccPub.bits = 256

	//x 坐标填充：前 32 字节设为 0，后 32 字节填充 pubKey64 的前 32 字节
	C.memset(unsafe.Pointer(&eccPub.x[0]), 0, C.size_t(32))                             // 前 32 字节填充 0
	C.memcpy(unsafe.Pointer(&eccPub.x[32]), unsafe.Pointer(&pubKey64[0]), C.size_t(32)) // 复制 pubKey64 前 32 字节到 x 的后 32 字节

	//y 坐标填充：前 32 字节设为 0，后 32 字节填充 pubKey64 的后 32 字节
	C.memset(unsafe.Pointer(&eccPub.y[0]), 0, C.size_t(32))                              // 前 32 字节填充 0
	C.memcpy(unsafe.Pointer(&eccPub.y[32]), unsafe.Pointer(&pubKey64[32]), C.size_t(32)) // 复制 pubKey64 后 32 字节到 y 的后 32 字节

	return eccPub, nil
}

func convertECCSignatureToBytes(sig *C.ECCSignature) []byte {
	result := make([]byte, 64)
	copy(result[:32], (*[32]byte)(unsafe.Pointer(&sig.r[32]))[:])
	copy(result[32:], (*[32]byte)(unsafe.Pointer(&sig.s[32]))[:])
	return result
}

type sm2Signature struct {
	R, S *big.Int
}

// 将 C 的 ECCSignature 转换为 Go 的 sm2Signature
func convertECCSignatureToGo(sig C.ECCSignature) sm2Signature {
	// 创建 sm2Signature
	goSig := sm2Signature{
		R: new(big.Int),
		S: new(big.Int),
	}

	// 将 r 和 s 的字节数组转换为 *big.Int
	goSig.R.SetBytes(C.GoBytes(unsafe.Pointer(&sig.r[0]), C.ECCref_MAX_LEN))
	goSig.S.SetBytes(C.GoBytes(unsafe.Pointer(&sig.s[0]), C.ECCref_MAX_LEN))

	return goSig
}
