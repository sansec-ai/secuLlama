#ifndef _SDF_H_
#define _SDF_H_ 1

#ifdef __cplusplus
extern "C"{
#endif

/*RSA最大模长定义*/
#define SGD_RSA_MAX_BITS    4096

/*数据类型定义*/
typedef char								SGD_CHAR;
typedef char								SGD_INT8;
typedef short								SGD_INT16;
typedef int									SGD_INT32;
typedef long long							SGD_INT64;
typedef unsigned char						SGD_UCHAR;
typedef unsigned char						SGD_UINT8;
typedef unsigned short						SGD_UINT16;
typedef unsigned int						SGD_UINT32;
typedef unsigned long long					SGD_UINT64;
typedef unsigned int						SGD_RV;
typedef void*								SGD_OBJ;
typedef int									SGD_BOOL;
typedef void*								SGD_HANDLE;

#define GEER

/*设备信息*/
typedef struct DeviceInfo_st{
	unsigned char IssuerName[40];
	unsigned char DeviceName[16];
	unsigned char DeviceSerial[16];
	unsigned int  DeviceVersion;
	unsigned int  StandardVersion;
	unsigned int  AsymAlgAbility[2];
	unsigned int  SymAlgAbility;
	unsigned int  HashAlgAbility;
	unsigned int  BufferSize;
}DEVICEINFO;

/*设备运行信息--自定义扩展*/
typedef struct st_DeviceRunStatus{
	unsigned int onboot;		//服务是否开机自启动
	unsigned int service;		//当前服务状态，0-未启动，1-已启动，>1状态异常
	unsigned int concurrency;	//当前并发数
	unsigned int memtotal;		//内存大小
	unsigned int memfree;		//内存空闲
	unsigned int cpu;			//CPU占用率，不包含小数点部分
	unsigned int reserve1;
	unsigned int reserve2;
}DEVICE_RUN_STATUS;

/*密钥同步返回数据结构体*/
typedef struct SyncInfoData_st {
	unsigned char IssuerName[16];    //同步从机标签名称
	unsigned int  ReturnCode;        //此从机返回编码，0：成功  其他:失败
}SYNCINFODATA;

//注意密钥同步暂时最多支持100台从机
typedef struct SyncInfo_st {
	unsigned int Numbers;		//同步从机返回报文数量
	SYNCINFODATA Info[100];      //各个从机的同步报文
}SYNCINFO;


/*RSA密钥*/
#define LiteRSAref_MAX_BITS    2048
#define LiteRSAref_MAX_LEN     ((LiteRSAref_MAX_BITS + 7) / 8)
#define LiteRSAref_MAX_PBITS   ((LiteRSAref_MAX_BITS + 1) / 2)
#define LiteRSAref_MAX_PLEN    ((LiteRSAref_MAX_PBITS + 7)/ 8)

typedef struct RSArefPublicKeyLite_st
{
	unsigned int  bits;
	unsigned char m[LiteRSAref_MAX_LEN];
	unsigned char e[LiteRSAref_MAX_LEN];
}RSArefPublicKeyLite;

typedef struct RSArefPrivateKeyLite_st
{
	unsigned int  bits;
	unsigned char m[LiteRSAref_MAX_LEN];
	unsigned char e[LiteRSAref_MAX_LEN];
	unsigned char d[LiteRSAref_MAX_LEN];
	unsigned char prime[2][LiteRSAref_MAX_PLEN];
	unsigned char pexp[2][LiteRSAref_MAX_PLEN];
	unsigned char coef[LiteRSAref_MAX_PLEN];
}RSArefPrivateKeyLite;

#define ExRSAref_MAX_BITS    4096
#define ExRSAref_MAX_LEN     ((ExRSAref_MAX_BITS + 7) / 8)
#define ExRSAref_MAX_PBITS   ((ExRSAref_MAX_BITS + 1) / 2)
#define ExRSAref_MAX_PLEN    ((ExRSAref_MAX_PBITS + 7)/ 8)

typedef struct RSArefPublicKeyEx_st
{
	unsigned int  bits;
	unsigned char m[ExRSAref_MAX_LEN];
	unsigned char e[ExRSAref_MAX_LEN];
} RSArefPublicKeyEx;

typedef struct RSArefPrivateKeyEx_st
{
	unsigned int  bits;
	unsigned char m[ExRSAref_MAX_LEN];
	unsigned char e[ExRSAref_MAX_LEN];
	unsigned char d[ExRSAref_MAX_LEN];
	unsigned char prime[2][ExRSAref_MAX_PLEN];
	unsigned char pexp[2][ExRSAref_MAX_PLEN];
	unsigned char coef[ExRSAref_MAX_PLEN];
} RSArefPrivateKeyEx;

#if defined(SGD_RSA_MAX_BITS) && (SGD_RSA_MAX_BITS > LiteRSAref_MAX_BITS)
#define RSAref_MAX_BITS    ExRSAref_MAX_BITS
#define RSAref_MAX_LEN     ExRSAref_MAX_LEN
#define RSAref_MAX_PBITS   ExRSAref_MAX_PBITS
#define RSAref_MAX_PLEN    ExRSAref_MAX_PLEN

typedef struct RSArefPublicKeyEx_st  RSArefPublicKey;
typedef struct RSArefPrivateKeyEx_st  RSArefPrivateKey;
#else
#define RSAref_MAX_BITS    LiteRSAref_MAX_BITS
#define RSAref_MAX_LEN     LiteRSAref_MAX_LEN
#define RSAref_MAX_PBITS   LiteRSAref_MAX_PBITS
#define RSAref_MAX_PLEN    LiteRSAref_MAX_PLEN

typedef struct RSArefPublicKeyLite_st  RSArefPublicKey;
typedef struct RSArefPrivateKeyLite_st  RSArefPrivateKey;
#endif

/*ECC密钥*/
#define ECCref_MAX_BITS			512
#define ECCref_MAX_LEN			((ECCref_MAX_BITS+7) / 8)
#define ECCref_MAX_CIPHER_LEN	136

typedef struct ECCrefPublicKey_st
{
	unsigned int  bits;
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
	unsigned int  bits;
	unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

typedef struct ECCrefPublicKey1_st
{
	unsigned char x[ECCref_MAX_LEN /2];
	unsigned char y[ECCref_MAX_LEN / 2];
} ECCrefPublicKeyLite;

typedef struct ECCrefPrivateKey1_st
{
	unsigned char K[ECCref_MAX_LEN / 2];
} ECCrefPrivateKeyLite;



/*ECC 密文*/
typedef struct ECCCipher_st
{
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
	unsigned char M[32];
	int clength; //C的有效长度
	unsigned char C[ECCref_MAX_CIPHER_LEN];
} ECCCipher;

/*ECC 签名*/
typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];
	unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

/*密钥对保护结构结构体*/
typedef struct ECCrefPairEnvelopedKey_st
{
	unsigned int versions;
	unsigned int  ulSymmAlgID;
	unsigned int  ulBits;
	unsigned char encryptedPriKey[64];
	ECCrefPublicKey pubKey;
	ECCCipher      pairCipher;
} ECCPairEnvelopedKey;
/*RSA加密密钥对保护结构，自定义*/
typedef struct RSA_ENVELOPEDKEYBLOB {
	SGD_UINT32 Version;                  // 当前版本为 1
	SGD_UINT32 ulSymmAlgID;              // 规范中的算法标识，限定ECB模式
	SGD_UCHAR cbEncryptedPriKey[4096];    // 加密保护的加密私钥（其他类型没有将公钥结构放到私钥结构后面）
	SGD_UINT32 ulEncryptedPriKeyLen;      // 加密保护的加密私钥长度
	SGD_UCHAR cbEncryptedSymmKey[512];   // RSA公钥加密的密钥加密密钥
	SGD_UINT32 ulEncryptedSymmKeyLen;      // RSA公钥加密的密钥加密密钥长度
}RSAENVELOPEDKEYBLOB, *PRSAENVELOPEDKEYBLOB;
typedef struct ECCPairEnvelopedKey  ENVELOPEDKEYBLOB;
//ECDSA
#define ECDSAref_MAX_BITS		640
#define ECDSAref_MAX_LEN			((ECDSAref_MAX_BITS+7) / 8)

#define SGD_ECDSA_Brainpool			0x00080800
#define SGD_ECDSA_P					0x00080001
#define SGD_ECDSA_K					0x00080002
#define SGD_ECDSA_B					0x00080003
#define SGD_ECDSA_BrainpoolR1		0x00080004
#define SGD_ECDSA_BrainpoolT1		0x00080005
#define SGD_ECDSA_FRP_256			0x00080006
#define SGD_ECDSA_FRP				0x00080006
#define SGD_ECDSA_WAPIP				0x00080007
typedef struct ECDSArefPublicKey_st
{
	unsigned int  bits;
	unsigned int  curvetype;
	unsigned char x[ECDSAref_MAX_LEN];
	unsigned char y[ECDSAref_MAX_LEN];
} ECDSArefPublicKey;

typedef struct ECDSArefPrivateKey_st
{
	unsigned int  bits;
	unsigned int  curvetype;
	unsigned char D[ECDSAref_MAX_LEN];
} ECDSArefPrivateKey;

typedef struct ECDSASignature_st
{
	unsigned char r[ECDSAref_MAX_LEN];
	unsigned char s[ECDSAref_MAX_LEN];
} ECDSASignature;


typedef struct KeyHandleInfo_st
{
	SGD_UINT32 nHandleFlag;		//句柄标识
	void * hSessionHandle;
	SGD_UINT32 nKeyType;
	SGD_UINT32 nID;
	SGD_UINT32 nLength;
	SGD_UCHAR  pbKey[64+16];
}KEY_INFO,*KEY_HANDLE;

//HMAC上下文结构体， 内部分布HMAC用
typedef struct HMacCtxInter_st
{
	unsigned char hCtx[1024];
	unsigned int  hCtxLen;
	unsigned char oCtx[1024];
	unsigned int  oCtxLen;
	unsigned int  uiAlgID;
}HMacCtxInter;

typedef struct ECCPoint_st
{
	unsigned char  x[ECCref_MAX_LEN];
	unsigned char  y[ECCref_MAX_LEN];
}ECCPoint;

// 扩展的签名结构定义
typedef  struct  ECCSignatureEx_st
{
	ECCPoint	R;
	unsigned char  	s[ECCref_MAX_LEN];
} ECCSignatureEx;

#define SGD_KYBER                   0x00600000
#define SGD_DILITHIUM               0x00600001
#define SGD_SPHINCS                 0x00600002
#define SGD_FALCON                  0x00600003
#define SGD_LAC                     0x00600004
#define SGD_AIGISENC                0x00600005
#define SGD_AIGISSIG                0x00600006
#define PQCPubKey_MAX_LEN           4096
#define PQCPriKey_MAX_LEN           8192

typedef struct PQCPublicKey_st
{
	unsigned int  PQCAlgID;
	unsigned int  security_level;
	unsigned int  hash_mode;
	unsigned int  sphincs_plus_mode;
	unsigned int  pk_len;
	unsigned char pk[PQCPubKey_MAX_LEN];
} PQCPublicKey;
typedef struct PQCPrivateKey_st
{
	unsigned int  PQCAlgID;
	unsigned int  security_level;
	unsigned int  hash_mode;
	unsigned int  sphincs_plus_mode;
	unsigned int  sk_len;
	unsigned char sk[PQCPriKey_MAX_LEN];
} PQCPrivateKey;


/*常量定义*/
#define SGD_TRUE			0x00000001
#define SGD_FALSE			0x00000000

#define SGD_SMS4_ECB		0x00000401
#define SGD_SMS4_CBC		0x00000402
#define SGD_SMS4_CFB		0x00000404
#define SGD_SMS4_OFB		0x00000408
#define SGD_SMS4_MAC		0x00000410
#define SGD_SMS4_CTR		0x00000420
#define SGD_SMS4_GCM		0x00000440
#define SGD_SMS4_GMAC	    0x00000440
#define SGD_SMS4_XTS		0x00000480
#define SGD_SMS4_CCM		0x000004A0
#define SGD_SMS4_CMAC		0x000004C0
#define SGD_SMS4_FPE_FF1	0x000004E0
#define SGD_SMS4_FPE_FF1_CN	0x000004E1
#define SGD_SMS4_FPE_FF3	0x000004F0
#define SGD_SMS4_FPE_FF3_CN	0x000004F1


#define SGD_3DES_ECB		0x00001001
#define SGD_3DES_CBC		0x00001002
#define SGD_3DES_CFB		0x00001004
#define SGD_3DES_OFB		0x00001008
#define SGD_3DES_MAC		0x00001010
#define SGD_3DES_CTR		0x00001020
#define SGD_3DES_CMAC		0x000010C0


#define SGD_AES_ECB			0x00002001
#define SGD_AES_CBC			0x00002002
#define SGD_AES_CFB			0x00002004
#define SGD_AES_OFB			0x00002008
#define SGD_AES_MAC			0x00002010
#define SGD_AES_CTR			0x00002020
#define SGD_AES_GCM			0x00002040
#define SGD_AES_GCM_256		0x00002040
#define SGD_AES_GMAC	    0x00002040
#define SGD_AES_XTS			0x00002080
#define SGD_AES_CCM			0x000020A0
#define SGD_AES_CMAC		0x000020C0
#define SGD_AES_FPE_FF1		0x000020E0
#define SGD_AES_FPE_FF1_CN	0x000020E1
#define SGD_AES_FPE_FF3		0x000020F0
#define SGD_AES_FPE_FF3_CN	0x000020F1

#define SGD_DES_ECB			0x00004001
#define SGD_DES_CBC			0x00004002
#define SGD_DES_CFB			0x00004004
#define SGD_DES_OFB			0x00004008
#define SGD_DES_MAC			0x00004010
#define SGD_DES_CTR			0x00004020


/*非对称密码算法标识*/
#define SGD_RSA				0x00010000
#define SGD_RSA_SIGN		0x00010100	//私钥运算
#define SGD_RSA_ENC			0x00010200	//公钥运算


#define SGD_SM2 			0x00020100
#define SGD_SM2_1			0x00020200	//椭圆曲线签名算法
#define SGD_SM2_2			0x00020400	//椭圆曲线密钥交换协议
#define SGD_SM2_3			0x00020800	//椭圆曲线加密算法




#define SGD_SM3				0x00000001
#define SGD_SHA1			0x00000002
#define SGD_SHA256			0x00000004
#define SGD_SHA512			0x00000008
#define SGD_SHA384			0x00000010
#define SGD_SHA224			0x00000020
#define SGD_MD5				0x00000080
#define SGD_RIPEMD160		0x00000085

#define SGD_SHA3_256		0x00001004
#define SGD_SHA3_512		0x00001008
#define SGD_SHA3_384		0x00001010
#define SGD_SHA3_224		0x00001020

#define SGD_SHA3_KE128		0x00001040
#define SGD_SHA3_KE256		0x00001080


/*标准错误码定义*/
#define SDR_OK				0x0						   /*成功*/
#define SDR_BASE			0x01000000
#define SDR_UNKNOWERR				(SDR_BASE + 0x00000001)	   /*未知错误*/
#define SDR_NOTSUPPORT				(SDR_BASE + 0x00000002)	   /*不支持*/
#define SDR_COMMFAIL				(SDR_BASE + 0x00000003)    /*通信错误*/
#define SDR_HARDFAIL				(SDR_BASE + 0x00000004)    /*硬件错误*/
#define SDR_OPENDEVICE				(SDR_BASE + 0x00000005)    /*打开设备错误*/
#define SDR_OPENSESSION				(SDR_BASE + 0x00000006)    /*打开会话句柄错误*/
#define SDR_PARDENY					(SDR_BASE + 0x00000007)    /*权限不满足*/
#define SDR_KEYNOTEXIST				(SDR_BASE + 0x00000008)    /*密钥不存在*/
#define SDR_ALGNOTSUPPORT			(SDR_BASE + 0x00000009)    /*不支持的算法*/
#define SDR_ALGMODNOTSUPPORT 		(SDR_BASE + 0x0000000A)		/*不支持的算法模式*/
#define SDR_PKOPERR					(SDR_BASE + 0x0000000B)    /*公钥运算错误*/
#define SDR_SKOPERR					(SDR_BASE + 0x0000000C)    /*私钥运算错误*/
#define SDR_SIGNERR					(SDR_BASE + 0x0000000D)    /*签名错误*/
#define SDR_VERIFYERR				(SDR_BASE + 0x0000000E)    /*验证错误*/
#define SDR_SYMOPERR				(SDR_BASE + 0x0000000F)    /*对称运算错误*/
#define SDR_STEPERR					(SDR_BASE + 0x00000010)    /*步骤错误*/
#define SDR_FILESIZEERR				(SDR_BASE + 0x00000011)    /*文件大小错误 | 数据长度错误*/
#define SDR_FILENOEXIST				(SDR_BASE + 0x00000012)    /*文件不存在*/
#define SDR_FILEOFSERR				(SDR_BASE + 0x00000013)    /*文件操作偏移量错误*/
#define SDR_KEYTYPEERR				(SDR_BASE + 0x00000014)    /*密钥类型错误*/
#define SDR_KEYERR					(SDR_BASE + 0x00000015)    /*密钥错误*/

#define SDR_ENCDATAERR				(SDR_BASE + 0x00000016)		/*ECC加密数据错误*/
#define SDR_RANDERR					(SDR_BASE + 0x00000017)		/*随机数产生失败*/
#define SDR_PRKRERR					(SDR_BASE + 0x00000018)		/*私钥使用权限获取失败，未获取 | 私钥访问控制权限释放失败，未获取*/
#define SDR_MACERR					(SDR_BASE + 0x00000019)		/*MAC运算失败*/
#define SDR_FILEEXISTS				(SDR_BASE + 0x0000001A)		/*指定文件已存在*/
#define SDR_FILEWERR				(SDR_BASE + 0x0000001B)		/*文件写入失败*/
#define SDR_NOBUFFER				(SDR_BASE + 0x0000001C)		/*存储空间不足*/
#define SDR_INARGERR				(SDR_BASE + 0x0000001D)		/*输入参数错误：1、输入数据长度错误；2、输入数据或地址为空；3、输入密钥索引错误；4、输入的密钥模长错误*/
#define SDR_OUTARGERR				(SDR_BASE + 0x0000001E)		/*输出参数错误*/



/*设备管理类函数*/
SGD_RV SDF_OpenDevice(SGD_HANDLE *phDeviceHandle);
SGD_RV SDF_CloseDevice(SGD_HANDLE hDeviceHandle);
SGD_RV SDF_OpenSession(SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle);
SGD_RV SDF_CloseSession(SGD_HANDLE hSessionHandle);
SGD_RV SDF_GetVersion(unsigned int   *puiVersion);
SGD_RV SDF_GetDeviceInfo(SGD_HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo);
SGD_RV SDF_GenerateRandom(SGD_HANDLE hSessionHandle, SGD_UINT32  uiLength, SGD_UCHAR *pucRandom);
SGD_RV SDF_GetPrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex,SGD_UCHAR *pucPassword, SGD_UINT32  uiPwdLength);
SGD_RV SDF_ReleasePrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex);
/*密钥管理类函数*/
/*RSA算法密钥管理*/
SGD_RV SDF_ExportSignPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey);
SGD_RV SDF_ExportEncPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,RSArefPublicKey *pucPublicKey);
SGD_RV SDF_GenerateKeyWithIPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR *pucKey,SGD_UINT32 *puiKeyLength,SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithEPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits,RSArefPublicKey *pucPublicKey,SGD_UCHAR *pucKey,SGD_UINT32 *puiKeyLength,SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ImportKeyWithISK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,SGD_UCHAR *pucKey,SGD_UINT32 uiKeyLength,SGD_HANDLE *phKeyHandle);
/*ECC算法密钥管理*/
SGD_RV SDF_ExportSignPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,ECCrefPublicKey *pucPublicKey);
SGD_RV SDF_ExportEncPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex,ECCrefPublicKey *pucPublicKey);
SGD_RV SDF_GenerateKeyWithIPK_ECC (SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex,SGD_UINT32 uiKeyBits,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithEPK_ECC (SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits,SGD_UINT32  uiAlgID,ECCrefPublicKey *pucPublicKey,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ImportKeyWithISK_ECC (SGD_HANDLE hSessionHandle,SGD_UINT32 uiISKIndex,ECCCipher *pucKey,SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateAgreementDataWithECC (SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR *pucSponsorID,SGD_UINT32 uiSponsorIDLength,ECCrefPublicKey  *pucSponsorPublicKey,ECCrefPublicKey  *pucSponsorTmpPublicKey,SGD_HANDLE *phAgreementHandle);
SGD_RV SDF_GenerateKeyWithECC (SGD_HANDLE hSessionHandle, SGD_UCHAR *pucResponseID,SGD_UINT32 uiResponseIDLength,ECCrefPublicKey *pucResponsePublicKey,ECCrefPublicKey *pucResponseTmpPublicKey,SGD_HANDLE hAgreementHandle,SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateAgreementDataAndKeyWithECC (SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex,SGD_UINT32 uiKeyBits,SGD_UCHAR *pucResponseID,SGD_UINT32 uiResponseIDLength,SGD_UCHAR *pucSponsorID,SGD_UINT32 uiSponsorIDLength,ECCrefPublicKey *pucSponsorPublicKey,ECCrefPublicKey *pucSponsorTmpPublicKey,ECCrefPublicKey  *pucResponsePublicKey,	ECCrefPublicKey  *pucResponseTmpPublicKey,SGD_HANDLE *phKeyHandle);
/*对称算法密钥管理*/
SGD_RV SDF_GenerateKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits,SGD_UINT32  uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ImportKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32  uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_DestroyKey(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle);
/*非对称算法运算类函数*/
SGD_RV SDF_ExternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPublicKey *pucPublicKey,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR *pucDataOutput,SGD_UINT32  *puiOutputLength);
SGD_RV SDF_InternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR *pucDataOutput,SGD_UINT32  *puiOutputLength);
SGD_RV SDF_InternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle,SGD_UINT32  uiKeyIndex,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,SGD_UCHAR *pucDataOutput,SGD_UINT32  *puiOutputLength);
/*非对称密码ECC密钥管理、运算函数*/
SGD_RV SDF_ExternalVerify_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR *pucDataInput,SGD_UINT32  uiInputLength,ECCSignature *pucSignature);
SGD_RV SDF_InternalSign_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature);
SGD_RV SDF_InternalVerify_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32  uiISKIndex,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCSignature *pucSignature);
SGD_RV SDF_ExternalEncrypt_ECC(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength,ECCCipher *pucEncData);
/*对称密钥管理、密码运算函数*/
SGD_RV SDF_ImportKey(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength,SGD_HANDLE *phKeyHandle);
SGD_RV SDF_Encrypt(SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR *pucIV,SGD_UCHAR *pucData,SGD_UINT32 uiDataLength,SGD_UCHAR *pucEncData,SGD_UINT32  *puiEncDataLength);
SGD_RV SDF_Decrypt (SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR *pucIV,SGD_UCHAR *pucEncData,SGD_UINT32  uiEncDataLength,SGD_UCHAR *pucData,SGD_UINT32 *puiDataLength);
SGD_RV SDF_CalculateMAC(SGD_HANDLE hSessionHandle,SGD_HANDLE hKeyHandle,SGD_UINT32 uiAlgID,SGD_UCHAR *pucIV,SGD_UCHAR *pucData,SGD_UINT32 uiDataLength,SGD_UCHAR *pucMAC,SGD_UINT32  *puiMACLength);
/*杂凑运算函数*/
SGD_RV SDF_HashInit(SGD_HANDLE hSessionHandle,SGD_UINT32 uiAlgID,ECCrefPublicKey *pucPublicKey,SGD_UCHAR *pucID,SGD_UINT32 uiIDLength);
SGD_RV SDF_HashUpdate(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucData,SGD_UINT32  uiDataLength);
SGD_RV SDF_HashFinal(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucHash,SGD_UINT32  *puiHashLength);
SGD_RV SDF_Hash(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucID, SGD_UINT32 uiIDLength, SGD_UCHAR *pucData, SGD_UINT32  uiDataLength, SGD_UCHAR *pucHash, SGD_UINT32  *puiHashLength);
SGD_RV SDF_HMAC(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR  *pucData, SGD_UINT32  uiDataLength, SGD_UCHAR  *pucHmac, SGD_UINT32 *puiHmacLen);
/*用户文件操作函数*/
SGD_RV SDF_CreateFile(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiFileSize);
SGD_RV SDF_ReadFile(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiOffset,SGD_UINT32 *puiReadLength,SGD_UCHAR *pucBuffer);
SGD_RV SDF_WriteFile(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucFileName,SGD_UINT32 uiNameLen,SGD_UINT32 uiOffset,SGD_UINT32 uiWriteLength,SGD_UCHAR *pucBuffer);
SGD_RV SDF_DeleteFile(SGD_HANDLE hSessionHandle,SGD_UCHAR *pucFileName,SGD_UINT32 uiNameLen);
#ifdef __cplusplus
}
#endif

#endif /*#ifndef _SDF_H_*/
