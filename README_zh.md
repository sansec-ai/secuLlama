# secuLlama
## 功能说明( [English](README.md) )
本项目基于开源 [Ollama](https://github.com/ollama/ollama) ，增加安全配置参数，对大模型运行系统进行安全保护，主要特性如下:
### 1. SSL/TLS 传输安全保护
- 支持国密标准 **GM/T 0024-2014** 双证书 (签名证书和加密证书)
- 服务启动时配置环境变量如下:
```bash
  # 服务端SSL/TLS 证书文件的路径, PFX 格式
  OLLAMA_SSL_PFX=path/to/sig_cert.pfx
  # pfx 密码
  OLLAMA_SSL_PFX_PASSWD=123456
  # 系统检测OLLAMA_SSL_PFX是国密证书时，会自动启用加密证书的环境变量
  OLLAMA_SSL_PFX_ENC=path/to/enc_cert.pfx
  OLLAMA_SSL_PFX_ENC_PASSWD=123456
```
### 2. API Key 安全保护
- 默认启用API安全防护，并在第一次启动时生成一个随机的key，写入`~/.ollama/api_keys`文件。
- 每次对secuLlama的API调用，都会使用apiKey进行校验。

### 3. 大模型系统响应消息的签名
- 对大模型对话API输出的内容进行sm3计算和sm2签名，防止大模型的输出被非法篡改。
- 服务启动时需配置如下环境变量:
```bash
# sm2 key文件(PKCS8格式)
OLLAMA_SM2_KEY=path/to/sm2_private.pem
OLLAMA_SM2_SIGNATORY="Your Organization Name"
```
- 配置sm2签名后，客户端调用API 请求时，会在返回的对话消息中自动计算签名.
- 以``/api/chat``为例，响应消息示例如下：
```json
{
    "model": "deepseek-r1:1.5b",
    "created_at": "2025-03-11T10:45:56.928360888Z",
    "message": {
        "role": "assistant",
        "content": "<think>\n\n</think>\n\n您好！我是由中国的深度求索（DeepSeek）公司开发的智能助手DeepSeek-R1。有关模型和产品的详细内容请参考官方文档。"
    },
    "done_reason": "stop",
    "done": true,
    "signature": {
        "sm3": "cf05e6d620804396898976ecb81ca67b40caf7fa8de29a0c5fc0905f94f78a59",
        "value": "30440220370aaba3d848cbbc503a1f37ae7b19ed1fea617f50e79d362a159cda39e6064f0220313bab6a02a623d7930417cbb03120dc932e7a0ca0c7b5460678ea05657a98e4",
        "timestamp": "2025-03-11 10:45:56.934260136 +0000 UTC",
        "signatory": "三未信安人工智能系统"
    },
    "total_duration": 24225576425,
    "load_duration": 22651813713,
    "prompt_eval_count": 5,
    "prompt_eval_duration": 123000000,
    "eval_count": 38,
    "eval_duration": 1432000000
}
```

### 4.大模型文件的一致性校验
- 模型文件在拉取到本地后进行hmac计算 ，并在模型文件运行加载时进行hmac验证，防止模型文件被篡改。
- 服务启动时需要配置HMAC key值(16字节):
```
OLLAMA_HMAC_KEY=12345678xxxxxxxx
```
### 5. 硬件安全模块(HSM)的支持
- 本项目支持使用密码卡等硬件模块，提供安全密钥的保护能力 ，可对api key文件及证书文件进行加密保护。
- 支持标准GM 0018的密码运算接口。
- 在启用HSM功能后，配置以下环境变量：
```bash
# sm2 key在密码机中的索引
OLLAMA_SM2_KEY=1
# hmac key值
OLLAMA_HMAC_KEY=12345678xxxxxxxx
# 用于加密api key文件的SM4密钥
OLLAMA_SM4_KEY=12345678xxxxxxxx
```

## 安装

- 使用软件密码算法的编译与Ollama一致，参考[Manual install instructions](https://github.com/ollama/ollama/blob/main/docs/linux.md).
- 使用硬件安全模块编译，需要将连接的密码卡(机)的库文件复制到`security`目录，并启用`hsm`标签编译，如下：
```bash
go build --tags=hsm .
```


## 使用说明
### ollama命令
- 基本与Ollama一样，使用方法请参考[Ollama项目](https://github.com/ollama/ollama)。
- 客户端增加如下的配置参数：
```bash
--insecure # 是否忽略证书校验
--gmtls # 使用国密证书 (默认使用RSA证书)
```
- 示例如下:
```bash
export OLLAMA_HOST=https://127.0.0.1:11434 
export OAPIKEY=ss-.....
# 连接国密服务端
ollama --gmtls --apikey=${OAPIKEY} list

# 连接rsa服务端
ollama --apikey=${OAPIKEY} list
```
### REST API
- 使用方式与原[Ollama](https://github.com/ollama/ollama)项目保持一致。
- 在调用API时需要增加了apikey安全认证，示例如下：
```bash
curl -kv -X POST https://127.0.0.1:11434/api/chat \
     -H "Authorization: Bearer ss-......" \
     -H "Content-Type: application/json" \
     -d '{
          "model": "deepseek-r1:1.5b",
          "messages": [
            { "role": "user", "content": "介绍自己" }
          ],
          "stream": true
        }'
```
## ApiKey文件说明
apikey文件默认存储目录：`~/.ollama/api_keys`，格式：[密文]$[明文]
说明：
- 没有$分隔符，表示是明文
-	可以只保留密文，但需要保留$