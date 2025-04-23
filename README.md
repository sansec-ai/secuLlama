# secuLlama
## 功能说明( [English](README_en.md) )
本项目基于开源 [Ollama](https://github.com/ollama/ollama) ，增加安全配置参数，对大模型运行系统进行安全保护，主要特性如下:
- SSL/TLS 传输安全保护: 支持国密标准 **GM/T 0024-2014** 双证书 (签名证书和加密证书)。
- API Key 安全保护: 支持使用密码卡等硬件模块，提供安全密钥的保护能力 ，可对api key文件及证书文件进行加密保护。
- 大模型系统响应消息签名: 对大模型对话API输出内容进行SM3计算和签名。
- 大模型文件的一致性校验: 对大模型文件进行hmac计算，并在模型文件运行加载时进行hmac验证，防止模型文件被篡改。
- 资源流量智能调控：通过QoS策略动态限制API并发请求数量，保障服务质量。

## 使用说明
### 安装&编译
```bash
# 环境要求 golang == 1.24.0
git clone https://github.com/sansec-ai/secuLlama.git
cd secuLlama
cmake -B build
cmake --build build
go build -o secuLlama .
# 编译成功，会在项目目录下生成可执行文件 `secuLlama` 。

```
### 启动服务
##### 1. 准备SSL证书（可选）
首先要准备SSL证书 ，可以使用openssl生成自签名证书，也可以使用商业证书。
```bash
# 
# 复制到/data/certs/目录

# 配置SSL证书的路径和密码
export OLLAMA_SSL_PFX=/data/certs/server.pfx
export OLLAMA_SSL_PFX_PASSWD=123456
# 如果是国密SSL证书，还需要同时配置加密证书
# OLLAMA_SSL_PFX_ENC=path/to/enc_cert.pfx
# OLLAMA_SSL_PFX_ENC_PASSWD=123456
```
##### 2. 配置sm2 key文件, 要求PKCS8格式（可选）
```bash
# ... 生成sm2key文件

# 配置sm2 key文件路径和签名者信息
export OLLAMA_SM2_KEY=/data/keys/sm2-pkcs8.key
export OLLAMA_SM2_SIGNATORY=三未信安人工智能系统
```
##### 3. 配置HMAC KEY
```bash
export OLLAMA_HMAC_KEY=12345678xxxxxxxx
```
##### 4. 启动服务
```bash
./secuLlama serve
.....
.....
time=2025-04-11T13:34:40.144+08:00 level=INFO source=routes.go:1333 msg="Listening on [::]:11434 (version 0.0.0)"
time=2025-04-11T13:34:40.147+08:00 level=INFO source=gpu.go:217 msg="looking for compatible GPUs"
time=2025-04-11T13:34:45.595+08:00 level=INFO source=gpu.go:377 msg="no compatible GPUs were discovered"
time=2025-04-11T13:34:45.596+08:00 level=INFO source=types.go:130 msg="inference compute" id=0 library=cpu variant="" compute="" driver=0.0 name="" total="15.5 GiB" available="4.2 GiB"
time=2025-04-11T13:34:45.596+08:00 level=INFO source=routes.go:1378 msg="Starting GMSSL server."
```

### APIKEY
`secuLlama` 默认启用APIKEY保护，在第一次启动时生成一个随机的key，写入`~/.ollama/api_keys`文件，内容如下：
```bash
$ cat ~/.ollama/api_keys
sm-xxxxxxxxxxxxxxxxxxxxxxxx=$sm-xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```
该文件格式为: `密文$明文`，在系统生成后可以将明文删除（需保留`$`分隔符）。
- 注: 只有在HSM模式下才会真正生成密文，否则密文和明文是相同的。

### 下载模型
```bash
# 配置本地secuLlama服务端地址
export OLLAMA_HOST=https://127.0.0.1:11434
# 配置管理用的apikey
export OAPIKEY=sm-xxxxxx
# 连接服务端
./secuLlama --apikey=${OAPIKEY} pull deepseek-r1:1.5b
pulling manifest 
pulling aabd4debf0c8... 100% ▕███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████▏ 1.1 GB                         
pulling 369ca498f347... 100% ▕███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████▏  387 B                         
pulling 6e4c38e1172f... 100% ▕███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████▏ 1.1 KB                         
pulling f4d24e9138dd... 100% ▕███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████▏  148 B                         
pulling a85fe2a2e58e... 100% ▕███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████▏  487 B                         
verifying sha256 digest 
writing manifest 
success 
```
### REST API使用示例
在调用API时需要增加apikey安全认证，示例如下：
```bash
curl -X POST https://127.0.0.1:11434/api/chat \
     -H "Authorization: Bearer sm-xxxx(替换为实际apikey)" \
     -H "Content-Type: application/json" \
     -d '{
          "model": "deepseek-r1:1.5b",
          "messages": [
            { "role": "user", "content": "介绍自己" }
          ],
          "stream": true
        }'
```
在配置sm2签名后，调用API 请求时，会在返回的对话消息中自动计算签名，如下：
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

## HSM 支持
### 编译
- 本项目支持使用密码卡等硬件模块，提供安全密钥的保护能力 ，可对api key文件及证书文件进行加密保护。
- 启用HSM支持，需要把HSM设备的驱动类库复制到本项目的`security`目录, 并使用`--tags=hsm`编译。
- 示例如下：
```bash
# 以三未信安科技有限公司的密码机为例，需要将`libswsds.so`复制到`security`目录，并更名为`libhsm_0018.so`。
cp your_path/libswsds.so security/libhsm_0018.so
go build --tags=hsm  -o secuLlama .
```
### 配置
在启用HSM支持的`secuLlama`，配置与普通`secuLlama`的配置相同，只是`OLLAMA_SM2_KEY`环境变量配置的是在密码机中的索引：
```bash
# SM2 密钥索引
OLLAMA_SM2_KEY=2
```
还需要配置SM4key用于对apikey文件加密：
```bash
export OLLAMA_SM4_KEY=1234xxxxxxxxxxxx
```


## 功能特性
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


## 其他
### secuLlama命令
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
secuLlama --gmtls --apikey=${OAPIKEY} list

# 连接rsa服务端
secuLlama --apikey=${OAPIKEY} list
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

## 贡献指南
欢迎贡献代码或提出改进建议！请参考贡献指南了解如何参与项目。

## 联系我们
如需进一步了解或技术支持，请访问 GitHub项目页面 或联系项目维护者。