# secuLlama
## Feature Description( [中文](README_zh.md) )
This project is based on the open source  [Ollama](https://github.com/ollama/ollama) , with added security configuration parameters to protect the large model runtime system. The main features are as follows:
### 1. SSL/TLS Transmission Security Protection
- Supports the national standard **GM/T 0024-2014** dual certificates (signature certificate and encryption certificate)
- Environment variable configuration is as follows:
```bash
  # Path to the server SSL/TLS certificate file
  OLLAMA_SSL_CERT=path/to/sig_cert.pem
  OLLAMA_SSL_KEY=path/to/sig_key.pem
  # When the system detects that OLLAMA_SSL_CERT is a national certificate, it will automatically enable the environment variables for the encryption certificate
  OLLAMA_SSL_CERT_ENC=path/to/enc_cert.pem
  OLLAMA_SSL_KEY_ENC=path/to/enc_key.pem
```
### 2. API Key Security Protection
- API security protection is enabled by default, and a random key is generated on the first startup and written to the ~/.ollama/api_keys file.

### 3. Signature for Large Model System Response Messages
- Performs SM3 calculation and signature on the output content of the large model conversation API to prevent tampering with the model file.
- Required environment variables:
```bash
# SM2 key file (PKCS8 format)
OLLAMA_SM2_KEY=path/to/sm2_private.pem
OLLAMA_SM2_SIGNATORY="Your Organization Name"
```
- After configuring the SM2 signature, the client will automatically calculate the signature in the returned conversation message when calling the API.
- Example response message for /api/chat:
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
### 4. Consistency Check for Large Model Files
- Performs HMAC calculation on the model file after it is pulled locally and verifies the HMAC when the model file is loaded to prevent tampering.
- Required HMAC key data(16 bytes):
```
OLLAMA_HMAC_KEY=path/to/hmac_key.bin
```
### 5. Hardware Security Module Support
- This project supports the use of hardware modules such as cryptographic cards to provide secure key protection capabilities, encrypting API keys, HMAC keys, SM2 keys, and certificate files.
- Supports the standard GM 0018 cryptographic operation interface.
- After enabling the HSM function, configure the following environment variables:
```bash
# Index of the sm2 key in the cryptographic device
OLLAMA_SM2_KEY=1
# The hmac key data(16 bytes)
OLLAMA_HMAC_KEY=123456
# The sm4 key data(16 bytes)
OLLAMA_SM4_KEY=12345678xxxxxxxx
```

## Installation

- The compilation using software cryptographic algorithms is consistent with Ollama. Refer to Manual install instructions.
- To compile with Hardware Security Module (HSM), you need to copy the library files of the connected HSM to the `security` directory and enable the hsm tag for compilation as follows:

## Usage Instructions
### ollama Command
- Basically the same as Ollama, refer to the[Ollama项目](https://github.com/ollama/ollama)for usage.
- After enabling SSL/TLS transmission on the server, the client needs to add the following configuration parameters:
```bash
--insecure # Ignore certificate verification
--gmtls # Use GM SSL certificate(Default to using RSA certificate)
```
- Example:
```bash
export OLLAMA_HOST=https://127.0.0.1:11434 
export OAPIKEY=ss-.....
# Connect to GM SSL certificate server
ollama --gmtls --apikey=${OAPIKEY} list

# Connect to RSA SSL server
ollama --apikey=${OAPIKEY} list
```
### REST API
- Usage is consistent with the original[Ollama](https://github.com/ollama/ollama)project.
- API calls require added API key security authentication, example:
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
### API Key File Description
The API key file is stored by default in the directory: ~/.ollama/api_keys, with the format: [ciphertext]$[plaintext].
Notes:
- If there is no $ separator, it indicates that the key is in plaintext.
- Only the ciphertext can be retained, but the $ must be preserved.