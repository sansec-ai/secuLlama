# secuLlama
## Feature Description( [中文](README.md) )
This project is based on the open source [Ollama](https://github.com/ollama/ollama), with added security configuration parameters to protect the large model runtime system. The main features are as follows:
- **SSL/TLS Transmission Security Protection**: Supports the national standard **GM/T 0024-2014** dual certificates (signature certificate and encryption certificate). 
- **API Key Security Protection**: Enforces API key security by default, generating a random key on first startup and storing it in the `~/.ollama/api_keys` file. The file format is `[ciphertext]$[plaintext]`.
- **Signature for Large Model Responses**: SM3 hashing and SM2 signing are applied to the output content of the conversation API to prevent tampering.
- **Model File Integrity Check**: HMAC verification is performed during model file loading to ensure integrity.
- **Resource Flow Control**: Dynamic API request concurrency limits via QoS policies to ensure service quality.
- **Hardware Security Module (HSM) Support**: Integrates cryptographic cards for secure key management, supporting the GM 0018 interface.

### Detailed Features
#### 1. SSL/TLS Transmission Security Protection
- Configuration requires the following environment variables:
```bash
# Path to the signature certificate PFX file and password
OLLAMA_SSL_PFX=path/to/sig_cert.pfx
OLLAMA_SSL_PFX_PASSWD=123456
# Encryption certificate PFX (automatically enabled for national certificates)
OLLAMA_SSL_PFX_ENC=path/to/enc_cert.pfx
OLLAMA_SSL_PFX_ENC_PASSWD=123456
```

#### 2. API Key Security Protection
- By default, API keys are encrypted. The `~/.ollama/api_keys` file format:
  - `[ciphertext]$[plaintext]` (ciphertext only if `$` is kept without plaintext)
  - HSM mode generates true ciphertext.

#### 3. Response Message Signing
- SM2 key requirements:
```bash
OLLAMA_SM2_KEY=path/to/sm2_private.pem  # PKCS8 format
OLLAMA_SM2_SIGNATORY="Your Organization Name"
```
- API responses include a `signature` block with SM3 digest and SM2 signature.

#### 4. Model File Integrity Check
- HMAC key (16 bytes) must be configured:
```bash
OLLAMA_HMAC_KEY=12345678xxxxxxxx
```

#### 5. HSM Support
- **Compilation**:
  - Copy HSM library (e.g., `libswsds.so` → `security/libhsm_0018.so`):
  ```bash
  cp your_path/libswsds.so security/libhsm_0018.so
  ```
  - Build with `--tags=hsm`:
  ```bash
  go build --tags=hsm -o secuLlama .
  ```
- **Configuration**:
```bash
# SM2 key index in HSM
OLLAMA_SM2_KEY=2
# HMAC and SM4 keys for encryption
OLLAMA_HMAC_KEY=12345678xxxxxxxx
OLLAMA_SM4_KEY=12345678xxxxxxxx
```

## Installation & Compilation
```bash
# Environment requirement: golang 1.24.0
git clone https://github.com/sansec-ai/secuLlama.git
cd secuLlama
# Standard build
cmake -B build
cmake --build build
go build -o secuLlama .
# HSM-enabled build
go build --tags=hsm -o secuLlama .
```

## Usage Instructions
### Starting the Service
1. **Optional SSL Certificate Preparation** (using OpenSSL or commercial certs):
   ```bash
   export OLLAMA_SSL_PFX=/data/certs/server.pfx
   export OLLAMA_SSL_PFX_PASSWD=123456
   ```
2. **Optional SM2 Key Configuration**:
   ```bash
   export OLLAMA_SM2_KEY=/data/keys/sm2-pkcs8.key
   export OLLAMA_SM2_SIGNATORY="SanSec AI System"
   ```
3. **HMAC Key Setup**:
   ```bash
   export OLLAMA_HMAC_KEY=12345678xxxxxxxx
   ```
4. **Launch Command**:
   ```bash
   ./secuLlama serve
   ```

### API Key Management
- The default API key file `~/.ollama/api_keys` uses `[ciphertext]$[plaintext]` format.  
- In HSM mode, ciphertext is generated using SM4 encryption with `OLLAMA_SM4_KEY`.

### Model Download Example
```bash
export OLLAMA_HOST=https://127.0.0.1:11434
export OAPIKEY=sm-xxxxxx
./secuLlama --apikey=${OAPIKEY} pull deepseek-r1:1.5b
```

### REST API Usage
```bash
curl -X POST https://127.0.0.1:11434/api/chat \
  -H "Authorization: Bearer sm-xxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-r1:1.5b",
    "messages": [{"role": "user", "content": "介绍自己"}],
    "stream": true
  }'
```

### Command-Line Parameters
```bash
--insecure   # Disable certificate verification
--gmtls      # Use national GM certificates (default RSA)
```

### HSM Configuration Notes
- Ensure HSM libraries are placed in the `security` directory.
- SM4 key is required for encrypting API keys and model files in HSM mode.

## API Key File Format
Stored in `~/.ollama/api_keys` with format:
- `[ciphertext]$[plaintext]`  
- Preserve `$` even if plaintext is removed.

## Contribution Guidelines
Contributions are welcome! Please follow the contribution guide for participation.