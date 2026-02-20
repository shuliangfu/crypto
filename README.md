# @dreamer/crypto

> Encryption and security utilities for Deno and Bun: hash, encrypt/decrypt,
> sign/verify, JWT, and more.

English | [中文 (Chinese)](./docs/zh-CN/README.md)

[![JSR](https://jsr.io/badges/@dreamer/crypto)](https://jsr.io/@dreamer/crypto)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-85%20passed-brightgreen)](./docs/en-US/TEST_REPORT.md)

**Changelog** (latest): [1.0.2] - 2026-02-20 — Added: browser test suite (14
tests, 85 total). Changed: client entry English-only errors, no i18n. Full
history: [English](./docs/en-US/CHANGELOG.md) |
[中文 (Chinese)](./docs/zh-CN/CHANGELOG.md)

---

## 🎯 Features

Full-featured crypto and security library: hash, symmetric/asymmetric
encryption, digital signatures, JWT, password hashing, random generation. Built
on Web Crypto API. Compatible with Deno and Bun.

---

## 📦 Installation

### Deno

```bash
deno add jsr:@dreamer/crypto
```

### Bun

```bash
bunx jsr add @dreamer/crypto
```

---

## 🌍 Environment Compatibility

| Environment      | Version Requirement | Status                                          |
| ---------------- | ------------------- | ----------------------------------------------- |
| **Deno**         | 2.5+                | ✅ Fully supported                              |
| **Bun**          | 1.0+                | ✅ Fully supported                              |
| **Server**       | -                   | ✅ Supported (Deno/Bun runtime, Web Crypto API) |
| **Client**       | -                   | ✅ Supported (browser, Web Crypto API)          |
| **Dependencies** | -                   | 📦 No external dependencies (Web Crypto API)    |

---

## ✨ Characteristics

- **Hash**:
  - SHA1, SHA256, SHA512
  - Hash verification
  - MD5 rejected (insecure)
- **Symmetric encryption (AES)**:
  - AES-128-GCM, AES-256-GCM, AES-128-CBC, AES-256-CBC
  - Key generation and import
  - CryptoKey and Uint8Array key support
- **Asymmetric encryption (RSA)**:
  - RSA-OAEP
  - Key pair generation (configurable modulus length)
- **Digital signatures**:
  - RSA signatures (RSA-SHA256, RSA-SHA384, RSA-SHA512)
  - ECDSA signatures (P-256, P-384, P-521)
- **Random generation**:
  - Secure random bytes
  - Random string (custom charset support)
  - Random integer
  - UUID v4
- **Password hashing**:
  - bcrypt, argon2 (argon2id, argon2i, argon2d)
- **JWT (JSON Web Token)**:
  - Token generation, verification, decode
  - HS256/384/512, RS256/384/512, ES256/384/512
- **Key generation and management**:
  - AES keys, RSA key pairs, ECDSA key pairs

---

## 🎯 Use Cases

- **Data encryption storage and transport**: Sensitive data encryption, database
  field encryption, API data transmission encryption
- **Authentication and authorization**: JWT token generation and verification,
  session management
- **Secure communication**: HTTPS certificates, message encryption, key exchange
- **Password storage**: User password hashing, password verification
- **Digital signatures**: Document signing, data integrity verification, tamper
  resistance
- **Security tokens**: API key generation, temporary tokens, one-time passwords

---

## 🚀 Quick Start

### Hash Algorithm

```typescript
import { hash, verifyHash } from "jsr:@dreamer/crypto";

const data = "sensitive data";
const hashValue = await hash(data, "sha256");
console.log(hashValue); // 64-char hex string

const isValid = await verifyHash(data, hashValue, "sha256");
console.log(isValid); // true

const sha1Hash = await hash(data, "sha1");
const sha512Hash = await hash(data, "sha512");
```

### Symmetric Encryption and Decryption (AES)

```typescript
import { decrypt, encrypt, generateKey } from "jsr:@dreamer/crypto";

const key = await generateKey("aes-256");
const plaintext = "sensitive data";
const encrypted = await encrypt(plaintext, key, "aes-256-gcm");
console.log(encrypted); // base64

const decrypted = await decrypt(encrypted, key, "aes-256-gcm");
console.log(decrypted); // "sensitive data"
```

### JWT

```typescript
import { decodeJWT, signJWT, verifyJWT } from "jsr:@dreamer/crypto";

const payload = { userId: 123, username: "alice", role: "admin" };
const secret = "your-secret-key";

const token = await signJWT(payload, secret, {
  algorithm: "HS256",
  expiresIn: "1h",
  issuer: "my-app",
  audience: "api-users",
  subject: "user-123",
});

const decoded = await verifyJWT(token, secret);
console.log(decoded); // { userId: 123, username: "alice", ... }

const decodedOnly = decodeJWT(token);
```

### Random Number Generation

```typescript
import {
  generateRandomBytes,
  generateRandomInt,
  generateRandomString,
  generateUUID,
} from "jsr:@dreamer/crypto";

const randomBytes = generateRandomBytes(32);
const randomString = generateRandomString(32);
const randomInt = generateRandomInt(1, 100);
const uuid = generateUUID();
```

---

## 🎨 Examples

### Asymmetric Encryption (RSA)

```typescript
import {
  decryptRSA,
  encryptRSA,
  generateRSAKeyPair,
} from "jsr:@dreamer/crypto";

const { publicKey, privateKey } = await generateRSAKeyPair(2048);
const plaintext = "sensitive data";
const encrypted = await encryptRSA(plaintext, publicKey);
const decrypted = await decryptRSA(encrypted, privateKey);
console.log(decrypted); // "sensitive data"
```

### Digital Signatures

```typescript
import {
  generateECDSAKeyPair,
  generateRSAKeyPair,
  sign,
  verify,
} from "jsr:@dreamer/crypto";

// RSA
const { publicKey, privateKey } = await generateRSAKeyPair(2048);
const data = "important document";
const signature = await sign(data, privateKey, "rsa-sha256");
const isValid = await verify(data, signature, publicKey, "rsa-sha256");
console.log(isValid); // true

// ECDSA
const { publicKey: ecdsaPublicKey, privateKey: ecdsaPrivateKey } =
  await generateECDSAKeyPair("P-256");
const ecdsaSignature = await sign(data, ecdsaPrivateKey, "ecdsa-sha256");
const isValidECDSA = await verify(
  data,
  ecdsaSignature,
  ecdsaPublicKey,
  "ecdsa-sha256",
);
```

### Password Hashing

```typescript
import { hashPassword, verifyPassword } from "jsr:@dreamer/crypto";

const password = "user-password";
const hashed = await hashPassword(password, "bcrypt", { rounds: 10 });
const isValid = await verifyPassword(password, hashed);
console.log(isValid); // true

const argon2Hashed = await hashPassword(password, "argon2id", {
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
});
const isValidArgon2 = await verifyPassword(password, argon2Hashed);
```

### Full Application Example

```typescript
import {
  decrypt,
  encrypt,
  generateKey,
  hashPassword,
  signJWT,
  verifyJWT,
  verifyPassword,
} from "jsr:@dreamer/crypto";

async function registerUser(username: string, password: string) {
  const hashedPassword = await hashPassword(password, "bcrypt", {
    rounds: 10,
  });
  await saveUser({ username, password: hashedPassword });
}

async function loginUser(username: string, password: string) {
  const user = await findUser(username);
  const isValid = await verifyPassword(password, user.password);
  if (isValid) {
    const token = await signJWT(
      { userId: user.id, username: user.username },
      process.env.JWT_SECRET!,
      { expiresIn: "24h" },
    );
    return { token };
  }
  throw new Error("Invalid password");
}

async function saveSensitiveData(data: string) {
  const key = await generateKey("aes-256");
  const encrypted = await encrypt(data, key, "aes-256-gcm");
  await saveToDatabase({ encrypted }); // store key securely elsewhere
}

async function verifyRequest(token: string) {
  const payload = await verifyJWT(token, process.env.JWT_SECRET!);
  return payload;
}
```

---

## 📚 API Documentation

### Hash Algorithm

| Method                                                | Description  |
| ----------------------------------------------------- | ------------ |
| `hash(data, algorithm?): Promise<string>`             | Compute hash |
| `verifyHash(data, hash, algorithm): Promise<boolean>` | Verify hash  |

**Algorithms**: `sha1`, `sha256`, `sha512` (MD5 rejected)

### Symmetric Encryption and Decryption

| Method                                                  | Description           |
| ------------------------------------------------------- | --------------------- |
| `encrypt(plaintext, key, algorithm?): Promise<string>`  | Encrypt               |
| `decrypt(ciphertext, key, algorithm?): Promise<string>` | Decrypt               |
| `generateKey(algorithm): Promise<CryptoKey>`            | Generate AES key      |
| `importAESKey(keyData, algorithm?): Promise<CryptoKey>` | Import key from bytes |

**Algorithms**: `aes-128-gcm`, `aes-256-gcm`, `aes-128-cbc`, `aes-256-cbc`

### Asymmetric Encryption and Decryption

| Method                                                          | Description              |
| --------------------------------------------------------------- | ------------------------ |
| `generateRSAKeyPair(bits?): Promise<{ publicKey, privateKey }>` | Generate RSA key pair    |
| `encryptRSA(plaintext, publicKey): Promise<string>`             | Encrypt with public key  |
| `decryptRSA(ciphertext, privateKey): Promise<string>`           | Decrypt with private key |

### Digital Signatures

| Method                                                            | Description |
| ----------------------------------------------------------------- | ----------- |
| `sign(data, privateKey, algorithm): Promise<string>`              | Sign        |
| `verify(data, signature, publicKey, algorithm): Promise<boolean>` | Verify      |

**Algorithms**: `rsa-sha256`, `rsa-sha384`, `rsa-sha512`, `ecdsa-sha256`,
`ecdsa-sha384`, `ecdsa-sha512`

### Password Hashing

| Method                                                         | Description     |
| -------------------------------------------------------------- | --------------- |
| `hashPassword(password, algorithm, options?): Promise<string>` | Hash password   |
| `verifyPassword(password, hashed): Promise<boolean>`           | Verify password |

**Algorithms**: `bcrypt`, `argon2id`, `argon2i`, `argon2d`

### JWT

| Method                                                | Description                  |
| ----------------------------------------------------- | ---------------------------- |
| `signJWT(payload, secret, options?): Promise<string>` | Sign JWT                     |
| `verifyJWT(token, secret): Promise<JWTPayload>`       | Verify JWT                   |
| `decodeJWT(token)`                                    | Decode JWT (no verification) |

**Algorithms**: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`,
`ES384`, `ES512`

### Random Number Generation

| Method                                           | Description   |
| ------------------------------------------------ | ------------- |
| `generateRandomBytes(length): Uint8Array`        | Random bytes  |
| `generateRandomString(length, charset?): string` | Random string |
| `generateRandomInt(min, max): number`            | Random int    |
| `generateUUID(): string`                         | UUID v4       |

---

## 🔧 Advanced Configuration

### Security Notes

#### Key Management

- ✅ **Key storage**: Store keys securely (env vars, KMS)
- ✅ **Key rotation**: Rotate keys regularly, especially symmetric keys
- ✅ **Key length**: AES at least 256-bit, RSA at least 2048-bit
- ❌ **Do not hardcode keys**: Never hardcode keys in code
- ❌ **Do not commit keys**: Do not commit keys to version control

#### Password Hashing

- ✅ **Use dedicated algorithms**: Use bcrypt or argon2, not plain hash (MD5,
  SHA256)
- ✅ **Sufficient cost**: bcrypt rounds at least 10
- ✅ **Salting**: Automatic salting
- ❌ **Do not use MD5/SHA256**: These are not suitable for password hashing

#### Algorithm Selection

- ✅ **Symmetric**: AES-256-GCM for bulk data (recommended)
- ✅ **Asymmetric**: RSA-OAEP for key exchange
- ✅ **Signatures**: RSA or ECDSA
- ❌ **Avoid weak algorithms**: Avoid DES, RC4, etc.

#### JWT Security

- ✅ **Strong keys**: HS256 at least 256-bit, RS256 at least 2048-bit
- ✅ **Expiration**: All tokens should have expiration
- ✅ **Verify signatures**: Always verify token signatures
- ❌ **Do not store sensitive data in payload**: JWT payload is decodable

---

## 📊 Test Report

[![Tests](https://img.shields.io/badge/tests-85%20passed-brightgreen)](./docs/en-US/TEST_REPORT.md)

| Metric             | Value                        |
| ------------------ | ---------------------------- |
| **Total**          | 85                           |
| **Passed**         | 85                           |
| **Failed**         | 0                            |
| **Pass Rate**      | 100%                         |
| **Execution Time** | ~8s                          |
| **Environment**    | Deno 2.5+, Bun 1.0+; browser |

**Coverage**: 71 server-side tests (mod.test.ts) and 14 browser client tests
(browser.test.ts). Hash, verify, random, AES keys, symmetric encryption,
RSA/ECDSA key pairs, RSA encryption, signatures, JWT, edge cases, security
validation; browser tests cover client bundle in headless browser.

See [TEST_REPORT.md](./docs/en-US/TEST_REPORT.md) for details.

---

## 📝 Notes

- All crypto operations are async; use `await`
- Store keys and sensitive data securely; do not hardcode
- Use a key management service in production (e.g. AWS KMS, Azure Key Vault)
- Rotate algorithms and keys periodically

---

## 🤝 Contributing

Issues and Pull Requests welcome!

---

## 📄 License

Apache License 2.0 - see [LICENSE](./LICENSE)

---

<div align="center">

**Made with ❤️ by Dreamer Team**

</div>
