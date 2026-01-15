# @dreamer/crypto

> 一个兼容 Deno 和 Bun 的加密和安全工具库，提供哈希、加密解密、签名验证、JWT 等功能

[![JSR](https://jsr.io/badges/@dreamer/crypto)](https://jsr.io/@dreamer/crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🎯 功能

一个功能完整的加密和安全工具库，提供哈希算法、对称/非对称加密解密、数字签名、JWT 令牌、密码哈希、随机数生成等全面的安全功能。基于 Web Crypto API 标准实现，**全面兼容 Deno 和 Bun 运行时环境**，适用于数据加密存储、身份验证、安全通信、密码管理等各类安全场景。

---

## ✨ 特性

| 特性 | 说明 |
|------|------|
| 🔐 **哈希算法** | MD5、SHA1、SHA256、SHA512 |
| 🔒 **对称加密解密（AES）** | AES-128-GCM、AES-256-GCM、AES-128-CBC、AES-256-CBC |
| 🔑 **非对称加密解密（RSA）** | RSA-OAEP |
| ✍️ **数字签名** | RSA、ECDSA 签名生成和验证 |
| 🎲 **随机数生成** | 安全随机数生成器 |
| 🔐 **密码哈希** | bcrypt、argon2（argon2id、argon2i、argon2d） |
| 🎫 **JWT（JSON Web Token）** | Token 生成、验证、解析 |
| 🔑 **密钥生成和管理** | AES 密钥、RSA 密钥对、ECDSA 密钥对 |

---

## 🎯 使用场景

- **数据加密存储和传输**：敏感数据加密、数据库字段加密、API 数据传输加密
- **身份验证和授权**：JWT Token 生成和验证、会话管理
- **安全通信**：HTTPS 证书、消息加密、密钥交换
- **密码存储**：用户密码哈希存储、密码验证
- **数字签名**：文档签名、数据完整性验证、防篡改
- **安全令牌**：API 密钥生成、临时令牌、一次性密码

---

## 📦 安装

### Deno

```bash
deno add jsr:@dreamer/crypto
```

### Bun

```bash
bunx jsr add @dreamer/crypto
```

---

## 🌍 环境兼容性

| 环境 | 版本要求 | 状态 |
|------|---------|------|
| **Deno** | 2.5+ | ✅ 完全支持 |
| **Bun** | 1.0+ | ✅ 完全支持 |
| **服务端** | - | ✅ 支持（兼容 Deno 和 Bun 运行时，使用 Web Crypto API） |
| **客户端** | - | ✅ 支持（浏览器环境，使用 Web Crypto API） |
| **依赖** | - | 📦 无外部依赖（基于 Web Crypto API 标准） |

---

## 🚀 快速开始

### 哈希算法

```typescript
import { hash, verifyHash } from "jsr:@dreamer/crypto";

// 计算哈希值
const data = "敏感数据";
const hashValue = hash(data, "sha256");
console.log(hashValue); // 64位十六进制字符串

// 验证哈希值
const isValid = verifyHash(data, hashValue, "sha256");
console.log(isValid); // true

// 支持的算法
const sha1Hash = hash(data, "sha1");
const sha256Hash = hash(data, "sha256");
const sha512Hash = hash(data, "sha512");
```

### 对称加密解密（AES）

```typescript
import { encrypt, decrypt, generateKey } from "jsr:@dreamer/crypto";

// 生成密钥
const key = generateKey("aes-256"); // 生成 256 位密钥
// 或使用自定义密钥
const customKey = new Uint8Array(32); // 32 字节 = 256 位

// 加密数据
const plaintext = "敏感数据";
const encrypted = encrypt(plaintext, key, "aes-256-gcm");
console.log(encrypted); // base64 编码的加密数据

// 解密数据
const decrypted = decrypt(encrypted, key, "aes-256-gcm");
console.log(decrypted); // "敏感数据"

// 支持的算法
const gcmEncrypted = encrypt(plaintext, key, "aes-256-gcm"); // 推荐，带认证
const cbcEncrypted = encrypt(plaintext, key, "aes-256-cbc"); // 传统模式
```

### 非对称加密解密（RSA）

```typescript
import {
  generateRSAKeyPair,
  encryptRSA,
  decryptRSA
} from "jsr:@dreamer/crypto";

// 生成 RSA 密钥对
const { publicKey, privateKey } = await generateRSAKeyPair(2048); // 2048 位密钥

// 公钥加密
const plaintext = "敏感数据";
const encrypted = await encryptRSA(plaintext, publicKey);
console.log(encrypted); // base64 编码的加密数据

// 私钥解密
const decrypted = await decryptRSA(encrypted, privateKey);
console.log(decrypted); // "敏感数据"

// 导出密钥（PEM 格式）
const publicKeyPEM = await exportPublicKey(publicKey, "pem");
const privateKeyPEM = await exportPrivateKey(privateKey, "pem");
```

### 数字签名

```typescript
import { sign, verify } from "jsr:@dreamer/crypto";

// 生成密钥对
const { publicKey, privateKey } = await generateRSAKeyPair(2048);

// 签名数据
const data = "重要文档";
const signature = await sign(data, privateKey, "rsa-sha256");
console.log(signature); // base64 编码的签名

// 验证签名
const isValid = await verify(data, signature, publicKey, "rsa-sha256");
console.log(isValid); // true

// 使用 ECDSA（更高效）
const { publicKey: ecdsaPublicKey, privateKey: ecdsaPrivateKey } =
  await generateECDSAKeyPair("P-256");
const ecdsaSignature = await sign(data, ecdsaPrivateKey, "ecdsa-sha256");
const isValidECDSA = await verify(data, ecdsaSignature, ecdsaPublicKey, "ecdsa-sha256");
```

### 密码哈希

```typescript
import { hashPassword, verifyPassword } from "jsr:@dreamer/crypto";

// 方式1：使用 bcrypt（推荐，兼容性好）
const password = "用户密码";
const hashed = await hashPassword(password, "bcrypt", { rounds: 10 });
console.log(hashed); // bcrypt 哈希字符串

// 验证密码
const isValid = await verifyPassword(password, hashed);
console.log(isValid); // true

// 方式2：使用 argon2（推荐，更安全）
const argon2Hashed = await hashPassword(password, "argon2id", {
  memoryCost: 65536, // 64 MB
  timeCost: 3,       // 迭代次数
  parallelism: 4,    // 并行度
});
const isValidArgon2 = await verifyPassword(password, argon2Hashed);
```

### JWT（JSON Web Token）

```typescript
import { signJWT, verifyJWT, decodeJWT } from "jsr:@dreamer/crypto";

// 生成 JWT Token
const payload = {
  userId: 123,
  username: "alice",
  role: "admin",
};

const secret = "your-secret-key"; // 或使用 RSA 密钥对
const token = await signJWT(payload, secret, {
  algorithm: "HS256",
  expiresIn: "1h",        // 1小时后过期
  issuer: "my-app",       // 签发者
  audience: "api-users",  // 受众
  subject: "user-123",   // 主题
});

console.log(token); // JWT Token 字符串

// 验证 JWT Token
try {
  const decoded = await verifyJWT(token, secret);
  console.log(decoded); // { userId: 123, username: "alice", ... }
} catch (error) {
  console.error("Token 验证失败:", error);
}

// 仅解码（不验证）
const decoded = decodeJWT(token);
console.log(decoded); // { header: {...}, payload: {...}, signature: "..." }
```

### 随机数生成

```typescript
import { generateRandomBytes, generateRandomString } from "jsr:@dreamer/crypto";

// 生成随机字节
const randomBytes = generateRandomBytes(32); // 32 字节
console.log(randomBytes); // Uint8Array

// 生成随机字符串
const randomString = generateRandomString(32); // 32 字符
console.log(randomString); // 随机字符串

// 生成随机整数
const randomInt = generateRandomInt(1, 100); // 1 到 100 之间的随机数
console.log(randomInt);

// 生成 UUID
const uuid = generateUUID();
console.log(uuid); // UUID v4 格式
```

---

## 📚 API 文档

```typescript
import {
  hashPassword,
  verifyPassword,
  encrypt,
  decrypt,
  generateKey,
  signJWT,
  verifyJWT,
} from "jsr:@dreamer/crypto";

// 1. 用户注册：密码哈希
async function registerUser(username: string, password: string) {
  const hashedPassword = await hashPassword(password, "bcrypt", { rounds: 10 });
  // 存储到数据库
  await saveUser({ username, password: hashedPassword });
}

// 2. 用户登录：密码验证 + JWT 生成
async function loginUser(username: string, password: string) {
  const user = await findUser(username);
  const isValid = await verifyPassword(password, user.password);

  if (isValid) {
    // 生成 JWT Token
    const token = await signJWT(
      { userId: user.id, username: user.username },
      process.env.JWT_SECRET!,
      { expiresIn: "24h" }
    );
    return { token };
  } else {
    throw new Error("密码错误");
  }
}

// 3. 数据加密存储
async function saveSensitiveData(data: string) {
  const key = generateKey("aes-256");
  const encrypted = encrypt(data, key, "aes-256-gcm");
  // 存储加密后的数据和密钥（密钥需要安全存储）
  await saveToDatabase({ encrypted, keyId: key.id });
}

// 4. 数据解密
async function getSensitiveData(keyId: string) {
  const { encrypted, key } = await loadFromDatabase(keyId);
  const decrypted = decrypt(encrypted, key, "aes-256-gcm");
  return decrypted;
}

// 5. API 请求验证
async function verifyRequest(token: string) {
  try {
    const payload = await verifyJWT(token, process.env.JWT_SECRET!);
    return payload; // { userId, username, ... }
  } catch (error) {
    throw new Error("Token 无效");
  }
}
```

---

## 📚 API 文档

### 哈希算法

- `hash(data: string, algorithm: string)`: 计算哈希值
- `verifyHash(data: string, hash: string, algorithm: string)`: 验证哈希值

**支持的算法**：`md5`、`sha1`、`sha256`、`sha512`

### 对称加密解密

- `encrypt(plaintext: string, key: Uint8Array, algorithm: string)`: 加密数据
- `decrypt(ciphertext: string, key: Uint8Array, algorithm: string)`: 解密数据
- `generateKey(algorithm: string)`: 生成密钥

**支持的算法**：`aes-128-gcm`、`aes-256-gcm`、`aes-128-cbc`、`aes-256-cbc`

### 非对称加密解密

- `generateRSAKeyPair(bits: number)`: 生成 RSA 密钥对
- `encryptRSA(plaintext: string, publicKey: CryptoKey)`: 公钥加密（使用 RSA-OAEP 算法）
- `decryptRSA(ciphertext: string, privateKey: CryptoKey)`: 私钥解密（使用 RSA-OAEP 算法）

### 数字签名

- `sign(data: string, privateKey: CryptoKey, algorithm: string)`: 签名数据
- `verify(data: string, signature: string, publicKey: CryptoKey, algorithm: string)`: 验证签名

**支持的算法**：`rsa-sha256`、`ecdsa-sha256`

### 密码哈希

- `hashPassword(password: string, algorithm: string, options?)`: 哈希密码
- `verifyPassword(password: string, hashed: string)`: 验证密码

**支持的算法**：`bcrypt`、`argon2id`、`argon2i`、`argon2d`

### JWT

- `signJWT(payload: object, secret: string | CryptoKey, options?)`: 生成 JWT Token
- `verifyJWT(token: string, secret: string | CryptoKey)`: 验证 JWT Token
- `decodeJWT(token: string)`: 解码 JWT Token（不验证）

**支持的算法**：`HS256`、`HS384`、`HS512`、`RS256`、`RS384`、`RS512`、`ES256`、`ES384`、`ES512`

### 随机数生成

- `generateRandomBytes(length: number)`: 生成随机字节
- `generateRandomString(length: number)`: 生成随机字符串
- `generateRandomInt(min: number, max: number)`: 生成随机整数
- `generateUUID()`: 生成 UUID v4

---

## ⚠️ 安全注意事项

### 密钥管理

- ✅ **密钥存储**：密钥应存储在安全的地方（环境变量、密钥管理服务）
- ✅ **密钥轮换**：定期更换密钥，特别是对称加密密钥
- ✅ **密钥长度**：使用足够长的密钥（AES 至少 256 位，RSA 至少 2048 位）
- ❌ **不要硬编码密钥**：不要在代码中硬编码密钥
- ❌ **不要提交密钥**：不要将密钥提交到版本控制系统

### 密码哈希

- ✅ **使用专用算法**：使用 bcrypt 或 argon2，不要使用普通哈希算法（MD5、SHA256）
- ✅ **足够的成本参数**：bcrypt rounds 至少 10，argon2 根据性能调整
- ✅ **加盐**：算法会自动加盐，不需要手动加盐
- ❌ **不要使用 MD5/SHA256**：这些算法不适合密码哈希

### 加密算法选择

- ✅ **对称加密**：大量数据使用 AES-256-GCM（推荐）
- ✅ **非对称加密**：密钥交换使用 RSA-OAEP（推荐）
- ✅ **数字签名**：使用 RSA 或 ECDSA
- ❌ **避免弱算法**：避免使用 DES、RC4 等弱算法

### JWT 安全

- ✅ **使用强密钥**：HS256 至少 256 位，RS256 至少 2048 位
- ✅ **设置过期时间**：所有 Token 都应该有过期时间
- ✅ **验证签名**：始终验证 Token 签名
- ❌ **不要在客户端存储敏感信息**：JWT 载荷可以被解码（但不验证签名）

---

## 📝 备注

- 所有加密操作都是异步的，使用 `await` 等待结果
- 密钥和敏感数据应安全存储，不要硬编码
- 生产环境建议使用密钥管理服务（如 AWS KMS、Azure Key Vault）
- 定期更新加密算法和密钥，保持安全性

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📄 许可证

MIT License - 详见 [LICENSE.md](./LICENSE.md)

---

<div align="center">

**Made with ❤️ by Dreamer Team**

</div>
