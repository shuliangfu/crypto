# @dreamer/crypto

> 一个兼容 Deno 和 Bun 的加密和安全工具库，提供哈希、加密解密、签名验证、JWT 等功能

[English](./README.md) | 中文 (Chinese)

[![JSR](https://jsr.io/badges/@dreamer/crypto)](https://jsr.io/@dreamer/crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE.md)
[![Tests](https://img.shields.io/badge/tests-70%20passed-brightgreen)](./TEST_REPORT.md)

---

## 🎯 功能

一个功能完整的加密和安全工具库，提供哈希算法、对称/非对称加密解密、数字签名、JWT 令牌、密码哈希、随机数生成等全面的安全功能。基于 Web Crypto API 标准实现，**全面兼容 Deno 和 Bun 运行时环境**，适用于数据加密存储、身份验证、安全通信、密码管理等各类安全场景。

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

| 环境       | 版本要求 | 状态                                                                 |
| ---------- | -------- | -------------------------------------------------------------------- |
| **Deno**   | 2.5+     | ✅ 完全支持                                                           |
| **Bun**    | 1.0+     | ✅ 完全支持                                                           |
| **服务端** | -        | ✅ 支持（兼容 Deno 和 Bun 运行时，使用 Web Crypto API）               |
| **客户端** | -        | ✅ 支持（浏览器环境，使用 Web Crypto API）                           |
| **依赖**   | -        | 📦 无外部依赖（基于 Web Crypto API 标准）                            |

---

## ✨ 特性

- **哈希算法**：
  - SHA1、SHA256、SHA512
  - 哈希验证
  - 拒绝 MD5（不安全）
- **对称加密解密（AES）**：
  - AES-128-GCM、AES-256-GCM、AES-128-CBC、AES-256-CBC
  - 密钥生成和导入
  - 支持 CryptoKey 和 Uint8Array 密钥
- **非对称加密解密（RSA）**：
  - RSA-OAEP
  - 密钥对生成（可指定模长）
- **数字签名**：
  - RSA 签名（RSA-SHA256、RSA-SHA384、RSA-SHA512）
  - ECDSA 签名（P-256、P-384、P-521）
- **随机数生成**：
  - 安全随机字节
  - 随机字符串（支持自定义字符集）
  - 随机整数
  - UUID v4
- **密码哈希**：
  - bcrypt、argon2（argon2id、argon2i、argon2d）
- **JWT（JSON Web Token）**：
  - Token 生成、验证、解码
  - 支持 HS256/384/512、RS256/384/512、ES256/384/512
- **密钥生成和管理**：
  - AES 密钥、RSA 密钥对、ECDSA 密钥对

---

## 🎯 使用场景

- **数据加密存储和传输**：敏感数据加密、数据库字段加密、API 数据传输加密
- **身份验证和授权**：JWT Token 生成和验证、会话管理
- **安全通信**：HTTPS 证书、消息加密、密钥交换
- **密码存储**：用户密码哈希存储、密码验证
- **数字签名**：文档签名、数据完整性验证、防篡改
- **安全令牌**：API 密钥生成、临时令牌、一次性密码

---

## 🚀 快速开始

### 哈希算法

```typescript
import { hash, verifyHash } from "jsr:@dreamer/crypto";

// 计算哈希值
const data = "敏感数据";
const hashValue = await hash(data, "sha256");
console.log(hashValue); // 64 位十六进制字符串

// 验证哈希值
const isValid = await verifyHash(data, hashValue, "sha256");
console.log(isValid); // true

// 支持的算法
const sha1Hash = await hash(data, "sha1");
const sha512Hash = await hash(data, "sha512");
```

### 对称加密解密（AES）

```typescript
import { encrypt, decrypt, generateKey } from "jsr:@dreamer/crypto";

// 生成密钥
const key = await generateKey("aes-256");

// 加密数据
const plaintext = "敏感数据";
const encrypted = await encrypt(plaintext, key, "aes-256-gcm");
console.log(encrypted); // base64 编码的加密数据

// 解密数据
const decrypted = await decrypt(encrypted, key, "aes-256-gcm");
console.log(decrypted); // "敏感数据"
```

### JWT

```typescript
import { signJWT, verifyJWT, decodeJWT } from "jsr:@dreamer/crypto";

const payload = { userId: 123, username: "alice", role: "admin" };
const secret = "your-secret-key";

// 生成 JWT
const token = await signJWT(payload, secret, {
  algorithm: "HS256",
  expiresIn: "1h",
  issuer: "my-app",
  audience: "api-users",
  subject: "user-123",
});

// 验证 JWT
const decoded = await verifyJWT(token, secret);
console.log(decoded); // { userId: 123, username: "alice", ... }

// 仅解码（不验证）
const decodedOnly = decodeJWT(token);
```

### 随机数生成

```typescript
import {
  generateRandomBytes,
  generateRandomString,
  generateRandomInt,
  generateUUID,
} from "jsr:@dreamer/crypto";

const randomBytes = generateRandomBytes(32);
const randomString = generateRandomString(32);
const randomInt = generateRandomInt(1, 100);
const uuid = generateUUID();
```

---

## 🎨 使用示例

### 非对称加密解密（RSA）

```typescript
import {
  generateRSAKeyPair,
  encryptRSA,
  decryptRSA,
} from "jsr:@dreamer/crypto";

// 生成 RSA 密钥对
const { publicKey, privateKey } = await generateRSAKeyPair(2048);

// 公钥加密
const plaintext = "敏感数据";
const encrypted = await encryptRSA(plaintext, publicKey);

// 私钥解密
const decrypted = await decryptRSA(encrypted, privateKey);
console.log(decrypted); // "敏感数据"
```

### 数字签名

```typescript
import {
  sign,
  verify,
  generateRSAKeyPair,
  generateECDSAKeyPair,
} from "jsr:@dreamer/crypto";

// RSA 签名
const { publicKey, privateKey } = await generateRSAKeyPair(2048);
const data = "重要文档";
const signature = await sign(data, privateKey, "rsa-sha256");
const isValid = await verify(data, signature, publicKey, "rsa-sha256");
console.log(isValid); // true

// ECDSA 签名（更高效）
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

### 密码哈希

```typescript
import { hashPassword, verifyPassword } from "jsr:@dreamer/crypto";

// bcrypt
const password = "用户密码";
const hashed = await hashPassword(password, "bcrypt", { rounds: 10 });
const isValid = await verifyPassword(password, hashed);
console.log(isValid); // true

// argon2
const argon2Hashed = await hashPassword(password, "argon2id", {
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
});
const isValidArgon2 = await verifyPassword(password, argon2Hashed);
```

### 完整应用场景示例

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
  const hashedPassword = await hashPassword(password, "bcrypt", {
    rounds: 10,
  });
  // 存储到数据库
  await saveUser({ username, password: hashedPassword });
}

// 2. 用户登录：密码验证 + JWT 生成
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
  throw new Error("密码错误");
}

// 3. 数据加密存储
async function saveSensitiveData(data: string) {
  const key = await generateKey("aes-256");
  const encrypted = await encrypt(data, key, "aes-256-gcm");
  await saveToDatabase({ encrypted }); // 密钥需单独安全存储
}

// 4. API 请求验证
async function verifyRequest(token: string) {
  const payload = await verifyJWT(token, process.env.JWT_SECRET!);
  return payload;
}
```

---

## 📚 API 文档

### 哈希算法

| 方法 | 说明 |
| ------ | ------ |
| `hash(data: string, algorithm?: HashAlgorithm): Promise<string>` | 计算哈希值 |
| `verifyHash(data: string, hash: string, algorithm: HashAlgorithm): Promise<boolean>` | 验证哈希值 |

**支持的算法**：`sha1`、`sha256`、`sha512`（MD5 已拒绝）

### 对称加密解密

| 方法 | 说明 |
| ------ | ------ |
| `encrypt(plaintext: string, key: CryptoKey \| Uint8Array, algorithm?: SymmetricAlgorithm): Promise<string>` | 加密数据 |
| `decrypt(ciphertext: string, key: CryptoKey \| Uint8Array, algorithm?: SymmetricAlgorithm): Promise<string>` | 解密数据 |
| `generateKey(algorithm: "aes-128" \| "aes-256"): Promise<CryptoKey>` | 生成 AES 密钥 |
| `importAESKey(keyData: Uint8Array, algorithm?: SymmetricAlgorithm): Promise<CryptoKey>` | 从字节导入密钥 |

**支持的算法**：`aes-128-gcm`、`aes-256-gcm`、`aes-128-cbc`、`aes-256-cbc`

### 非对称加密解密

| 方法 | 说明 |
| ------ | ------ |
| `generateRSAKeyPair(bits?: number): Promise<{ publicKey, privateKey }>` | 生成 RSA 密钥对（默认 2048） |
| `encryptRSA(plaintext: string, publicKey: CryptoKey): Promise<string>` | 公钥加密（RSA-OAEP） |
| `decryptRSA(ciphertext: string, privateKey: CryptoKey): Promise<string>` | 私钥解密 |

### 数字签名

| 方法 | 说明 |
| ------ | ------ |
| `sign(data: string, privateKey: CryptoKey, algorithm: SignatureAlgorithm): Promise<string>` | 签名数据 |
| `verify(data: string, signature: string, publicKey: CryptoKey, algorithm: SignatureAlgorithm): Promise<boolean>` | 验证签名 |

**支持的算法**：`rsa-sha256`、`rsa-sha384`、`rsa-sha512`、`ecdsa-sha256`、`ecdsa-sha384`、`ecdsa-sha512`

### 密码哈希

| 方法 | 说明 |
| ------ | ------ |
| `hashPassword(password: string, algorithm: PasswordHashAlgorithm, options?): Promise<string>` | 哈希密码 |
| `verifyPassword(password: string, hashed: string): Promise<boolean>` | 验证密码 |

**支持的算法**：`bcrypt`、`argon2id`、`argon2i`、`argon2d`

### JWT

| 方法 | 说明 |
| ------ | ------ |
| `signJWT(payload: object, secret: string \| CryptoKey, options?): Promise<string>` | 生成 JWT |
| `verifyJWT(token: string, secret: string \| CryptoKey): Promise<JWTPayload>` | 验证 JWT |
| `decodeJWT(token: string): { header, payload, signature }` | 解码 JWT（不验证） |

**支持的算法**：`HS256`、`HS384`、`HS512`、`RS256`、`RS384`、`RS512`、`ES256`、`ES384`、`ES512`

### 随机数生成

| 方法 | 说明 |
| ------ | ------ |
| `generateRandomBytes(length: number): Uint8Array` | 生成随机字节 |
| `generateRandomString(length: number, charset?: string): string` | 生成随机字符串 |
| `generateRandomInt(min: number, max: number): number` | 生成随机整数 |
| `generateUUID(): string` | 生成 UUID v4 |

---

## 🔧 高级配置

### 安全注意事项

#### 密钥管理

- ✅ **密钥存储**：密钥应存储在安全的地方（环境变量、密钥管理服务）
- ✅ **密钥轮换**：定期更换密钥，特别是对称加密密钥
- ✅ **密钥长度**：AES 至少 256 位，RSA 至少 2048 位
- ❌ **不要硬编码密钥**：不要在代码中硬编码密钥
- ❌ **不要提交密钥**：不要将密钥提交到版本控制系统

#### 密码哈希

- ✅ **使用专用算法**：使用 bcrypt 或 argon2，不要使用普通哈希（MD5、SHA256）
- ✅ **足够的成本参数**：bcrypt rounds 至少 10
- ✅ **加盐**：算法会自动加盐
- ❌ **不要使用 MD5/SHA256**：这些算法不适合密码哈希

#### 加密算法选择

- ✅ **对称加密**：大量数据使用 AES-256-GCM（推荐）
- ✅ **非对称加密**：密钥交换使用 RSA-OAEP
- ✅ **数字签名**：使用 RSA 或 ECDSA
- ❌ **避免弱算法**：避免 DES、RC4 等

#### JWT 安全

- ✅ **使用强密钥**：HS256 至少 256 位，RS256 至少 2048 位
- ✅ **设置过期时间**：所有 Token 都应该有过期时间
- ✅ **验证签名**：始终验证 Token 签名
- ❌ **不要在客户端存储敏感信息**：JWT 载荷可被解码

---

## 📊 测试报告

[![Tests](https://img.shields.io/badge/tests-70%20passed-brightgreen)](./TEST_REPORT.md)

| 指标 | 值 |
| ------ | ----- |
| **总测试数** | 70 |
| **通过** | 70 |
| **失败** | 0 |
| **通过率** | 100% |
| **测试执行时间** | ~5 秒 |
| **测试环境** | Deno 2.5+, Bun 1.0+ |

**测试覆盖**：哈希、哈希验证、随机数生成、AES 密钥、对称加解密、RSA/ECDSA 密钥对、RSA 加解密、数字签名、JWT 生成/验证/解码、边界情况与安全验证。

详细测试报告请查看 [TEST_REPORT.md](./TEST_REPORT.md)

---

## 📝 注意事项

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
