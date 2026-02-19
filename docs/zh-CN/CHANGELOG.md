# 变更日志

本项目的所有重要变更将记录于此。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

---

## [1.0.1] - 2026-02-19

### 新增

- **国际化 (i18n)**：通过 `@dreamer/i18n` 支持，所有运行时错误文案（哈希、签名、
  JWT、密码哈希、时间解析等）均已本地化。
- **语言 API**：主入口导出 `setCryptoLocale(locale)`、`detectLocale()` 及
  `Locale` 类型；未设置时根据环境变量 `LANGUAGE` / `LC_ALL` / `LANG` 检测语言。
- **语言包**：`src/locales/zh-CN.json` 与 `src/locales/en-US.json`，包含
  `error.*` 键对应包内所有错误文案。

### 变更

- 错误信息不再使用硬编码英文，改为内部 `$tr("error.*")`，调用方可通过
  `setCryptoLocale("zh-CN")` 或 `setCryptoLocale("en-US")` 切换语言。

---

## [1.0.0] - 2026-02-06

### 新增

首个稳定版本。兼容 Deno 与 Bun 的加密与安全工具库。基于 Web Crypto
API，核心功能无外部依赖。

#### 哈希

- **hash(data, algorithm?)**：计算哈希（SHA1、SHA256、SHA512）
- **verifyHash(data, hash, algorithm)**：验证哈希
- 明确拒绝 MD5（不安全）

#### 对称加密（AES）

- **encrypt / decrypt**：AES-128-GCM、AES-256-GCM、AES-128-CBC、AES-256-CBC
- **generateKey(algorithm)**：生成 AES 密钥（aes-128、aes-256）
- **importAESKey(keyData, algorithm?)**：从 Uint8Array 导入密钥
- 支持 CryptoKey 与 Uint8Array 密钥
- 自动生成 IV（GCM 12 字节，CBC 16 字节）

#### 非对称加密（RSA）

- **generateRSAKeyPair(modulusLength?)**：生成 RSA 密钥对（默认 2048）
- **encryptRSA / decryptRSA**：RSA-OAEP 加密与解密

#### 数字签名

- **sign / verify**：RSA（RSA-SHA256、RSA-SHA384、RSA-SHA512）与
  ECDSA（P-256、P-384、P-521）
- **generateRSASigningKeyPair(modulusLength?)**：RSA 签名密钥对
- **generateECDSAKeyPair(namedCurve?)**：ECDSA 密钥对（P-256、P-384、P-521）

#### 随机数生成

- **generateRandomBytes(length)**：安全随机字节
- **generateRandomString(length, charset?)**：随机字符串，支持自定义字符集
- **generateRandomInt(min, max)**：范围内随机整数
- **generateUUID()**：UUID v4

#### JWT（JSON Web Token）

- **signJWT(payload, secret, options?)**：使用
  HS256/384/512、RS256/384/512、ES256/384/512 签发 JWT
- **verifyJWT(token, secret)**：验证并解码 JWT
- **decodeJWT(token)**：仅解码不验证
- 选项：expiresIn、issuer、audience、subject、issuedAt、notBefore

#### 密码哈希（接口）

- **hashPassword / verifyPassword**：bcrypt 与
  argon2（argon2id、argon2i、argon2d）接口
- 需外部库实现（Web Crypto API 不支持 bcrypt/argon2）

#### 类型导出

- `HashAlgorithm`、`SymmetricAlgorithm`、`SignatureAlgorithm`、`PasswordHashAlgorithm`、`JWTOptions`、`JWTPayload`、`PasswordHashOptions`

#### 客户端模块

- **jsr:@dreamer/crypto/client**：浏览器环境客户端入口
