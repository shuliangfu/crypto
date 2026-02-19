# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [1.0.1] - 2026-02-19

### Added

- **Internationalization (i18n)** via `@dreamer/i18n`: all runtime error
  messages (hash, signature, JWT, password hashing, time parsing) are now
  localized.
- **Locale API**: `setCryptoLocale(locale)`, `detectLocale()`, and `Locale` type
  exported from the main entry; locale is detected from `LANGUAGE` / `LC_ALL` /
  `LANG` when not set.
- **Locale files**: `src/locales/zh-CN.json` and `src/locales/en-US.json` with
  `error.*` keys for all package error messages.

### Changed

- Error messages no longer use hardcoded English strings; they use the internal
  `$tr("error.*")` so that callers can switch language with
  `setCryptoLocale("zh-CN")` or `setCryptoLocale("en-US")`.

---

## [1.0.0] - 2026-02-06

### Added

First stable release. Encryption and security utility library compatible with
Deno and Bun. Built on Web Crypto API, no external dependencies for core
features.

#### Hash

- **hash(data, algorithm?)**: Compute hash (SHA1, SHA256, SHA512)
- **verifyHash(data, hash, algorithm)**: Verify hash
- MD5 explicitly rejected (insecure)

#### Symmetric Encryption (AES)

- **encrypt / decrypt**: AES-128-GCM, AES-256-GCM, AES-128-CBC, AES-256-CBC
- **generateKey(algorithm)**: Generate AES key (aes-128, aes-256)
- **importAESKey(keyData, algorithm?)**: Import key from Uint8Array
- Support for CryptoKey and Uint8Array keys
- Automatic IV generation (12 bytes for GCM, 16 for CBC)

#### Asymmetric Encryption (RSA)

- **generateRSAKeyPair(modulusLength?)**: Generate RSA key pair (default 2048)
- **encryptRSA / decryptRSA**: RSA-OAEP encryption and decryption

#### Digital Signatures

- **sign / verify**: RSA (RSA-SHA256, RSA-SHA384, RSA-SHA512) and ECDSA (P-256,
  P-384, P-521)
- **generateRSASigningKeyPair(modulusLength?)**: RSA signing key pair
- **generateECDSAKeyPair(namedCurve?)**: ECDSA key pair (P-256, P-384, P-521)

#### Random Generation

- **generateRandomBytes(length)**: Secure random bytes
- **generateRandomString(length, charset?)**: Random string with custom charset
- **generateRandomInt(min, max)**: Random integer in range
- **generateUUID()**: UUID v4

#### JWT (JSON Web Token)

- **signJWT(payload, secret, options?)**: Sign JWT with HS256/384/512,
  RS256/384/512, ES256/384/512
- **verifyJWT(token, secret)**: Verify and decode JWT
- **decodeJWT(token)**: Decode without verification
- Options: expiresIn, issuer, audience, subject, issuedAt, notBefore

#### Password Hashing (Interface)

- **hashPassword / verifyPassword**: Interface for bcrypt and argon2 (argon2id,
  argon2i, argon2d)
- Requires external library for implementation (Web Crypto API does not support
  bcrypt/argon2)

#### Type Exports

- `HashAlgorithm`, `SymmetricAlgorithm`, `SignatureAlgorithm`,
  `PasswordHashAlgorithm`, `JWTOptions`, `JWTPayload`, `PasswordHashOptions`

#### Client Module

- **jsr:@dreamer/crypto/client**: Client-side entry for browser environments
