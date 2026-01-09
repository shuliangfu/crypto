/**
 * @module @dreamer/crypto
 *
 * @dreamer/crypto 加密和安全工具库
 *
 * 提供哈希、加密解密、签名验证、JWT 等功能，基于 Web Crypto API 标准。
 *
 * 特性：
 * - 哈希算法（SHA1、SHA256、SHA512、SHA3-256、SHA3-512）
 * - 对称加密解密（AES）
 * - 非对称加密解密（RSA）
 * - 数字签名（RSA、ECDSA）
 * - 随机数生成
 * - 密码哈希（bcrypt、argon2，需要外部库）
 * - JWT（JSON Web Token）
 * - 密钥生成和管理
 *
 * 环境兼容性：
 * - 服务端：✅ 支持（兼容 Deno 和 Bun 运行时，使用 Web Crypto API）
 * - 客户端：✅ 支持（浏览器环境，使用 Web Crypto API）
 *
 * @example
 * ```typescript
 * import { hash, encrypt, decrypt, generateKey } from "jsr:@dreamer/crypto";
 *
 * // 计算哈希
 * const hashValue = await hash("数据", "sha256");
 *
 * // 加密解密
 * const key = await generateKey("aes-256");
 * const encrypted = await encrypt("敏感数据", key, "aes-256-gcm");
 * const decrypted = await decrypt(encrypted, key, "aes-256-gcm");
 * ```
 */

/**
 * 哈希算法类型
 */
export type HashAlgorithm =
  | "md5"
  | "sha1"
  | "sha256"
  | "sha512";

/**
 * 对称加密算法类型
 */
export type SymmetricAlgorithm =
  | "aes-128-gcm"
  | "aes-256-gcm"
  | "aes-128-cbc"
  | "aes-256-cbc";

/**
 * 非对称加密算法类型
 */
export type AsymmetricAlgorithm = "rsa-oaep";

/**
 * 签名算法类型
 */
export type SignatureAlgorithm =
  | "rsa-sha256"
  | "rsa-sha384"
  | "rsa-sha512"
  | "ecdsa-sha256"
  | "ecdsa-sha384"
  | "ecdsa-sha512";

/**
 * 密码哈希算法类型
 */
export type PasswordHashAlgorithm =
  | "bcrypt"
  | "argon2id"
  | "argon2i"
  | "argon2d";

/**
 * 密码哈希选项
 */
export interface PasswordHashOptions {
  /** bcrypt rounds（4-31，默认 10） */
  rounds?: number;
  /** argon2 内存成本（默认 65536，64 MB） */
  memoryCost?: number;
  /** argon2 时间成本（默认 3） */
  timeCost?: number;
  /** argon2 并行度（默认 4） */
  parallelism?: number;
}

/**
 * JWT 选项
 */
export interface JWTOptions {
  /** 算法（默认 HS256） */
  algorithm?:
    | "HS256"
    | "HS384"
    | "HS512"
    | "RS256"
    | "RS384"
    | "RS512"
    | "ES256"
    | "ES384"
    | "ES512";
  /** 过期时间（如 "1h", "24h", "7d"） */
  expiresIn?: string;
  /** 签发者 */
  issuer?: string;
  /** 受众 */
  audience?: string;
  /** 主题 */
  subject?: string;
  /** 签发时间 */
  issuedAt?: Date;
  /** 生效时间 */
  notBefore?: Date;
}

/**
 * JWT 载荷
 */
export interface JWTPayload {
  [key: string]: unknown;
  /** 签发者 */
  iss?: string;
  /** 受众 */
  aud?: string;
  /** 主题 */
  sub?: string;
  /** 过期时间（Unix 时间戳） */
  exp?: number;
  /** 生效时间（Unix 时间戳） */
  nbf?: number;
  /** 签发时间（Unix 时间戳） */
  iat?: number;
}

/**
 * 将字符串转换为 ArrayBuffer
 */
function stringToArrayBuffer(str: string): ArrayBuffer {
  return new TextEncoder().encode(str).buffer;
}

/**
 * 将 ArrayBuffer 转换为字符串
 */
function arrayBufferToString(buffer: ArrayBuffer): string {
  return new TextDecoder().decode(buffer);
}

/**
 * 将 ArrayBuffer 转换为 Base64
 */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * 将 Base64 转换为 ArrayBuffer
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * 将 ArrayBuffer 转换为十六进制字符串
 */
function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * 将十六进制字符串转换为 ArrayBuffer
 */
function _hexToArrayBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

/**
 * 获取 Web Crypto API 的哈希算法名称
 */
function getWebCryptoHashAlgorithm(algorithm: HashAlgorithm): string {
  switch (algorithm) {
    case "md5":
      throw new Error("MD5 不支持 Web Crypto API，请使用其他算法");
    case "sha1":
      return "SHA-1";
    case "sha256":
      return "SHA-256";
    case "sha512":
      return "SHA-512";
    default:
      throw new Error(`不支持的哈希算法: ${algorithm}`);
  }
}

/**
 * 计算哈希值
 *
 * @param data 要哈希的数据
 * @param algorithm 哈希算法
 * @returns 十六进制哈希值
 */
export async function hash(
  data: string,
  algorithm: HashAlgorithm = "sha256",
): Promise<string> {
  const crypto = globalThis.crypto;
  const dataBuffer = stringToArrayBuffer(data);
  const hashBuffer = await crypto.subtle.digest(
    getWebCryptoHashAlgorithm(algorithm),
    dataBuffer,
  );
  return arrayBufferToHex(hashBuffer);
}

/**
 * 验证哈希值
 *
 * @param data 原始数据
 * @param hashValue 哈希值
 * @param algorithm 哈希算法
 * @returns 是否匹配
 */
export async function verifyHash(
  data: string,
  hashValue: string,
  algorithm: HashAlgorithm = "sha256",
): Promise<boolean> {
  const computedHash = await hash(data, algorithm);
  return computedHash === hashValue;
}

/**
 * 生成随机字节
 *
 * @param length 字节长度
 * @returns 随机字节数组
 */
export function generateRandomBytes(length: number): Uint8Array {
  const crypto = globalThis.crypto;
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * 生成随机字符串
 *
 * @param length 字符串长度
 * @param charset 字符集（默认：字母数字）
 * @returns 随机字符串
 */
export function generateRandomString(
  length: number,
  charset: string =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
): string {
  const bytes = generateRandomBytes(length);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += charset[bytes[i] % charset.length];
  }
  return result;
}

/**
 * 生成随机整数
 *
 * @param min 最小值（包含）
 * @param max 最大值（不包含）
 * @returns 随机整数
 */
export function generateRandomInt(min: number, max: number): number {
  const crypto = globalThis.crypto;
  const range = max - min;
  const maxValid = Math.floor(256 / range) * range - 1;
  let randomValue: number;
  do {
    randomValue = crypto.getRandomValues(new Uint8Array(1))[0];
  } while (randomValue > maxValid);
  return min + (randomValue % range);
}

/**
 * 生成 UUID v4
 *
 * @returns UUID 字符串
 */
export function generateUUID(): string {
  const crypto = globalThis.crypto;
  return crypto.randomUUID();
}

/**
 * 生成 AES 密钥
 *
 * @param algorithm 算法（aes-128 或 aes-256）
 * @returns CryptoKey
 */
export async function generateKey(
  algorithm: "aes-128" | "aes-256",
): Promise<CryptoKey> {
  const crypto = globalThis.crypto;
  const keyLength = algorithm === "aes-128" ? 128 : 256;
  return await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: keyLength,
    },
    true,
    ["encrypt", "decrypt"],
  );
}

/**
 * 从字节数组导入 AES 密钥
 *
 * @param keyData 密钥数据
 * @param algorithm 算法
 * @returns CryptoKey
 */
export async function importAESKey(
  keyData: Uint8Array,
  algorithm: SymmetricAlgorithm = "aes-256-gcm",
): Promise<CryptoKey> {
  const crypto = globalThis.crypto;
  const keyLength = algorithm.includes("128") ? 128 : 256;
  // 确保 keyData 基于 ArrayBuffer，创建一个新的 Uint8Array 副本
  const keyBuffer = new Uint8Array(keyData);
  return await crypto.subtle.importKey(
    "raw",
    keyBuffer,
    {
      name: algorithm.includes("gcm") ? "AES-GCM" : "AES-CBC",
      length: keyLength,
    },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * 对称加密
 *
 * @param plaintext 明文
 * @param key 密钥（CryptoKey 或 Uint8Array）
 * @param algorithm 算法
 * @returns Base64 编码的加密数据
 */
export async function encrypt(
  plaintext: string,
  key: CryptoKey | Uint8Array,
  algorithm: SymmetricAlgorithm = "aes-256-gcm",
): Promise<string> {
  const crypto = globalThis.crypto;
  let cryptoKey: CryptoKey;

  if (key instanceof CryptoKey) {
    cryptoKey = key;
  } else {
    cryptoKey = await importAESKey(key, algorithm);
  }

  const plaintextBuffer = stringToArrayBuffer(plaintext);
  const ivBytes = generateRandomBytes(algorithm.includes("gcm") ? 12 : 16); // GCM 使用 12 字节，CBC 使用 16 字节
  // 创建一个新的 Uint8Array 副本以确保基于 ArrayBuffer
  const iv = new Uint8Array(ivBytes);

  const encrypted = await crypto.subtle.encrypt(
    {
      name: algorithm.includes("gcm") ? "AES-GCM" : "AES-CBC",
      iv: iv,
    },
    cryptoKey,
    plaintextBuffer,
  );

  // 将 IV 和加密数据组合在一起
  const combined = new Uint8Array(ivBytes.length + encrypted.byteLength);
  combined.set(ivBytes, 0);
  combined.set(new Uint8Array(encrypted), ivBytes.length);

  return arrayBufferToBase64(combined.buffer);
}

/**
 * 对称解密
 *
 * @param ciphertext Base64 编码的加密数据
 * @param key 密钥（CryptoKey 或 Uint8Array）
 * @param algorithm 算法
 * @returns 明文
 */
export async function decrypt(
  ciphertext: string,
  key: CryptoKey | Uint8Array,
  algorithm: SymmetricAlgorithm = "aes-256-gcm",
): Promise<string> {
  const crypto = globalThis.crypto;
  let cryptoKey: CryptoKey;

  if (key instanceof CryptoKey) {
    cryptoKey = key;
  } else {
    cryptoKey = await importAESKey(key, algorithm);
  }

  const combined = base64ToArrayBuffer(ciphertext);
  const ivLength = algorithm.includes("gcm") ? 12 : 16;
  const ivView = new Uint8Array(combined, 0, ivLength);
  // 创建一个新的 Uint8Array 副本以确保基于 ArrayBuffer
  const iv = new Uint8Array(ivView);
  const encrypted = new Uint8Array(combined, ivLength);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: algorithm.includes("gcm") ? "AES-GCM" : "AES-CBC",
      iv: iv,
    },
    cryptoKey,
    encrypted,
  );

  return arrayBufferToString(decrypted);
}

/**
 * 生成 RSA 密钥对（用于加密/解密）
 *
 * @param modulusLength 模长（默认 2048）
 * @returns 密钥对
 */
export async function generateRSAKeyPair(
  modulusLength: number = 2048,
): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }> {
  const crypto = globalThis.crypto;
  return await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );
}

/**
 * 生成 RSA 签名密钥对（用于签名/验证）
 *
 * @param modulusLength 模长（默认 2048）
 * @returns 密钥对
 */
export async function generateRSASigningKeyPair(
  modulusLength: number = 2048,
): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }> {
  const crypto = globalThis.crypto;
  return await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
}

/**
 * 生成 ECDSA 密钥对
 *
 * @param namedCurve 曲线名称（默认 P-256）
 * @returns 密钥对
 */
export async function generateECDSAKeyPair(
  namedCurve: "P-256" | "P-384" | "P-521" = "P-256",
): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }> {
  const crypto = globalThis.crypto;
  return await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: namedCurve,
    },
    true,
    ["sign", "verify"],
  );
}

/**
 * RSA 加密（使用 RSA-OAEP 算法）
 *
 * @param plaintext 明文
 * @param publicKey 公钥
 * @returns Base64 编码的加密数据
 */
export async function encryptRSA(
  plaintext: string,
  publicKey: CryptoKey,
): Promise<string> {
  const crypto = globalThis.crypto;
  const plaintextBuffer = stringToArrayBuffer(plaintext);

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    plaintextBuffer,
  );

  return arrayBufferToBase64(encrypted);
}

/**
 * RSA 解密（使用 RSA-OAEP 算法）
 *
 * @param ciphertext Base64 编码的加密数据
 * @param privateKey 私钥
 * @returns 明文
 */
export async function decryptRSA(
  ciphertext: string,
  privateKey: CryptoKey,
): Promise<string> {
  const crypto = globalThis.crypto;
  const encrypted = base64ToArrayBuffer(ciphertext);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    encrypted,
  );

  return arrayBufferToString(decrypted);
}

/**
 * 数字签名
 *
 * @param data 要签名的数据
 * @param privateKey 私钥
 * @param algorithm 签名算法
 * @returns Base64 编码的签名
 */
export async function sign(
  data: string,
  privateKey: CryptoKey,
  algorithm: SignatureAlgorithm = "rsa-sha256",
): Promise<string> {
  const crypto = globalThis.crypto;
  const dataBuffer = stringToArrayBuffer(data);

  let hashAlg: string;
  let signAlg: string;

  if (algorithm.startsWith("rsa-")) {
    hashAlg = algorithm.replace("rsa-", "").toUpperCase().replace(
      "SHA",
      "SHA-",
    );
    signAlg = "RSASSA-PKCS1-v1_5";
  } else if (algorithm.startsWith("ecdsa-")) {
    hashAlg = algorithm.replace("ecdsa-", "").toUpperCase().replace(
      "SHA",
      "SHA-",
    );
    signAlg = "ECDSA";
  } else {
    throw new Error(`不支持的签名算法: ${algorithm}`);
  }

  const signature = await crypto.subtle.sign(
    {
      name: signAlg,
      hash: hashAlg,
    },
    privateKey,
    dataBuffer,
  );

  return arrayBufferToBase64(signature);
}

/**
 * 验证签名
 *
 * @param data 原始数据
 * @param signature Base64 编码的签名
 * @param publicKey 公钥
 * @param algorithm 签名算法
 * @returns 是否有效
 */
export async function verify(
  data: string,
  signature: string,
  publicKey: CryptoKey,
  algorithm: SignatureAlgorithm = "rsa-sha256",
): Promise<boolean> {
  const crypto = globalThis.crypto;
  const dataBuffer = stringToArrayBuffer(data);
  const signatureBuffer = base64ToArrayBuffer(signature);

  let hashAlg: string;
  let signAlg: string;

  if (algorithm.startsWith("rsa-")) {
    hashAlg = algorithm.replace("rsa-", "").toUpperCase().replace(
      "SHA",
      "SHA-",
    );
    signAlg = "RSASSA-PKCS1-v1_5";
  } else if (algorithm.startsWith("ecdsa-")) {
    hashAlg = algorithm.replace("ecdsa-", "").toUpperCase().replace(
      "SHA",
      "SHA-",
    );
    signAlg = "ECDSA";
  } else {
    throw new Error(`不支持的签名算法: ${algorithm}`);
  }

  return await crypto.subtle.verify(
    {
      name: signAlg,
      hash: hashAlg,
    },
    publicKey,
    signatureBuffer,
    dataBuffer,
  );
}

/**
 * Base64 URL 编码
 */
function base64UrlEncode(str: string): string {
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Base64 URL 解码
 */
function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  return base64;
}

/**
 * 解析时间字符串（如 "1h", "24h", "7d"）
 */
function parseTimeString(timeStr: string): number {
  const match = timeStr.match(/^(\d+)([smhd])$/);
  if (!match) {
    throw new Error(`无效的时间格式: ${timeStr}`);
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case "s":
      return value;
    case "m":
      return value * 60;
    case "h":
      return value * 60 * 60;
    case "d":
      return value * 24 * 60 * 60;
    default:
      throw new Error(`不支持的时间单位: ${unit}`);
  }
}

/**
 * 生成 JWT Token
 *
 * @param payload 载荷
 * @param secret 密钥（字符串或 CryptoKey）
 * @param options 选项
 * @returns JWT Token
 */
export async function signJWT(
  payload: JWTPayload,
  secret: string | CryptoKey,
  options: JWTOptions = {},
): Promise<string> {
  const algorithm = options.algorithm || "HS256";
  const now = Math.floor(Date.now() / 1000);

  // 构建 JWT 载荷
  const jwtPayload: JWTPayload = {
    ...payload,
    iat: options.issuedAt ? Math.floor(options.issuedAt.getTime() / 1000) : now,
  };

  if (options.expiresIn) {
    jwtPayload.exp = now + parseTimeString(options.expiresIn);
  }

  if (options.notBefore) {
    jwtPayload.nbf = Math.floor(options.notBefore.getTime() / 1000);
  }

  if (options.issuer) {
    jwtPayload.iss = options.issuer;
  }

  if (options.audience) {
    jwtPayload.aud = options.audience;
  }

  if (options.subject) {
    jwtPayload.sub = options.subject;
  }

  // 构建 JWT Header
  const header = {
    alg: algorithm,
    typ: "JWT",
  };

  // Base64 URL 编码 Header 和 Payload
  const encodedHeader = base64UrlEncode(
    btoa(JSON.stringify(header)).replace(/=/g, ""),
  );
  const encodedPayload = base64UrlEncode(
    btoa(JSON.stringify(jwtPayload)).replace(/=/g, ""),
  );

  // 签名
  const dataToSign = `${encodedHeader}.${encodedPayload}`;
  let signature: string;

  if (algorithm.startsWith("HS")) {
    // HMAC 签名
    const crypto = globalThis.crypto;
    let key: CryptoKey;

    if (secret instanceof CryptoKey) {
      key = secret;
    } else {
      key = await crypto.subtle.importKey(
        "raw",
        stringToArrayBuffer(secret),
        {
          name: "HMAC",
          hash: algorithm === "HS256"
            ? "SHA-256"
            : algorithm === "HS384"
            ? "SHA-384"
            : "SHA-512",
        },
        false,
        ["sign"],
      );
    }

    const signatureBuffer = await crypto.subtle.sign(
      "HMAC",
      key,
      stringToArrayBuffer(dataToSign),
    );
    signature = base64UrlEncode(arrayBufferToBase64(signatureBuffer));
  } else if (algorithm.startsWith("RS") || algorithm.startsWith("ES")) {
    // RSA 或 ECDSA 签名
    if (!(secret instanceof CryptoKey)) {
      throw new Error("RSA/ECDSA 算法需要使用 CryptoKey");
    }

    const hashAlg = algorithm === "RS256" || algorithm === "ES256"
      ? "SHA-256"
      : algorithm === "RS384" || algorithm === "ES384"
      ? "SHA-384"
      : "SHA-512";

    const signAlg = algorithm.startsWith("RS") ? "RSASSA-PKCS1-v1_5" : "ECDSA";

    const signatureBuffer = await globalThis.crypto.subtle.sign(
      {
        name: signAlg,
        hash: hashAlg,
      },
      secret,
      stringToArrayBuffer(dataToSign),
    );
    signature = base64UrlEncode(arrayBufferToBase64(signatureBuffer));
  } else {
    throw new Error(`不支持的 JWT 算法: ${algorithm}`);
  }

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

/**
 * 验证 JWT Token
 *
 * @param token JWT Token
 * @param secret 密钥（字符串或 CryptoKey）
 * @returns 解码后的载荷
 */
export async function verifyJWT(
  token: string,
  secret: string | CryptoKey,
): Promise<JWTPayload> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("无效的 JWT Token 格式");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  // 解码 Header
  const header = JSON.parse(
    atob(base64UrlDecode(encodedHeader)),
  ) as { alg: string; typ: string };

  if (header.typ !== "JWT") {
    throw new Error("无效的 JWT Token 类型");
  }

  const algorithm = header.alg;

  // 验证签名
  const dataToVerify = `${encodedHeader}.${encodedPayload}`;
  const signature = base64ToArrayBuffer(base64UrlDecode(encodedSignature));

  let isValid: boolean;

  if (algorithm.startsWith("HS")) {
    // HMAC 验证
    const crypto = globalThis.crypto;
    let key: CryptoKey;

    if (secret instanceof CryptoKey) {
      key = secret;
    } else {
      key = await crypto.subtle.importKey(
        "raw",
        stringToArrayBuffer(secret),
        {
          name: "HMAC",
          hash: algorithm === "HS256"
            ? "SHA-256"
            : algorithm === "HS384"
            ? "SHA-384"
            : "SHA-512",
        },
        false,
        ["verify"],
      );
    }

    isValid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      stringToArrayBuffer(dataToVerify),
    );
  } else if (algorithm.startsWith("RS") || algorithm.startsWith("ES")) {
    // RSA 或 ECDSA 验证
    if (!(secret instanceof CryptoKey)) {
      throw new Error("RSA/ECDSA 算法需要使用 CryptoKey");
    }

    const hashAlg = algorithm === "RS256" || algorithm === "ES256"
      ? "SHA-256"
      : algorithm === "RS384" || algorithm === "ES384"
      ? "SHA-384"
      : "SHA-512";

    const signAlg = algorithm.startsWith("RS") ? "RSASSA-PKCS1-v1_5" : "ECDSA";

    isValid = await globalThis.crypto.subtle.verify(
      {
        name: signAlg,
        hash: hashAlg,
      },
      secret,
      signature,
      stringToArrayBuffer(dataToVerify),
    );
  } else {
    throw new Error(`不支持的 JWT 算法: ${algorithm}`);
  }

  if (!isValid) {
    throw new Error("JWT Token 签名验证失败");
  }

  // 解码 Payload
  const payload = JSON.parse(
    atob(base64UrlDecode(encodedPayload)),
  ) as JWTPayload;

  // 验证过期时间
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    throw new Error("JWT Token 已过期");
  }

  // 验证生效时间
  if (payload.nbf && payload.nbf > now) {
    throw new Error("JWT Token 尚未生效");
  }

  return payload;
}

/**
 * 解码 JWT Token（不验证签名）
 *
 * @param token JWT Token
 * @returns 解码后的 Header 和 Payload
 */
export function decodeJWT(token: string): {
  header: Record<string, unknown>;
  payload: JWTPayload;
  signature: string;
} {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("无效的 JWT Token 格式");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  const header = JSON.parse(atob(base64UrlDecode(encodedHeader)));
  const payload = JSON.parse(
    atob(base64UrlDecode(encodedPayload)),
  ) as JWTPayload;

  return {
    header,
    payload,
    signature: encodedSignature,
  };
}

/**
 * 密码哈希（使用 bcrypt 或 argon2）
 *
 * 注意：Web Crypto API 不直接支持 bcrypt 和 argon2
 * 这些算法需要外部库支持，这里提供一个接口
 *
 * @param _password 密码
 * @param algorithm 算法
 * @param _options 选项
 * @returns 哈希值
 */
export function hashPassword(
  _password: string,
  algorithm: PasswordHashAlgorithm = "bcrypt",
  _options: PasswordHashOptions = {},
): Promise<string> {
  // 注意：这里需要依赖外部库来实现 bcrypt 和 argon2
  // 由于 Deno 标准库不包含这些，这里抛出错误提示
  return Promise.reject(
    new Error(
      `密码哈希算法 ${algorithm} 需要外部库支持。请使用专门的密码哈希库（如 npm:bcrypt 或 npm:argon2）`,
    ),
  );
}

/**
 * 验证密码
 *
 * @param _password 密码
 * @param _hash 哈希值
 * @returns 是否匹配
 */
export function verifyPassword(
  _password: string,
  _hash: string,
): Promise<boolean> {
  // 注意：这里需要依赖外部库来实现 bcrypt 和 argon2
  return Promise.reject(
    new Error(
      "密码验证需要外部库支持。请使用专门的密码哈希库（如 npm:bcrypt 或 npm:argon2）",
    ),
  );
}
