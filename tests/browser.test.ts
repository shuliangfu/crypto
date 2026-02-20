/**
 * @fileoverview 使用 @dreamer/test 浏览器测试集成，在浏览器环境中测试 crypto client 的加密能力
 * （hash、verifyHash、generateUUID、AES 加解密、JWT 签名与验证等）
 */

import {
  afterAll,
  beforeAll,
  cleanupAllBrowsers,
  describe,
  expect,
  it,
} from "@dreamer/test";

const browserConfig = {
  sanitizeOps: false,
  sanitizeResources: false,
  timeout: 60_000,
  browser: {
    enabled: true,
    browserSource: "test" as const,
    entryPoint: "./tests/browser-entry.ts",
    globalName: "CryptoClient",
    browserMode: false,
    moduleLoadTimeout: 45_000,
    headless: true,
    reuseBrowser: true,
  },
};

describe("Crypto client - 浏览器环境测试", () => {
  beforeAll(async () => {
    // 由 @dreamer/test 自动创建/复用浏览器上下文，无需手动创建
  });

  afterAll(async () => {
    await cleanupAllBrowsers();
  });

  it("应在浏览器中挂载 CryptoClient 并具备全部客户端 API", async (t) => {
    const result = await t!.browser!.evaluate(() => {
      const C =
        (globalThis as unknown as { CryptoClient: Record<string, unknown> })
          .CryptoClient;
      if (!C) return { ok: false, error: "CryptoClient 未定义" };
      return {
        ok: true,
        hasHash: typeof C.hash === "function",
        hasVerifyHash: typeof C.verifyHash === "function",
        hasGenerateRandomBytes: typeof C.generateRandomBytes === "function",
        hasGenerateRandomString: typeof C.generateRandomString === "function",
        hasGenerateRandomInt: typeof C.generateRandomInt === "function",
        hasGenerateUUID: typeof C.generateUUID === "function",
        hasGenerateKey: typeof C.generateKey === "function",
        hasImportAESKey: typeof C.importAESKey === "function",
        hasEncrypt: typeof C.encrypt === "function",
        hasDecrypt: typeof C.decrypt === "function",
        hasGenerateRSAKeyPair: typeof C.generateRSAKeyPair === "function",
        hasGenerateRSASigningKeyPair:
          typeof C.generateRSASigningKeyPair === "function",
        hasEncryptRSA: typeof C.encryptRSA === "function",
        hasDecryptRSA: typeof C.decryptRSA === "function",
        hasSign: typeof C.sign === "function",
        hasVerify: typeof C.verify === "function",
        hasSignJWT: typeof C.signJWT === "function",
        hasVerifyJWT: typeof C.verifyJWT === "function",
        hasDecodeJWT: typeof C.decodeJWT === "function",
        hasHashPassword: typeof C.hashPassword === "function",
        hasVerifyPassword: typeof C.verifyPassword === "function",
      };
    });
    expect(result.ok).toBe(true);
    expect(result.hasHash).toBe(true);
    expect(result.hasVerifyHash).toBe(true);
    expect(result.hasGenerateRandomBytes).toBe(true);
    expect(result.hasGenerateRandomString).toBe(true);
    expect(result.hasGenerateRandomInt).toBe(true);
    expect(result.hasGenerateUUID).toBe(true);
    expect(result.hasGenerateKey).toBe(true);
    expect(result.hasImportAESKey).toBe(true);
    expect(result.hasEncrypt).toBe(true);
    expect(result.hasDecrypt).toBe(true);
    expect(result.hasGenerateRSAKeyPair).toBe(true);
    expect(result.hasGenerateRSASigningKeyPair).toBe(true);
    expect(result.hasEncryptRSA).toBe(true);
    expect(result.hasDecryptRSA).toBe(true);
    expect(result.hasSign).toBe(true);
    expect(result.hasVerify).toBe(true);
    expect(result.hasSignJWT).toBe(true);
    expect(result.hasVerifyJWT).toBe(true);
    expect(result.hasDecodeJWT).toBe(true);
    expect(result.hasHashPassword).toBe(true);
    expect(result.hasVerifyPassword).toBe(true);
  }, browserConfig);

  it("应在浏览器中正确计算 SHA256 哈希", async (t) => {
    const result = await t!.browser!.evaluate(async () => {
      const C = (globalThis as unknown as {
        CryptoClient: {
          hash: (data: string, alg: string) => Promise<string>;
        };
      }).CryptoClient;
      const h = await C.hash("hello", "sha256");
      return { hash: h, length: h?.length ?? 0 };
    });
    expect(result.hash).toBeDefined();
    expect(typeof result.hash).toBe("string");
    // SHA256 hex 长度为 64
    expect(result.length).toBe(64);
  }, browserConfig);

  it("应在浏览器中正确校验哈希 verifyHash", async (t) => {
    const result = await t!.browser!.evaluate(async () => {
      const C = (globalThis as unknown as {
        CryptoClient: {
          hash: (data: string, alg: string) => Promise<string>;
          verifyHash: (
            data: string,
            hashed: string,
            alg: string,
          ) => Promise<boolean>;
        };
      }).CryptoClient;
      const data = "verify-me";
      const hashed = await C.hash(data, "sha256");
      const valid = await C.verifyHash(data, hashed, "sha256");
      const invalid = await C.verifyHash("wrong", hashed, "sha256");
      return { valid, invalid };
    });
    expect(result.valid).toBe(true);
    expect(result.invalid).toBe(false);
  }, browserConfig);

  it("应在浏览器中生成不重复的 UUID", async (t) => {
    const result = await t!.browser!.evaluate(() => {
      const C = (globalThis as unknown as {
        CryptoClient: { generateUUID: () => string };
      }).CryptoClient;
      const u1 = C.generateUUID();
      const u2 = C.generateUUID();
      const uuidRe =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      return {
        u1,
        u2,
        different: u1 !== u2,
        format1: uuidRe.test(u1),
        format2: uuidRe.test(u2),
      };
    });
    expect(result.u1).toBeDefined();
    expect(result.u2).toBeDefined();
    expect(result.different).toBe(true);
    expect(result.format1).toBe(true);
    expect(result.format2).toBe(true);
  }, browserConfig);

  it("应在浏览器中完成 AES-256-GCM 加密与解密", async (t) => {
    const result = await t!.browser!.evaluate(async () => {
      const C = (globalThis as unknown as {
        CryptoClient: {
          generateKey: (alg: string) => Promise<CryptoKey>;
          encrypt: (
            plain: string,
            key: CryptoKey,
            alg: string,
          ) => Promise<string>;
          decrypt: (
            cipher: string,
            key: CryptoKey,
            alg: string,
          ) => Promise<string>;
        };
      }).CryptoClient;
      const key = await C.generateKey("aes-256");
      const plain = "secret-message";
      const cipher = await C.encrypt(plain, key, "aes-256-gcm");
      const decrypted = await C.decrypt(cipher, key, "aes-256-gcm");
      return { decrypted, match: decrypted === plain };
    });
    expect(result.decrypted).toBe("secret-message");
    expect(result.match).toBe(true);
  }, browserConfig);

  it("应在浏览器中完成 JWT 签名与验证", async (t) => {
    const result = await t!.browser!.evaluate(async () => {
      const C = (globalThis as unknown as {
        CryptoClient: {
          signJWT: (
            payload: Record<string, unknown>,
            secret: string,
            opts?: { algorithm?: string },
          ) => Promise<string>;
          verifyJWT: (
            token: string,
            secret: string,
          ) => Promise<Record<string, unknown>>;
        };
      }).CryptoClient;
      const secret = "my-secret";
      const token = await C.signJWT({ sub: "user-1" }, secret, {
        algorithm: "HS256",
      });
      const payload = await C.verifyJWT(token, secret);
      return { sub: payload.sub, hasIat: "iat" in payload };
    });
    expect(result.sub).toBe("user-1");
    expect(result.hasIat).toBe(true);
  }, browserConfig);

  it(
    "应在浏览器中正确使用 generateRandomBytes / generateRandomString / generateRandomInt",
    async (t) => {
      const result = await t!.browser!.evaluate(() => {
        const C = (globalThis as unknown as {
          CryptoClient: {
            generateRandomBytes: (n: number) => Uint8Array;
            generateRandomString: (n: number, charset?: string) => string;
            generateRandomInt: (min: number, max: number) => number;
          };
        }).CryptoClient;
        const bytes = C.generateRandomBytes(32);
        const str = C.generateRandomString(16);
        const num = C.generateRandomInt(10, 100);
        return {
          bytesLength: bytes.length,
          strLength: str.length,
          numInRange: num >= 10 && num < 100,
        };
      });
      expect(result.bytesLength).toBe(32);
      expect(result.strLength).toBe(16);
      expect(result.numInRange).toBe(true);
    },
    browserConfig,
  );

  it("应在浏览器中正确使用 decodeJWT", async (t) => {
    const result = await t!.browser!.evaluate(async () => {
      const C = (globalThis as unknown as {
        CryptoClient: {
          signJWT: (
            p: Record<string, unknown>,
            s: string,
            o?: { algorithm?: string },
          ) => Promise<string>;
          decodeJWT: (
            token: string,
          ) => {
            header: Record<string, unknown>;
            payload: Record<string, unknown>;
            signature: string;
          };
        };
      }).CryptoClient;
      const token = await C.signJWT({ sub: "decode-test" }, "secret", {
        algorithm: "HS256",
      });
      const decoded = C.decodeJWT(token);
      return {
        typ: decoded.header.typ,
        alg: decoded.header.alg,
        sub: decoded.payload.sub,
        hasSignature: decoded.signature.length > 0,
      };
    });
    expect(result.typ).toBe("JWT");
    expect(result.alg).toBe("HS256");
    expect(result.sub).toBe("decode-test");
    expect(result.hasSignature).toBe(true);
  }, browserConfig);

  it(
    "应在浏览器中 hashPassword / verifyPassword 抛出需要外部库的错误",
    async (t) => {
      const result = await t!.browser!.evaluate(async () => {
        const C = (globalThis as unknown as {
          CryptoClient: {
            hashPassword: (p: string, a?: string) => Promise<string>;
            verifyPassword: (p: string, h: string) => Promise<boolean>;
          };
        }).CryptoClient;
        let hashErr = "";
        let verifyErr = "";
        try {
          await C.hashPassword("pwd", "bcrypt");
        } catch (e) {
          hashErr = (e as Error).message;
        }
        try {
          await C.verifyPassword("pwd", "hash");
        } catch (e) {
          verifyErr = (e as Error).message;
        }
        return { hashErr, verifyErr };
      });
      expect(result.hashErr).toContain("external library");
      expect(result.verifyErr).toContain("external library");
    },
    browserConfig,
  );

  it(
    "应在浏览器中使用 Uint8Array 密钥完成 AES 加解密（importAESKey）",
    async (t) => {
      const result = await t!.browser!.evaluate(async () => {
        const C = (globalThis as unknown as {
          CryptoClient: {
            generateRandomBytes: (n: number) => Uint8Array;
            importAESKey: (raw: Uint8Array, alg: string) => Promise<CryptoKey>;
            encrypt: (
              plain: string,
              key: CryptoKey | Uint8Array,
              alg: string,
            ) => Promise<string>;
            decrypt: (
              cipher: string,
              key: CryptoKey | Uint8Array,
              alg: string,
            ) => Promise<string>;
          };
        }).CryptoClient;
        const raw = C.generateRandomBytes(32);
        const plain = "raw-key-secret";
        const cipher = await C.encrypt(plain, raw, "aes-256-gcm");
        const decrypted = await C.decrypt(cipher, raw, "aes-256-gcm");
        return { decrypted, match: decrypted === plain };
      });
      expect(result.decrypted).toBe("raw-key-secret");
      expect(result.match).toBe(true);
    },
    browserConfig,
  );

  it("应在浏览器中完成 RSA 加解密 roundtrip", async (t) => {
    const result = await t!.browser!.evaluate(async () => {
      const C = (globalThis as unknown as {
        CryptoClient: {
          generateRSAKeyPair: () => Promise<
            { publicKey: CryptoKey; privateKey: CryptoKey }
          >;
          encryptRSA: (plain: string, pub: CryptoKey) => Promise<string>;
          decryptRSA: (cipher: string, priv: CryptoKey) => Promise<string>;
        };
      }).CryptoClient;
      const { publicKey, privateKey } = await C.generateRSAKeyPair();
      const plain = "rsa-secret";
      const cipher = await C.encryptRSA(plain, publicKey);
      const decrypted = await C.decryptRSA(cipher, privateKey);
      return { decrypted, match: decrypted === plain };
    });
    expect(result.decrypted).toBe("rsa-secret");
    expect(result.match).toBe(true);
  }, browserConfig);

  it("应在浏览器中完成 RSA 签名与验证 roundtrip", async (t) => {
    const result = await t!.browser!.evaluate(async () => {
      const C = (globalThis as unknown as {
        CryptoClient: {
          generateRSASigningKeyPair: () => Promise<
            { publicKey: CryptoKey; privateKey: CryptoKey }
          >;
          sign: (data: string, priv: CryptoKey, alg: string) => Promise<string>;
          verify: (
            data: string,
            sig: string,
            pub: CryptoKey,
            alg: string,
          ) => Promise<boolean>;
        };
      }).CryptoClient;
      const { publicKey, privateKey } = await C.generateRSASigningKeyPair();
      const data = "signed-message";
      const sig = await C.sign(data, privateKey, "rsa-sha256");
      const valid = await C.verify(data, sig, publicKey, "rsa-sha256");
      const invalid = await C.verify("tampered", sig, publicKey, "rsa-sha256");
      return { valid, invalid };
    });
    expect(result.valid).toBe(true);
    expect(result.invalid).toBe(false);
  }, browserConfig);
}, browserConfig);
