/**
 * @fileoverview Crypto 测试
 */

import { assertRejects, describe, expect, it } from "@dreamer/test";
import {
  decodeJWT,
  decrypt,
  decryptRSA,
  encrypt,
  encryptRSA,
  generateECDSAKeyPair,
  generateKey,
  generateRandomBytes,
  generateRandomInt,
  generateRandomString,
  generateRSAKeyPair,
  generateRSASigningKeyPair,
  generateUUID,
  hash,
  importAESKey,
  sign,
  signJWT,
  verify,
  verifyHash,
  verifyJWT,
} from "../src/mod.ts";

describe("Crypto", () => {
  describe("hash", () => {
    it("应该计算 SHA1 哈希", async () => {
      const result = await hash("hello", "sha1");
      expect(result).toBeTruthy();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
    });

    it("应该计算 SHA256 哈希", async () => {
      const result = await hash("hello", "sha256");
      expect(result).toBeTruthy();
      expect(typeof result).toBe("string");
      expect(result.length).toBe(64); // SHA256 输出 32 字节 = 64 十六进制字符
    });

    it("应该计算 SHA512 哈希", async () => {
      const result = await hash("hello", "sha512");
      expect(result).toBeTruthy();
      expect(typeof result).toBe("string");
      expect(result.length).toBe(128); // SHA512 输出 64 字节 = 128 十六进制字符
    });

    it("应该默认使用 SHA256", async () => {
      const result1 = await hash("hello");
      const result2 = await hash("hello", "sha256");
      expect(result1).toBe(result2);
    });

    it("应该对相同输入产生相同哈希", async () => {
      const result1 = await hash("test", "sha256");
      const result2 = await hash("test", "sha256");
      expect(result1).toBe(result2);
    });

    it("应该对不同输入产生不同哈希", async () => {
      const result1 = await hash("test1", "sha256");
      const result2 = await hash("test2", "sha256");
      expect(result1).not.toBe(result2);
    });

    it("应该拒绝 MD5 算法", async () => {
      await assertRejects(
        async () => {
          await hash("hello", "md5" as any);
        },
        Error,
        "MD5 不支持",
      );
    });
  });

  describe("verifyHash", () => {
    it("应该验证正确的哈希", async () => {
      const data = "test data";
      const hashValue = await hash(data, "sha256");
      const isValid = await verifyHash(data, hashValue, "sha256");
      expect(isValid).toBe(true);
    });

    it("应该拒绝错误的哈希", async () => {
      const data = "test data";
      const wrongHash = "wrong hash value";
      const isValid = await verifyHash(data, wrongHash, "sha256");
      expect(isValid).toBe(false);
    });

    it("应该验证不同算法的哈希", async () => {
      const data = "test data";
      const hashValue = await hash(data, "sha512");
      const isValid = await verifyHash(data, hashValue, "sha512");
      expect(isValid).toBe(true);
    });
  });

  describe("generateRandomBytes", () => {
    it("应该生成指定长度的随机字节", () => {
      const bytes = generateRandomBytes(16);
      expect(bytes.length).toBe(16);
      expect(bytes instanceof Uint8Array).toBe(true);
    });

    it("应该生成不同的随机字节", () => {
      const bytes1 = generateRandomBytes(32);
      const bytes2 = generateRandomBytes(32);
      // 虽然理论上可能相同，但概率极低
      expect(bytes1).not.toEqual(bytes2);
    });
  });

  describe("generateRandomString", () => {
    it("应该生成指定长度的随机字符串", () => {
      const str = generateRandomString(10);
      expect(str.length).toBe(10);
    });

    it("应该使用默认字符集", () => {
      const str = generateRandomString(20);
      expect(str).toMatch(/^[A-Za-z0-9]+$/);
    });

    it("应该使用自定义字符集", () => {
      const charset = "0123456789";
      const str = generateRandomString(10, charset);
      expect(str).toMatch(/^[0-9]+$/);
      expect(str.length).toBe(10);
    });

    it("应该生成不同的随机字符串", () => {
      const str1 = generateRandomString(20);
      const str2 = generateRandomString(20);
      expect(str1).not.toBe(str2);
    });
  });

  describe("generateRandomInt", () => {
    it("应该生成指定范围内的随机整数", () => {
      const value = generateRandomInt(1, 10);
      expect(value).toBeGreaterThanOrEqual(1);
      expect(value).toBeLessThan(10);
    });

    it("应该生成不同的随机整数", () => {
      const values = new Set();
      for (let i = 0; i < 100; i++) {
        values.add(generateRandomInt(1, 100));
      }
      // 应该生成多个不同的值
      expect(values.size).toBeGreaterThan(1);
    });
  });

  describe("generateUUID", () => {
    it("应该生成有效的 UUID v4", () => {
      const uuid = generateUUID();
      expect(uuid).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    });

    it("应该生成不同的 UUID", () => {
      const uuid1 = generateUUID();
      const uuid2 = generateUUID();
      expect(uuid1).not.toBe(uuid2);
    });
  });

  describe("generateKey", () => {
    it("应该生成 AES-128 密钥", async () => {
      const key = await generateKey("aes-128");
      expect(key).toBeTruthy();
      expect(key.type).toBe("secret");
      expect(key.algorithm).toBeDefined();
    });

    it("应该生成 AES-256 密钥", async () => {
      const key = await generateKey("aes-256");
      expect(key).toBeTruthy();
      expect(key.type).toBe("secret");
    });
  });

  describe("importAESKey", () => {
    it("应该从字节数组导入 AES-256-GCM 密钥", async () => {
      const keyData = generateRandomBytes(32);
      const key = await importAESKey(keyData, "aes-256-gcm");
      expect(key).toBeTruthy();
      expect(key.type).toBe("secret");
    });

    it("应该从字节数组导入 AES-128-GCM 密钥", async () => {
      const keyData = generateRandomBytes(16);
      const key = await importAESKey(keyData, "aes-128-gcm");
      expect(key).toBeTruthy();
    });

    it("应该从字节数组导入 AES-256-CBC 密钥", async () => {
      const keyData = generateRandomBytes(32);
      const key = await importAESKey(keyData, "aes-256-cbc");
      expect(key).toBeTruthy();
    });

    it("应该从字节数组导入 AES-128-CBC 密钥", async () => {
      const keyData = generateRandomBytes(16);
      const key = await importAESKey(keyData, "aes-128-cbc");
      expect(key).toBeTruthy();
    });
  });

  describe("encrypt/decrypt", () => {
    it("应该使用 AES-256-GCM 加密和解密", async () => {
      const key = await generateKey("aes-256");
      const data = "敏感数据";
      const encrypted = await encrypt(data, key, "aes-256-gcm");
      const decrypted = await decrypt(encrypted, key, "aes-256-gcm");

      expect(decrypted).toBe(data);
      expect(encrypted).not.toBe(data);
    });

    it("应该使用 AES-128-GCM 加密和解密", async () => {
      const key = await generateKey("aes-128");
      const data = "test data";
      const encrypted = await encrypt(data, key, "aes-128-gcm");
      const decrypted = await decrypt(encrypted, key, "aes-128-gcm");

      expect(decrypted).toBe(data);
    });

    it("应该使用 AES-256-CBC 加密和解密", async () => {
      // AES-CBC 需要使用 importAESKey 导入密钥，因为 generateKey 只生成 AES-GCM 密钥
      const keyData = generateRandomBytes(32);
      const key = await importAESKey(keyData, "aes-256-cbc");
      const data = "test data";
      const encrypted = await encrypt(data, key, "aes-256-cbc");
      const decrypted = await decrypt(encrypted, key, "aes-256-cbc");

      expect(decrypted).toBe(data);
    });

    it("应该使用 AES-128-CBC 加密和解密", async () => {
      // AES-CBC 需要使用 importAESKey 导入密钥，因为 generateKey 只生成 AES-GCM 密钥
      const keyData = generateRandomBytes(16);
      const key = await importAESKey(keyData, "aes-128-cbc");
      const data = "test data";
      const encrypted = await encrypt(data, key, "aes-128-cbc");
      const decrypted = await decrypt(encrypted, key, "aes-128-cbc");

      expect(decrypted).toBe(data);
    });

    it("应该使用 Uint8Array 密钥加密和解密", async () => {
      const keyData = generateRandomBytes(32);
      const data = "test data";
      const encrypted = await encrypt(data, keyData, "aes-256-gcm");
      const decrypted = await decrypt(encrypted, keyData, "aes-256-gcm");

      expect(decrypted).toBe(data);
    });

    it("应该拒绝使用错误的密钥解密", async () => {
      const key1 = await generateKey("aes-256");
      const key2 = await generateKey("aes-256");
      const data = "test data";
      const encrypted = await encrypt(data, key1, "aes-256-gcm");

      await assertRejects(
        async () => {
          await decrypt(encrypted, key2, "aes-256-gcm");
        },
        Error,
      );
    });

    it("应该拒绝使用错误的算法解密", async () => {
      const key = await generateKey("aes-256");
      const data = "test data";
      const encrypted = await encrypt(data, key, "aes-256-gcm");

      await assertRejects(
        async () => {
          await decrypt(encrypted, key, "aes-256-cbc");
        },
        Error,
      );
    });
  });

  describe("generateRSAKeyPair", () => {
    it("应该生成 RSA 密钥对（默认 2048）", async () => {
      const keyPair = await generateRSASigningKeyPair();
      expect(keyPair.publicKey).toBeTruthy();
      expect(keyPair.privateKey).toBeTruthy();
      expect(keyPair.publicKey.type).toBe("public");
      expect(keyPair.privateKey.type).toBe("private");
    });

    it("应该生成指定模长的 RSA 密钥对", async () => {
      const keyPair = await generateRSAKeyPair(4096);
      expect(keyPair.publicKey).toBeTruthy();
      expect(keyPair.privateKey).toBeTruthy();
    });
  });

  describe("generateECDSAKeyPair", () => {
    it("应该生成 P-256 ECDSA 密钥对", async () => {
      const keyPair = await generateECDSAKeyPair("P-256");
      expect(keyPair.publicKey).toBeTruthy();
      expect(keyPair.privateKey).toBeTruthy();
      expect(keyPair.publicKey.type).toBe("public");
      expect(keyPair.privateKey.type).toBe("private");
    });

    it("应该生成 P-384 ECDSA 密钥对", async () => {
      const keyPair = await generateECDSAKeyPair("P-384");
      expect(keyPair.publicKey).toBeTruthy();
      expect(keyPair.privateKey).toBeTruthy();
    });

    it("应该生成 P-521 ECDSA 密钥对", async () => {
      const keyPair = await generateECDSAKeyPair("P-521");
      expect(keyPair.publicKey).toBeTruthy();
      expect(keyPair.privateKey).toBeTruthy();
    });

    it("应该默认使用 P-256", async () => {
      const keyPair = await generateECDSAKeyPair();
      expect(keyPair.publicKey).toBeTruthy();
      expect(keyPair.privateKey).toBeTruthy();
    });
  });

  describe("encryptRSA/decryptRSA", () => {
    it("应该使用 RSA-OAEP 加密和解密", async () => {
      // 注意：需要使用 generateRSAKeyPair 生成的密钥对（用于加密），而不是 generateRSASigningKeyPair（用于签名）
      const keyPair = await generateRSAKeyPair();
      const data = "test data";
      const encrypted = await encryptRSA(data, keyPair.publicKey);
      const decrypted = await decryptRSA(encrypted, keyPair.privateKey);

      expect(decrypted).toBe(data);
    });

    it("应该拒绝使用错误的私钥解密", async () => {
      // 注意：需要使用 generateRSAKeyPair 生成的密钥对（用于加密），而不是 generateRSASigningKeyPair（用于签名）
      const keyPair1 = await generateRSAKeyPair();
      const keyPair2 = await generateRSAKeyPair();
      const data = "test data";
      const encrypted = await encryptRSA(data, keyPair1.publicKey);

      await assertRejects(
        async () => {
          await decryptRSA(encrypted, keyPair2.privateKey);
        },
        Error,
      );
    });
  });

  describe("sign/verify", () => {
    describe("RSA 签名", () => {
      it("应该使用 RSA-SHA256 签名和验证", async () => {
        const keyPair = await generateRSASigningKeyPair();
        const data = "test data";
        const signature = await sign(data, keyPair.privateKey, "rsa-sha256");
        const isValid = await verify(
          data,
          signature,
          keyPair.publicKey,
          "rsa-sha256",
        );

        expect(isValid).toBe(true);
      });

      it("应该使用 RSA-SHA384 签名和验证", async () => {
        const keyPair = await generateRSASigningKeyPair();
        const data = "test data";
        const signature = await sign(data, keyPair.privateKey, "rsa-sha384");
        const isValid = await verify(
          data,
          signature,
          keyPair.publicKey,
          "rsa-sha384",
        );

        expect(isValid).toBe(true);
      });

      it("应该使用 RSA-SHA512 签名和验证", async () => {
        const keyPair = await generateRSASigningKeyPair();
        const data = "test data";
        const signature = await sign(data, keyPair.privateKey, "rsa-sha512");
        const isValid = await verify(
          data,
          signature,
          keyPair.publicKey,
          "rsa-sha512",
        );

        expect(isValid).toBe(true);
      });

      it("应该拒绝错误的签名", async () => {
        const keyPair = await generateRSASigningKeyPair();
        const data = "test data";
        const signature = await sign(data, keyPair.privateKey, "rsa-sha256");
        const wrongData = "wrong data";
        const isValid = await verify(
          wrongData,
          signature,
          keyPair.publicKey,
          "rsa-sha256",
        );

        expect(isValid).toBe(false);
      });

      it("应该拒绝使用错误的公钥验证", async () => {
        const keyPair1 = await generateRSASigningKeyPair();
        const keyPair2 = await generateRSASigningKeyPair();
        const data = "test data";
        const signature = await sign(data, keyPair1.privateKey, "rsa-sha256");
        const isValid = await verify(
          data,
          signature,
          keyPair2.publicKey,
          "rsa-sha256",
        );

        expect(isValid).toBe(false);
      });
    });

    describe("ECDSA 签名", () => {
      it("应该使用 ECDSA-SHA256 签名和验证", async () => {
        const keyPair = await generateECDSAKeyPair("P-256");
        const data = "test data";
        const signature = await sign(data, keyPair.privateKey, "ecdsa-sha256");
        const isValid = await verify(
          data,
          signature,
          keyPair.publicKey,
          "ecdsa-sha256",
        );

        expect(isValid).toBe(true);
      });

      it("应该使用 ECDSA-SHA384 签名和验证", async () => {
        const keyPair = await generateECDSAKeyPair("P-384");
        const data = "test data";
        const signature = await sign(data, keyPair.privateKey, "ecdsa-sha384");
        const isValid = await verify(
          data,
          signature,
          keyPair.publicKey,
          "ecdsa-sha384",
        );

        expect(isValid).toBe(true);
      });

      it("应该拒绝错误的签名", async () => {
        const keyPair = await generateECDSAKeyPair("P-256");
        const data = "test data";
        const signature = await sign(data, keyPair.privateKey, "ecdsa-sha256");
        const wrongData = "wrong data";
        const isValid = await verify(
          wrongData,
          signature,
          keyPair.publicKey,
          "ecdsa-sha256",
        );

        expect(isValid).toBe(false);
      });
    });
  });

  describe("JWT", () => {
    describe("signJWT", () => {
      it("应该使用 HS256 生成 JWT", async () => {
        const secret = "test-secret";
        const payload = { userId: 123, name: "test" };
        const token = await signJWT(payload, secret, { algorithm: "HS256" });

        expect(token).toBeTruthy();
        expect(token.split(".").length).toBe(3);
      });

      it("应该使用 HS384 生成 JWT", async () => {
        const secret = "test-secret";
        const payload = { userId: 123 };
        const token = await signJWT(payload, secret, { algorithm: "HS384" });

        expect(token).toBeTruthy();
        expect(token.split(".").length).toBe(3);
      });

      it("应该使用 HS512 生成 JWT", async () => {
        const secret = "test-secret";
        const payload = { userId: 123 };
        const token = await signJWT(payload, secret, { algorithm: "HS512" });

        expect(token).toBeTruthy();
        expect(token.split(".").length).toBe(3);
      });

      it("应该默认使用 HS256", async () => {
        const secret = "test-secret";
        const payload = { userId: 123 };
        const token1 = await signJWT(payload, secret);
        const token2 = await signJWT(payload, secret, { algorithm: "HS256" });

        // 由于时间戳不同，token 会不同，但应该都能验证
        expect(token1.split(".").length).toBe(3);
        expect(token2.split(".").length).toBe(3);
      });

      it("应该包含过期时间", async () => {
        const secret = "test-secret";
        const payload = { userId: 123 };
        const token = await signJWT(payload, secret, { expiresIn: "1h" });

        const decoded = decodeJWT(token);
        expect(decoded.payload.exp).toBeDefined();
        expect(decoded.payload.exp).toBeGreaterThan(
          Math.floor(Date.now() / 1000),
        );
      });

      it("应该包含签发者", async () => {
        const secret = "test-secret";
        const payload = { userId: 123 };
        const token = await signJWT(payload, secret, { issuer: "test-issuer" });

        const decoded = decodeJWT(token);
        expect(decoded.payload.iss).toBe("test-issuer");
      });

      it("应该包含受众", async () => {
        const secret = "test-secret";
        const payload = { userId: 123 };
        const token = await signJWT(payload, secret, {
          audience: "test-audience",
        });

        const decoded = decodeJWT(token);
        expect(decoded.payload.aud).toBe("test-audience");
      });

      it("应该包含主题", async () => {
        const secret = "test-secret";
        const payload = { userId: 123 };
        const token = await signJWT(payload, secret, {
          subject: "test-subject",
        });

        const decoded = decodeJWT(token);
        expect(decoded.payload.sub).toBe("test-subject");
      });

      it("应该使用 RSA 密钥生成 JWT", async () => {
        const keyPair = await generateRSASigningKeyPair();
        const payload = { userId: 123 };
        const token = await signJWT(payload, keyPair.privateKey, {
          algorithm: "RS256",
        });

        expect(token).toBeTruthy();
        expect(token.split(".").length).toBe(3);
      });

      it("应该使用 ECDSA 密钥生成 JWT", async () => {
        const keyPair = await generateECDSAKeyPair("P-256");
        const payload = { userId: 123 };
        const token = await signJWT(payload, keyPair.privateKey, {
          algorithm: "ES256",
        });

        expect(token).toBeTruthy();
        expect(token.split(".").length).toBe(3);
      });
    });

    describe("verifyJWT", () => {
      it("应该验证有效的 HS256 JWT", async () => {
        const secret = "test-secret";
        const payload = { userId: 123, name: "test" };
        const token = await signJWT(payload, secret, { algorithm: "HS256" });
        const verified = await verifyJWT(token, secret);

        expect(verified.userId).toBe(123);
        expect(verified.name).toBe("test");
      });

      it("应该验证有效的 HS384 JWT", async () => {
        const secret = "test-secret";
        const payload = { userId: 123 };
        const token = await signJWT(payload, secret, { algorithm: "HS384" });
        const verified = await verifyJWT(token, secret);

        expect(verified.userId).toBe(123);
      });

      it("应该验证有效的 HS512 JWT", async () => {
        const secret = "test-secret";
        const payload = { userId: 123 };
        const token = await signJWT(payload, secret, { algorithm: "HS512" });
        const verified = await verifyJWT(token, secret);

        expect(verified.userId).toBe(123);
      });

      it("应该拒绝错误的密钥", async () => {
        const secret = "test-secret";
        const payload = { userId: 123 };
        const token = await signJWT(payload, secret);
        const wrongSecret = "wrong-secret";

        await assertRejects(
          async () => {
            await verifyJWT(token, wrongSecret);
          },
          Error,
          "签名验证失败",
        );
      });

      it("应该拒绝无效的 Token 格式", async () => {
        const secret = "test-secret";
        const invalidToken = "invalid.token";

        await assertRejects(
          async () => {
            await verifyJWT(invalidToken, secret);
          },
          Error,
          "无效的 JWT Token 格式",
        );
      });

      it("应该拒绝过期的 Token", async () => {
        const secret = "test-secret";
        const payload = { userId: 123 };
        // 使用已过期的时间
        const token = await signJWT(payload, secret, {
          expiresIn: "1s",
        });

        // 等待 2 秒确保过期
        await new Promise((resolve) => setTimeout(resolve, 2000));

        await assertRejects(
          async () => {
            await verifyJWT(token, secret);
          },
          Error,
          "已过期",
        );
      });

      it("应该拒绝尚未生效的 Token", async () => {
        const secret = "test-secret";
        const payload = { userId: 123 };
        const futureDate = new Date(Date.now() + 5000); // 5 秒后
        const token = await signJWT(payload, secret, {
          notBefore: futureDate,
        });

        await assertRejects(
          async () => {
            await verifyJWT(token, secret);
          },
          Error,
          "尚未生效",
        );
      });

      it("应该验证使用 RSA 密钥签名的 JWT", async () => {
        const keyPair = await generateRSASigningKeyPair();
        const payload = { userId: 123 };
        const token = await signJWT(payload, keyPair.privateKey, {
          algorithm: "RS256",
        });
        const verified = await verifyJWT(token, keyPair.publicKey);

        expect(verified.userId).toBe(123);
      });

      it("应该验证使用 ECDSA 密钥签名的 JWT", async () => {
        const keyPair = await generateECDSAKeyPair("P-256");
        const payload = { userId: 123 };
        const token = await signJWT(payload, keyPair.privateKey, {
          algorithm: "ES256",
        });
        const verified = await verifyJWT(token, keyPair.publicKey);

        expect(verified.userId).toBe(123);
      });
    });

    describe("decodeJWT", () => {
      it("应该解码 JWT Token", async () => {
        const secret = "test-secret";
        const payload = { userId: 123, name: "test" };
        const token = await signJWT(payload, secret);
        const decoded = decodeJWT(token);

        expect(decoded.header.alg).toBe("HS256");
        expect(decoded.header.typ).toBe("JWT");
        expect(decoded.payload.userId).toBe(123);
        expect(decoded.payload.name).toBe("test");
        expect(decoded.signature).toBeTruthy();
      });

      it("应该拒绝无效的 Token 格式", () => {
        expect(() => {
          decodeJWT("invalid.token");
        }).toThrow("无效的 JWT Token 格式");
      });
    });
  });
});
