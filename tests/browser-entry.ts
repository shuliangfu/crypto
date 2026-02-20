/**
 * @fileoverview 浏览器测试入口：重导出 client，供 @dreamer/test 以 globalName CryptoClient 打包；
 * 设置 testReady，runner 据此判断 bundle 已加载完成。
 */
export * from "../src/client/mod.ts";

const g = globalThis as unknown as Record<string, unknown>;
g.testReady = true;
