/**
 * @module @dreamer/crypto/i18n
 *
 * @fileoverview 本包 i18n：使用 @dreamer/i18n 的 createI18n + $tr，不挂全局。
 * 支持通过 setCryptoLocale 设置语言；未设置时根据环境 LANGUAGE / LC_ALL / LANG 检测。
 * 默认语言 en-US。文案来自 src/locales/zh-CN.json、en-US.json。
 */

import {
  createI18n,
  type I18n,
  type TranslationData,
  type TranslationParams,
} from "@dreamer/i18n";
import { getEnv } from "@dreamer/runtime-adapter";
import zhCN from "./locales/zh-CN.json" with { type: "json" };
import enUS from "./locales/en-US.json" with { type: "json" };

/** 支持的 locale */
export type Locale = "zh-CN" | "en-US";

/** 默认语言 */
export const DEFAULT_LOCALE: Locale = "en-US";

const CRYPTO_LOCALES: Locale[] = ["zh-CN", "en-US"];

const LOCALE_DATA: Record<string, TranslationData> = {
  "zh-CN": zhCN as TranslationData,
  "en-US": enUS as TranslationData,
};

let cryptoI18n: I18n | null = null;

/**
 * 从环境变量检测语言（LANGUAGE > LC_ALL > LANG），无法检测或不在支持列表时返回 en-US。
 */
export function detectLocale(): Locale {
  const langEnv = getEnv("LANGUAGE") || getEnv("LC_ALL") || getEnv("LANG");
  if (!langEnv) return DEFAULT_LOCALE;

  const first = langEnv.split(/[:\s]/)[0]?.trim();
  if (!first) return DEFAULT_LOCALE;

  const match = first.match(/^([a-z]{2})[-_]([A-Z]{2})/i);
  if (match) {
    const normalized = `${match[1].toLowerCase()}-${
      match[2].toUpperCase()
    }` as Locale;
    if (CRYPTO_LOCALES.includes(normalized)) return normalized;
  }

  const primary = first.substring(0, 2).toLowerCase();
  for (const locale of CRYPTO_LOCALES) {
    if (locale.startsWith(primary + "-") || locale === primary) return locale;
  }
  return DEFAULT_LOCALE;
}

function initCryptoI18n(): void {
  if (cryptoI18n) return;
  const i18n = createI18n({
    defaultLocale: DEFAULT_LOCALE,
    fallbackBehavior: "default",
    locales: [...CRYPTO_LOCALES],
    translations: LOCALE_DATA as Record<string, TranslationData>,
  });
  i18n.setLocale(detectLocale());
  cryptoI18n = i18n;
}

initCryptoI18n();

/**
 * 设置本包当前语言（调用后 $tr 使用该语言）。
 * @param locale 如 "zh-CN" | "en-US"
 */
export function setCryptoLocale(locale: Locale): void {
  if (!cryptoI18n) initCryptoI18n();
  if (cryptoI18n) cryptoI18n.setLocale(locale);
}

/**
 * 翻译函数。未传 lang 时使用当前 locale；传 lang 时临时切换后恢复。
 * @param key 如 "error.md5NotSupported"
 * @param params 占位替换，如 { algorithm: "sha256" }
 * @param lang 可选语言
 */
export function $tr(
  key: string,
  params?: Record<string, string | number>,
  lang?: Locale,
): string {
  if (!cryptoI18n) initCryptoI18n();
  if (!cryptoI18n) return key;
  if (lang !== undefined) {
    const prev = cryptoI18n.getLocale();
    cryptoI18n.setLocale(lang);
    try {
      return cryptoI18n.t(key, params as TranslationParams);
    } finally {
      cryptoI18n.setLocale(prev);
    }
  }
  return cryptoI18n.t(key, params as TranslationParams);
}
