/**
 * 中英文切换的最小实现：中文是默认语言、没有前缀；英文页一律挂在 /en 下。
 * src/middleware.ts 剥掉 /en 前缀后改写到同一个页面，并把语言写进 Astro.locals.lang，
 * 页面与布局通过 getLang() 读取，再按语言选文案或选 snippets/en/ 下的英文版片段。
 */
export type Lang = 'zh' | 'en';

export const EN_PREFIX = '/en';

export function getLang(locals: App.Locals | undefined): Lang {
  return locals?.lang === 'en' ? 'en' : 'zh';
}

/** 站内路径加上当前语言的前缀：localePath('/ai', 'en') → '/en/ai'，localePath('/', 'en') → '/en' */
export function localePath(path: string, lang: Lang): string {
  if (lang !== 'en') return path;
  if (path === '/' || path === '') return EN_PREFIX;
  return EN_PREFIX + (path.startsWith('/') ? path : `/${path}`);
}

/** 按语言二选一，给页面里零散的短文案用 */
export function pick<T>(lang: Lang, zh: T, en: T): T {
  return lang === 'en' ? en : zh;
}

/** /en/xxx → { lang: 'en', path: '/xxx' }；其余原样返回中文 */
export function splitLocale(pathname: string): { lang: Lang; path: string } {
  if (pathname === EN_PREFIX || pathname === `${EN_PREFIX}/`) return { lang: 'en', path: '/' };
  if (pathname.startsWith(`${EN_PREFIX}/`)) return { lang: 'en', path: pathname.slice(EN_PREFIX.length) };
  return { lang: 'zh', path: pathname };
}
