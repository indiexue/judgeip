import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';

// Load isolated instances so in-memory caches cannot hide upstream failure cases.
export async function loadTs(path) {
  const url = new URL(path, import.meta.url);
  const source = stripTypeScriptTypes(await readFile(url, 'utf8'), { mode: 'transform' });
  const code = source.replace(/from (['"])(\.[^'"]+)\1/g, (_, quote, relative) => {
    const target = new URL(relative.endsWith('.ts') ? relative : relative + '.ts', url);
    return `from ${quote}${target.href}${quote}`;
  });
  return import('data:text/javascript;base64,' + Buffer.from(code + '\n//' + Math.random()).toString('base64'));
}
