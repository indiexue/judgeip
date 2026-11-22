import { readFile } from 'node:fs/promises';
import { registerHooks, stripTypeScriptTypes } from 'node:module';

// Source files import each other without an extension; let Node find the .ts file behind those specifiers.
registerHooks({
  resolve(specifier, context, nextResolve) {
    try {
      return nextResolve(specifier, context);
    } catch (error) {
      if (!specifier.startsWith('.') || /\.[cm]?[jt]s$/.test(specifier)) throw error;
      return nextResolve(specifier + '.ts', context);
    }
  },
});

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
