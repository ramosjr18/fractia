import fs from 'fs/promises';
import path from 'path';
import { createReadStream } from 'fs';
import readline from 'readline';
import { config } from '../config.js';

// Default extensions: JS + TS (covers Express, Next.js, React, etc.)
export const JS_EXTENSIONS  = ['.js', '.mjs', '.cjs'];
export const TS_EXTENSIONS  = ['.ts', '.tsx', '.mts', '.cts'];
export const ALL_EXTENSIONS = [...JS_EXTENSIONS, ...TS_EXTENSIONS, '.jsx'];

export const PROJECT_ROOT = () => config.projectRoot;
export const BACKEND_ROOT = () => config.projectRoot;
export const BACKEND_SRC  = () => _structure ? _structure.srcDir : path.join(config.projectRoot, 'src');

let _structure = null;

export function resetStructureCache() {
  _structure = null;
}

export function getStructure() {
  return _structure;
}

export async function findFile(baseDir, candidates) {
  for (const c of candidates) {
    if (await fileExists(path.join(baseDir, c))) return c;
  }
  return null;
}

export async function findDir(baseDir, candidates) {
  for (const c of candidates) {
    try {
      const stat = await fs.stat(path.join(baseDir, c));
      if (stat.isDirectory()) return c;
    } catch {}
  }
  return null;
}

async function findUp(startDir, fileName) {
  let curr = startDir;
  while (true) {
    const p = path.join(curr, fileName);
    if (await fileExists(p)) return p;
    const parent = path.dirname(curr);
    if (parent === curr) break;
    curr = parent;
  }
  return null;
}

export async function discoverStructure(root = config.projectRoot) {
  if (_structure) return _structure;

  const result = {
    framework: 'unknown',
    typescript: false,
    srcDir: root,
    entryFile: null,
    dirs: {},
    files: {}
  };

  // 0. Determine appRoot: handles monorepos where backend lives in a subdirectory
  const BACKEND_SUBDIRS = ['backend', 'server', 'api', 'service'];
  let appRoot = root;

  const directSrc = await findDir(root, ['src', 'app', 'lib', 'source']);
  if (!directSrc) {
    for (const sub of BACKEND_SUBDIRS) {
      const subPath = path.join(root, sub);
      const hasPkg = await fileExists(path.join(subPath, 'package.json'));
      const hasSrc = await findDir(subPath, ['src', 'app', 'lib', 'source']);
      if (hasPkg || hasSrc) {
        appRoot = subPath;
        break;
      }
    }
  }

  // 1. Walk up for common root files
  result.files.packageJson = await findUp(appRoot, 'package.json');
  result.files.env = await findUp(appRoot, '.env') || await findUp(root, '.env');
  result.files.gitignore = await findUp(appRoot, '.gitignore') || await findUp(root, '.gitignore');

  // Next.js specific config files
  result.files.nextConfig = await findFile(appRoot, ['next.config.js', 'next.config.mjs', 'next.config.ts']);
  result.files.middleware = await findFile(appRoot, ['middleware.ts', 'middleware.js']);

  // 2. Framework detection (order matters: more specific first)
  if (result.files.packageJson) {
    const pkgContent = await readFile(result.files.packageJson);
    if (pkgContent) {
      try {
        const pkg = JSON.parse(pkgContent);
        const deps = { ...pkg.dependencies, ...pkg.devDependencies };

        // Detect TypeScript
        result.typescript = !!(deps.typescript || deps['@types/node'] || deps['@types/react']);

        // Detect framework (most specific first)
        if (deps.next)              result.framework = 'nextjs';
        else if (deps['@nestjs/core']) result.framework = 'nestjs';
        else if (deps.nuxt)         result.framework = 'nuxt';
        else if (deps.express)      result.framework = 'express';
        else if (deps.fastify)      result.framework = 'fastify';
        else if (deps.koa)          result.framework = 'koa';
        else if (deps['@hapi/hapi']) result.framework = 'hapi';
        else if (deps.react)        result.framework = 'react';
        else if (deps.vue)          result.framework = 'vue';
        else if (deps.svelte)       result.framework = 'svelte';
        else if (deps.angular || deps['@angular/core']) result.framework = 'angular';
      } catch {}
    }
  }

  // 3. Find srcDir within appRoot
  // For Next.js with App Router, 'app' is the primary source directory
  const srcCandidates = result.framework === 'nextjs'
    ? ['src', 'app', 'pages', 'lib', 'source']
    : ['src', 'app', 'lib', 'source'];

  const srcCandidate = directSrc || await findDir(appRoot, srcCandidates);
  if (srcCandidate && appRoot === root) {
    result.srcDir = path.join(root, srcCandidate);
  } else if (appRoot !== root) {
    const nestedSrc = await findDir(appRoot, srcCandidates);
    result.srcDir = nestedSrc ? path.join(appRoot, nestedSrc) : appRoot;
  } else {
    result.srcDir = root;
  }

  // 4. Find entry file (include TS variants)
  const entryNames = result.framework === 'nextjs'
    ? ['next.config.js', 'next.config.mjs', 'next.config.ts', 'app/layout.tsx', 'app/layout.js', 'pages/_app.tsx', 'pages/_app.js']
    : ['server.js', 'server.ts', 'app.js', 'app.ts', 'index.js', 'index.ts', 'main.js', 'main.ts'];

  const entryCandidate = await findFile(result.srcDir, entryNames);
  if (entryCandidate) {
    result.entryFile = path.join(result.srcDir, entryCandidate);
  } else {
    const appRootEntry = await findFile(appRoot, entryNames);
    if (appRootEntry) result.entryFile = path.join(appRoot, appRootEntry);
  }

  // 5. Subdirectories (include Next.js-specific dirs)
  const subDirs = [
    'controllers', 'routes', 'middleware', 'models', 'schemas',
    'services', 'workers', 'modules',
    // Next.js / React
    'components', 'hooks', 'store', 'stores', 'providers', 'utils', 'lib',
    'api',          // Next.js API routes (app/api/ or pages/api/)
    'features',     // Feature-based architecture
    'types',        // TypeScript types
  ];
  for (const d of subDirs) {
    const found = await findDir(result.srcDir, [d]);
    if (found) result.dirs[d] = path.join(result.srcDir, found);
  }

  // For Next.js, also scan the root-level directories
  if (result.framework === 'nextjs' && appRoot === root) {
    for (const d of ['components', 'lib', 'hooks', 'store', 'stores', 'utils', 'types']) {
      if (!result.dirs[d]) {
        const found = await findDir(root, [d]);
        if (found) result.dirs[d] = path.join(root, found);
      }
    }
  }

  _structure = result;
  return result;
}

/**
 * Get the appropriate file extensions based on detected project structure.
 */
export function getProjectExtensions() {
  if (_structure?.typescript) return ALL_EXTENSIONS;
  return [...JS_EXTENSIONS, '.jsx'];
}

const MAX_FILE_SIZE = 500_000; // 500KB guard

/**
 * Read a single file. Returns null if not found.
 */
export async function readFile(filePath) {
  try {
    const stat = await fs.stat(filePath);
    if (stat.size > MAX_FILE_SIZE) return null;
    return await fs.readFile(filePath, 'utf8');
  } catch {
    return null;
  }
}

/**
 * Recursively walk a directory and return all files matching extension filter.
 * Returns array of { filePath, content } objects.
 * Now defaults to ALL_EXTENSIONS (JS + TS) instead of just .js.
 */
export async function readDir(dirPath, extensions = ALL_EXTENSIONS) {
  const results = [];
  try {
    await walk(dirPath, extensions, results);
  } catch {
    // Directory doesn't exist or permission error
  }
  return results;
}

async function walk(dirPath, extensions, results) {
  let entries;
  try {
    entries = await fs.readdir(dirPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      if (['node_modules', '.git', 'dist', 'build', '.next', 'coverage', '.turbo', '.vercel', '__pycache__', 'venv', '.venv', 'site-packages', 'vendor'].includes(entry.name)) continue;
      await walk(fullPath, extensions, results);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      if (extensions.includes(ext)) {
        const content = await readFile(fullPath);
        if (content !== null) results.push({ filePath: fullPath, content });
      }
    }
  }
}

/**
 * Grep files in a directory for patterns.
 * Returns array of { filePath, lineNumber, line, pattern, context } matches.
 * NEVER returns actual secret values — caller must redact if needed.
 */
export async function grepFiles(dirPath, patterns, options = {}) {
  const { extensions = ALL_EXTENSIONS, contextLines = 2, excludeDirs = [] } = options;
  const files = await readDir(dirPath, extensions);
  const matches = [];
  const compiledPatterns = patterns.map(p => typeof p === 'string' ? new RegExp(p, 'i') : p);

  for (const { filePath, content } of files) {
    // Skip security-audit folder itself
    if (filePath.includes('/fractia/')) continue;
    if (excludeDirs.some(d => filePath.includes(d))) continue;

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const pattern of compiledPatterns) {
        if (pattern.test(lines[i])) {
          const before = lines.slice(Math.max(0, i - contextLines), i);
          const after  = lines.slice(i + 1, i + 1 + contextLines);
          matches.push({
            filePath,
            lineNumber: i + 1,
            line: lines[i].trim(),
            pattern: pattern.toString(),
            context: { before, after }
          });
        }
      }
    }
  }
  return matches;
}

/**
 * List files directly in a directory (non-recursive) matching extension.
 */
export async function listFiles(dirPath, extension = '.js') {
  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    return entries
      .filter(e => e.isFile() && e.name.endsWith(extension))
      .map(e => path.join(dirPath, e.name));
  } catch {
    return [];
  }
}

/**
 * Check if a file exists.
 */
export async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Truncate a string to maxLen chars for safe inclusion in Claude prompts.
 */
export function truncate(str, maxLen = 2000) {
  if (!str) return '';
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen) + '\n... [truncated]';
}
