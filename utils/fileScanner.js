import fs from 'fs/promises';
import path from 'path';
import { createReadStream } from 'fs';
import readline from 'readline';
import { config } from '../config.js';

export const PROJECT_ROOT = () => config.projectRoot;
export const BACKEND_ROOT = () => config.projectRoot; // Simplified from path.join(..., 'backend')
export const BACKEND_SRC  = () => _structure ? _structure.srcDir : path.join(config.projectRoot, 'src');

let _structure = null;

export function resetStructureCache() {
  _structure = null;
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
    srcDir: root,
    entryFile: null,
    dirs: {},
    files: {}
  };

  // 1. Walk up for common root files
  result.files.packageJson = await findUp(root, 'package.json');
  result.files.env = await findUp(root, '.env');
  result.files.gitignore = await findUp(root, '.gitignore');

  // 2. Framework detection
  if (result.files.packageJson) {
    const pkgContent = await readFile(result.files.packageJson);
    if (pkgContent) {
      try {
        const pkg = JSON.parse(pkgContent);
        const deps = { ...pkg.dependencies, ...pkg.devDependencies };
        if (deps.express) result.framework = 'express';
        else if (deps.fastify) result.framework = 'fastify';
        else if (deps['@nestjs/core']) result.framework = 'nestjs';
        else if (deps.koa) result.framework = 'koa';
        else if (deps['@hapi/hapi']) result.framework = 'hapi';
      } catch {}
    }
  }

  // 3. Find srcDir
  const srcCandidate = await findDir(root, ['src', 'app', 'lib', 'source', '.']);
  if (srcCandidate) {
    result.srcDir = path.join(root, srcCandidate);
  }

  // 4. Find entry file
  const entryCandidate = await findFile(result.srcDir, ['server.js', 'app.js', 'index.js', 'main.js']);
  if (entryCandidate) {
    result.entryFile = path.join(result.srcDir, entryCandidate);
  } else {
    const rootEntry = await findFile(root, ['server.js', 'app.js', 'index.js', 'main.js']);
    if (rootEntry) result.entryFile = path.join(root, rootEntry);
  }

  // 5. Subdirectories
  const subDirs = ['controllers', 'routes', 'middleware', 'models', 'schemas', 'services', 'workers', 'modules'];
  for (const d of subDirs) {
    const found = await findDir(result.srcDir, [d]);
    if (found) result.dirs[d] = path.join(result.srcDir, found);
  }

  _structure = result;
  return result;
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
 */
export async function readDir(dirPath, extensions = ['.js']) {
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
      if (['node_modules', '.git', 'dist', 'build', '.next', 'coverage'].includes(entry.name)) continue;
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
  const { extensions = ['.js'], contextLines = 2, excludeDirs = [] } = options;
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
