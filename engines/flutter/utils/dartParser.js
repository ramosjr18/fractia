/**
 * Dart Parser — utilidades para análisis estático de archivos .dart
 * No necesita ejecutar Dart — grep + regex sobre texto.
 */
import { readFileSync, readdirSync, statSync } from 'fs';
import path from 'path';

// ── File walker ───────────────────────────────────────────────────────────────
export function findDartFiles(rootDir) {
  const results = [];
  const IGNORE  = new Set(['.dart_tool', 'build', '.pub-cache', '.pub', 'generated', '.g.dart']);

  function walk(dir) {
    let entries;
    try { entries = readdirSync(dir); } catch { return; }
    for (const entry of entries) {
      if (IGNORE.has(entry)) continue;
      const full = path.join(dir, entry);
      let stat;
      try { stat = statSync(full); } catch { continue; }
      if (stat.isDirectory()) {
        walk(full);
      } else if (entry.endsWith('.dart') && !entry.endsWith('.g.dart') && !entry.endsWith('.freezed.dart')) {
        results.push(full);
      }
    }
  }
  walk(rootDir);
  return results;
}

// ── File reader ───────────────────────────────────────────────────────────────
export function readDartFile(filePath) {
  try {
    return readFileSync(filePath, 'utf8');
  } catch {
    return '';
  }
}

// ── Grep ─────────────────────────────────────────────────────────────────────
/**
 * Find all matches of a pattern in a file's content.
 * Returns array of { line, lineNumber, match, file }
 */
export function grep(content, pattern, filePath = '') {
  const results = [];
  const lines   = content.split('\n');
  const re      = pattern instanceof RegExp ? pattern : new RegExp(pattern);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Skip pure comment lines
    if (/^\s*(\/\/|\/\*)/.test(line)) continue;
    const match = re.exec(line);
    if (match) {
      results.push({
        file:       filePath,
        lineNumber: i + 1,
        line:       line.trim(),
        match:      match[0],
      });
    }
  }
  return results;
}

/**
 * Search across all dart files in a directory for a pattern.
 * Returns array of hits with file path and line info.
 */
export function grepFiles(files, pattern) {
  const hits = [];
  for (const f of files) {
    const content = readDartFile(f);
    if (!content) continue;
    const matches = grep(content, pattern, f);
    hits.push(...matches);
  }
  return hits;
}

// ── Context extractor ─────────────────────────────────────────────────────────
/**
 * Get N lines of context around a line number in a file's content.
 */
export function getContext(content, lineNumber, context = 2) {
  const lines = content.split('\n');
  const start = Math.max(0, lineNumber - 1 - context);
  const end   = Math.min(lines.length, lineNumber + context);
  return lines.slice(start, end).map((l, i) => ({
    lineNumber: start + i + 1,
    line: l,
    isTarget: start + i + 1 === lineNumber,
  }));
}

// ── Import checker ────────────────────────────────────────────────────────────
export function hasImport(content, packagePattern) {
  const re = packagePattern instanceof RegExp ? packagePattern : new RegExp(packagePattern);
  return re.test(content);
}

// ── Relative path ─────────────────────────────────────────────────────────────
export function relPath(filePath, rootDir) {
  return filePath.startsWith(rootDir)
    ? filePath.slice(rootDir.length + 1)
    : filePath;
}
