/**
 * projectType.js — Shared project language/framework detection utility
 *
 * Usage:
 *   import { detectProjectType } from '../utils/projectType.js';
 *   const { isPython, isNode, root } = await detectProjectType();
 */

import path from 'path';
import fs from 'fs/promises';
import { discoverStructure, BACKEND_ROOT } from './fileScanner.js';
import { config } from '../config.js';

let _cache = null;

export async function detectProjectType() {
  if (_cache) return _cache;

  const structure = await discoverStructure();
  const root = config.projectRoot;

  // Check for Python markers
  const pythonMarkers = [
    'requirements.txt',
    'backend/requirements.txt',
    'pyproject.toml',
    'setup.py',
    'Pipfile',
  ];

  let hasPythonMarker = false;
  let requirementsTxtPath = null;

  for (const marker of pythonMarkers) {
    const fullPath = path.join(root, marker);
    try {
      await fs.access(fullPath);
      hasPythonMarker = true;
      if (marker.endsWith('requirements.txt')) requirementsTxtPath = fullPath;
      break;
    } catch (_) { /* not found */ }
  }

  // No package.json at project root signals non-Node project
  const hasPackageJson = !!structure.files.packageJson;

  // Framework signals
  const isNextJs   = structure.framework === 'nextjs';
  const isNestJs   = structure.framework === 'nestjs';
  const isExpress  = structure.framework === 'express';
  const isNode     = hasPackageJson || isNextJs || isNestJs || isExpress;
  const isPython   = hasPythonMarker && !isNode;

  _cache = {
    isPython,
    isNode,
    framework: structure.framework,
    root,
    src: structure.srcDir,
    requirementsTxtPath,
    structure,
  };

  return _cache;
}

/** Reset cache (call between test runs if PROJECT_ROOT changes) */
export function resetProjectTypeCache() {
  _cache = null;
}
