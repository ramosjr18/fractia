/**
 * Persistent CLI config — stored in ~/.fractia/config.json
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import path from 'path';
import os from 'os';

const CONFIG_DIR  = path.join(os.homedir(), '.fractia');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

const DEFAULTS = {
  outputMode:  'expanded',   // 'expanded' | 'compact'
  defaultDepth: 'standard',  // 'standard' | 'deep' | 'full'
  aiProvider:  '',           // 'claude' | 'openai' | 'none'
};

function load() {
  try {
    if (existsSync(CONFIG_FILE)) {
      return { ...DEFAULTS, ...JSON.parse(readFileSync(CONFIG_FILE, 'utf8')) };
    }
  } catch { /* corrupted — use defaults */ }
  return { ...DEFAULTS };
}

function save(data) {
  try {
    if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(CONFIG_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch { /* non-critical */ }
}

export const store = {
  get(key) {
    return load()[key] ?? DEFAULTS[key];
  },
  set(key, value) {
    const current = load();
    current[key] = value;
    save(current);
  },
  all() {
    return load();
  },
};
