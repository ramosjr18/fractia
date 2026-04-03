import { readFileSync, existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load .env manually (no dotenv dependency)
function loadEnv() {
  try {
    const envPath = path.join(__dirname, '.env');
    const raw = readFileSync(envPath, 'utf8');
    for (const line of raw.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq < 0) continue;
      const key = trimmed.slice(0, eq).trim();
      const val = trimmed.slice(eq + 1).trim();
      if (!process.env[key]) process.env[key] = val;
    }
  } catch {
    // No .env file — rely on process.env
  }
}

loadEnv();

export const config = {
  port: parseInt(process.env.PORT || '7777', 10),
  projectRoot: process.env.PROJECT_ROOT || '',   // resolved at runtime by selectProject
  anthropicApiKey: process.env.ANTHROPIC_API_KEY || '',
  openaiApiKey: process.env.OPENAI_API_KEY || '',
  aiProvider: process.env.AI_PROVIDER || '',   // 'claude' | 'openai' | 'none' — set at runtime
  githubToken: process.env.GITHUB_TOKEN || '',
  
  // OpSec & Stealth
  proxy: process.env.FRACTIA_PROXY || '', // e.g. http://user:pass@1.2.3.4:8080 or socks5://...
  userAgent: process.env.FRACTIA_USER_AGENT || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  stealthMode: process.env.FRACTIA_STEALTH === 'true',
  baseIP: process.env.FRACTIA_BASE_IP || '', // User's real public IP to detect leaks
};

// No longer throws on missing PROJECT_ROOT — handled interactively by server.js
