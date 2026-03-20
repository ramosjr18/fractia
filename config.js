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
  projectRoot: process.env.PROJECT_ROOT || path.join(__dirname, '..', 'exampleapp'),
  anthropicApiKey: process.env.ANTHROPIC_API_KEY || '',
};

if (!existsSync(config.projectRoot)) {
  throw new Error(`[Fractia] Fatal Error: PROJECT_ROOT does not exist on disk: ${config.projectRoot}`);
}
