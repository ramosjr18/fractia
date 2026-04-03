/**
 * Interactive project selector with history
 * Stores recent projects in ~/.fractia/projects.json
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from 'fs';
import path from 'path';
import os from 'os';
import readline from 'readline';
import { t, link, box, divider, colors } from './theme.js';
import chalk from 'chalk';

const HISTORY_DIR  = path.join(os.homedir(), '.fractia');
const HISTORY_FILE = path.join(HISTORY_DIR, 'projects.json');
const MAX_RECENT   = 8;

// ── History management ──────────────────────────────────────────────────────
function loadHistory() {
  try {
    if (existsSync(HISTORY_FILE)) {
      return JSON.parse(readFileSync(HISTORY_FILE, 'utf8'));
    }
  } catch { /* corrupted file, start fresh */ }
  return [];
}

function saveHistory(projects) {
  try {
    if (!existsSync(HISTORY_DIR)) mkdirSync(HISTORY_DIR, { recursive: true });
    writeFileSync(HISTORY_FILE, JSON.stringify(projects.slice(0, MAX_RECENT), null, 2), 'utf8');
  } catch { /* non-critical */ }
}

export function addToHistory(projectPath) {
  const projects = loadHistory();
  const normalized = path.resolve(projectPath);
  const name = path.basename(normalized);

  // Remove if already exists, then prepend
  const filtered = projects.filter(p => p.path !== normalized);
  filtered.unshift({ path: normalized, name, lastUsed: new Date().toISOString() });
  saveHistory(filtered);
}

// ── Detect projects in common workspace directories ─────────────────────────
function scanWorkspaceDir(dir) {
  try {
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
      .map(name => path.join(dir, name))
      .filter(p => {
        try {
          return statSync(p).isDirectory() &&
                 (existsSync(path.join(p, 'package.json')) ||
                  existsSync(path.join(p, '.git')));
        } catch { return false; }
      })
      .slice(0, 20);
  } catch { return []; }
}

// ── Interactive selector ────────────────────────────────────────────────────
export async function selectProject(envProjectRoot) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise(resolve => rl.question(q, resolve));

  const history = loadHistory();
  const hasEnvProject = envProjectRoot && existsSync(envProjectRoot);

  console.log('');
  console.log(box(chalk.bold('Selección de Proyecto'), { color: '#00b4d8' }));
  console.log('');

  // Build options list
  const options = [];
  let optNum = 1;

  // Option: use .env project if valid
  if (hasEnvProject) {
    options.push({ num: optNum, path: envProjectRoot, label: 'actual (.env)', type: 'env' });
    console.log(t.option(`[${optNum}]`, `${path.basename(envProjectRoot)}  ${t.dim(`← .env actual`)}`));
    console.log(`       ${t.label(envProjectRoot)}`);
    optNum++;
  }

  // Recent projects (exclude current env project)
  const recentProjects = history
    .filter(p => p.path !== envProjectRoot && existsSync(p.path))
    .slice(0, 5);

  if (recentProjects.length > 0) {
    console.log('');
    console.log(`  ${colors.accent2('recientes')}`);
    for (const proj of recentProjects) {
      options.push({ num: optNum, path: proj.path, label: proj.name, type: 'recent' });
      const ago = timeAgo(proj.lastUsed);
      console.log(t.option(`[${optNum}]`, `${proj.name}  ${t.dim(ago)}`));
      console.log(`       ${t.label(proj.path)}`);
      optNum++;
    }
  }

  // Manual path option
  console.log('');
  console.log(t.option(`[${optNum}]`, `Escribir ruta manualmente`));
  const manualNum = optNum;
  optNum++;
  
  console.log(t.option(`[v]`, `Volver`));

  console.log('');
  const ans = await ask(colors.accent2('  ▸ ') + colors.text(`Proyecto [1-${manualNum} / v]: `));
  
  if (ans.toLowerCase() === 'v') {
    rl.close();
    return null;
  }

  const choice = parseInt(ans.trim(), 10);
  let selectedPath;

  if (choice === manualNum || isNaN(choice)) {
    // Manual path entry
    const pathAns = ans.trim();
    if (pathAns && pathAns !== String(manualNum)) {
      // They typed a path directly instead of a number
      selectedPath = path.resolve(pathAns);
    } else {
      const manualPath = await ask(colors.accent2('  ▸ ') + colors.text('Ruta del proyecto: '));
      if (!manualPath) {
        rl.close();
        return null;
      }
      selectedPath = path.resolve(manualPath.trim());
    }
  } else {
    const opt = options.find(o => o.num === choice);
    if (opt) {
      selectedPath = opt.path;
    } else {
      // Default to env project or first option
      selectedPath = hasEnvProject ? envProjectRoot : options[0]?.path;
    }
  }

  rl.close();

  // Validate
  if (!selectedPath || !existsSync(selectedPath)) {
    console.log('');
    console.log(t.fail(`La ruta no existe: ${selectedPath}`));
    console.log(t.label('  Verifica la ruta e intenta de nuevo.\n'));
    return null;
  }

  // Save to history
  addToHistory(selectedPath);

  console.log('');
  console.log(`  ${colors.accent('▸')} ${colors.text('Proyecto:')} ${t.path(path.basename(selectedPath))}`);
  console.log(`    ${t.label(selectedPath)}`);
  console.log('');

  return selectedPath;
}

// ── Time ago helper ─────────────────────────────────────────────────────────
function timeAgo(isoString) {
  try {
    const diff = Date.now() - new Date(isoString).getTime();
    const mins  = Math.floor(diff / 60000);
    const hours = Math.floor(mins / 60);
    const days  = Math.floor(hours / 24);

    if (mins < 1) return 'ahora';
    if (mins < 60) return `hace ${mins}m`;
    if (hours < 24) return `hace ${hours}h`;
    if (days < 7) return `hace ${days}d`;
    return `hace ${Math.floor(days / 7)}sem`;
  } catch { return ''; }
}
