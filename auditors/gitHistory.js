/**
 * gitHistory.js — Git History Secrets Scanner
 *
 * Escanea TODO el historial de commits buscando secretos que fueron
 * añadidos en algún momento (aunque luego se borraron). Un secret
 * eliminado sigue viviendo en `git log` para siempre.
 *
 * Técnica: `git log -p` → parsear líneas añadidas (+) → aplicar
 * los mismos patrones de secrets.js → reportar commit, autor, fecha.
 *
 * Sin dependencias externas — solo usa `git` nativo del sistema.
 */
import path      from 'path';
import { execSync } from 'child_process';
import { discoverStructure } from '../utils/fileScanner.js';

// ── Mismos patrones que secrets.js ───────────────────────────────────────────
const PATTERNS = [
  { regex: /(['"`])sk-[A-Za-z0-9]{20,}\1/,                         label: 'OpenAI / Stripe API key',                severity: 'critical' },
  { regex: /(['"`])AKIA[A-Z0-9]{16}\1/,                             label: 'AWS Access Key ID',                      severity: 'critical' },
  { regex: /(['"`])Bearer [A-Za-z0-9._\-]{20,}\1/,                  label: 'Bearer token hardcodeado',               severity: 'critical' },
  { regex: /(['"`])ghp_[A-Za-z0-9]{36}\1/,                          label: 'GitHub Personal Access Token',           severity: 'critical' },
  { regex: /(['"`])xox[baprs]-[A-Za-z0-9-]{10,}\1/,                 label: 'Slack token',                            severity: 'critical' },
  { regex: /(['"`])SG\.[A-Za-z0-9._-]{20,}\1/,                      label: 'SendGrid API key',                       severity: 'critical' },
  { regex: /(['"`])key-[a-z0-9]{32}\1/,                             label: 'Mailgun API key',                        severity: 'critical' },
  { regex: /(['"`])AC[a-z0-9]{32}\1/,                               label: 'Twilio Account SID',                     severity: 'critical' },
  { regex: /(['"`])EAA[a-zA-Z0-9]{20,}\1/,                          label: 'Facebook Access Token',                  severity: 'critical' },
  { regex: /(['"`])ya29\.[A-Za-z0-9._-]+\1/,                        label: 'Google OAuth token',                     severity: 'critical' },
  { regex: /(['"`])rk_live_[A-Za-z0-9]{24}\1/,                      label: 'Stripe Restricted Key (live)',           severity: 'critical' },
  { regex: /(['"`])mongodb(\+srv)?:\/\/[^:]+:[^@]+@/,                label: 'MongoDB connection string con credenciales', severity: 'critical' },
  { regex: /(['"`])postgres:\/\/[^:]+:[^@]+@/,                      label: 'PostgreSQL DSN con credenciales',        severity: 'critical' },
  { regex: /private[_-]?key\s*[:=]\s*['"`]-----BEGIN/,              label: 'Clave privada PEM',                      severity: 'critical' },
  { regex: /jwt\.sign\([^)]+,\s*['"`][^'"`]{6,}['"`]/,              label: 'JWT signing secret hardcodeado',         severity: 'high'     },
  { regex: /(?:SECRET|KEY|TOKEN|PASSWORD|API_KEY)\b.*\|\|\s*['"`][^'"`]{4,}['"`]/i, label: 'Fallback hardcodeado via ||', severity: 'high' },
  { regex: /password\s*[:=]\s*['"`][^'"`]{6,}['"`]/i,               label: 'Password string hardcodeada',            severity: 'high'     },
  { regex: /api[_-]?key\s*[:=]\s*['"`][A-Za-z0-9._\-]{10,}['"`]/i, label: 'API key hardcodeada',                   severity: 'high'     },
  { regex: /(['"`])redis:\/\/:[^@]+@/,                              label: 'Redis DSN con contraseña',               severity: 'high'     },
  { regex: /secret\s*[:=]\s*['"`][^'"`]{6,}['"`]/i,                 label: 'Secret string hardcodeado',             severity: 'medium'   },
];

const SEV_RANK   = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
const MAX_COMMITS = 1000;
const MAX_BUF_MB  = 80;

// Extensions to skip (binary / generated)
const SKIP_EXT = new Set([
  // Binary / generated
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2',
  '.ttf', '.eot', '.zip', '.gz', '.tar', '.pdf', '.lock', '.map',
  // Documentation & config templates (code examples ≠ real secrets)
  '.md', '.mdx', '.txt', '.rst', '.adoc',
]);

function redact(line) {
  return line.replace(/(['"`])[^'"`]{4,}\1/g, "'[REDACTED]'");
}

function shortSha(sha) { return sha?.slice(0, 8) || '????????'; }

// ── Check if the secret STILL exists at HEAD ─────────────────────────────────
function existsAtHead(root, filePath, pattern) {
  try {
    const content = execSync(`git show HEAD:"${filePath}"`,
      { cwd: root, encoding: 'utf8', stdio: 'pipe', maxBuffer: 2 * 1024 * 1024 });
    return pattern.test(content);
  } catch {
    return false; // file deleted at HEAD
  }
}

// ── Parse git log -p output ───────────────────────────────────────────────────
function parseGitLog(logOutput, root) {
  const lines  = logOutput.split('\n');
  const hits   = new Map(); // dedupeKey → hit object

  let commitSha  = null;
  let author     = null;
  let dateStr    = null;
  let currentFile = null;

  for (const raw of lines) {
    // Commit header
    if (raw.startsWith('commit ')) {
      commitSha   = raw.slice(7).trim();
      currentFile = null;
      continue;
    }
    if (raw.startsWith('Author: ')) { author  = raw.slice(8).trim(); continue; }
    if (raw.startsWith('Date:'))    { dateStr = raw.replace(/^Date:\s*/, '').trim(); continue; }

    // File path from diff header
    if (raw.startsWith('+++ b/')) {
      currentFile = raw.slice(6).trim();
      continue;
    }
    // Binary file marker → reset
    if (raw.startsWith('Binary files')) { currentFile = null; continue; }

    // Only look at ADDED lines
    if (!raw.startsWith('+') || raw.startsWith('+++')) continue;
    if (!currentFile) continue;

    // Skip binary / generated extensions
    if (SKIP_EXT.has(path.extname(currentFile).toLowerCase())) continue;

    // Skip test, spec, mock files
    if (/\.(test|spec)\.(js|ts|jsx|tsx|py)|__tests__|__mocks__|node_modules/
          .test(currentFile)) continue;

    const content = raw.slice(1); // strip leading +
    const trimmed = content.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

    for (const pat of PATTERNS) {
      if (!pat.regex.test(content)) continue;

      // Deduplicate: same pattern type + same file → keep only first occurrence found
      const key = `${pat.label}::${currentFile}`;
      if (hits.has(key)) continue;

      hits.set(key, {
        pattern:    pat,
        file:       currentFile,
        commitFull: commitSha,
        commitShort: shortSha(commitSha),
        author,
        date:       dateStr,
        line:       trimmed,
      });
    }
  }

  return [...hits.values()];
}

// ── Main auditor ──────────────────────────────────────────────────────────────
export async function audit(depth) {
  const findings        = [];
  const recommendations = [];
  const _codeSnippets   = {};

  const structure = await discoverStructure();
  const root = structure.files.packageJson
    ? path.dirname(structure.files.packageJson)
    : structure.srcDir;

  // ── 1. Verify git repo ────────────────────────────────────────────────────
  try {
    execSync('git rev-parse --git-dir', { cwd: root, stdio: 'pipe' });
  } catch {
    return {
      id: 'gitHistory', name: 'Git History Secrets',
      severity: 'ok', score: 100,
      findings: [{
        type: 'info',
        title: 'No es un repositorio git',
        description: 'No se encontró directorio .git en el proyecto. El escáner de historial no aplica.',
        code_example: null, cve: null,
      }],
      recommendations: [],
      _codeSnippets: {},
    };
  }

  // ── 2. Count commits for info ─────────────────────────────────────────────
  let totalCommits = 0;
  try {
    totalCommits = parseInt(
      execSync('git rev-list --count HEAD', { cwd: root, encoding: 'utf8', stdio: 'pipe' }).trim(), 10
    );
  } catch {}

  const scannedCommits = Math.min(totalCommits, MAX_COMMITS);

  // ── 3. Get git log with patches ───────────────────────────────────────────
  let logOutput = '';
  try {
    // We scan --all to ensure total coverage across all branches and tags.
    logOutput = execSync(
      `git log -p --all --unified=0 --max-count=${MAX_COMMITS}`,
      { cwd: root, encoding: 'utf8', stdio: 'pipe', maxBuffer: MAX_BUF_MB * 1024 * 1024, timeout: 30_000 }
    );
  } catch (e) {
    return {
      id: 'gitHistory', name: 'Git History Secrets',
      severity: 'medium', score: 70,
      findings: [{
        type: 'warning',
        title: 'No se pudo leer el historial git',
        description: `Error al ejecutar git log: ${e.message?.slice(0, 200)}`,
        code_example: null, cve: null,
      }],
      recommendations: [],
      _codeSnippets: {},
    };
  }

  if (!logOutput.trim()) {
    return {
      id: 'gitHistory', name: 'Git History Secrets',
      severity: 'ok', score: 100,
      findings: [{ type: 'info', title: 'Sin commits en el historial', description: 'El repo no tiene commits todavía.', code_example: null, cve: null }],
      recommendations: [],
      _codeSnippets: {},
    };
  }

  // ── 4. Parse and match ────────────────────────────────────────────────────
  const rawHits = parseGitLog(logOutput, root);

  // ── 5. Check if still present at HEAD ────────────────────────────────────
  for (const hit of rawHits) {
    const stillPresent = existsAtHead(root, hit.file, hit.pattern.regex);
    
    // Check which branches/tags contain this commit
    let refs = [];
    try {
      refs = execSync(`git branch -a --contains ${hit.commitFull}`, { cwd: root, encoding: 'utf8' })
        .split('\n')
        .map(b => b.trim().replace('* ', ''))
        .filter(Boolean);
      
      const tags = execSync(`git tag --contains ${hit.commitFull}`, { cwd: root, encoding: 'utf8' })
        .split('\n')
        .map(t => `tag: ${t.trim()}`)
        .filter(t => t !== 'tag: ');
      
      refs = [...refs, ...tags];
    } catch {}

    const refInfo = refs.length > 0 ? ` [Refs: ${refs.join(', ')}]` : ' [Objeto huérfano / reflog]';
    const status = stillPresent
      ? '⚠️  AÚN EXISTE en el código actual'
      : `🗑️  Eliminado del código actual pero permanece en el historial${refInfo}`;

    findings.push({
      type:        'vulnerability',
      title:       `[Historial Git] ${hit.pattern.label}`,
      description: `Encontrado en commit ${hit.commitShort} · ${hit.date} · autor: ${hit.author} · archivo: ${hit.file}\n${status}`,
      code_example: redact(hit.line),
      cve:         null,
      _severity:   hit.pattern.severity,   // used below for module severity
      _commit:     hit.commitShort,
      _stillPresent: stillPresent,
    });

    // Code snippet (one per file, first hit wins)
    if (!_codeSnippets[hit.file]) {
      _codeSnippets[hit.file] = `# commit ${hit.commitShort} — ${hit.date}\n${redact(hit.line)}`;
    }
  }

  // ── 6. Summary info finding ───────────────────────────────────────────────
  findings.push({
    type:        'info',
    title:       `Historial escaneado: ${scannedCommits} de ${totalCommits} commits`,
    description: totalCommits > MAX_COMMITS
      ? `Solo se analizaron los últimos ${MAX_COMMITS} commits. El historial completo tiene ${totalCommits} commits.`
      : `Se analizó el historial completo (${totalCommits} commits).`,
    code_example: null,
    cve:         null,
    _severity:   'ok',
  });

  // ── 7. Recommendations ────────────────────────────────────────────────────
  const hasSecrets = rawHits.length > 0;
  const stillPresent = rawHits.filter(h => existsAtHead(root, h.file, h.pattern.regex));

  if (hasSecrets) {
    recommendations.push(
      'Rota INMEDIATAMENTE cualquier credencial encontrada en el historial — se considera comprometida.',
      'Usa `git filter-repo` (no `filter-branch`) para reescribir el historial y eliminar el secreto de todos los commits.',
      'Avisa a todos los colaboradores para que hagan `git pull --rebase` tras la reescritura.',
      'Implementa un pre-commit hook con `git-secrets` o `detect-secrets` para prevenir futuros commits con credenciales.',
    );
  } else {
    recommendations.push(
      'Sin secretos detectados en el historial analizado.',
      'Considera añadir un pre-commit hook con `detect-secrets` para prevención continua.',
    );
  }

  // ── 8. Compute severity ───────────────────────────────────────────────────
  const worstSev = findings.reduce((best, f) => {
    const rank = SEV_RANK[f._severity || 'ok'] || 0;
    return rank > SEV_RANK[best] ? (f._severity || 'ok') : best;
  }, 'ok');

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const score = Math.max(0, 100 - vulnCount * 18);

  return {
    id:              'gitHistory',
    name:            'Git History Secrets',
    severity:        worstSev,
    score,
    findings,
    recommendations,
    _codeSnippets,
  };
}
