/**
 * Auto-Remediation Agent — Pilar E
 *
 * Flujo:
 *  1. Recibe findings del Code Audit (con _codeSnippets de archivos reales)
 *  2. Por cada archivo con hallazgos critical/high, llama a la IA para generar el fix
 *  3. Escribe el archivo corregido en disco
 *  4. Crea branch git  →  commit  →  push  →  abre PR en GitHub (si hay token)
 *
 * Uso:
 *  import { runAutoFix } from './engines/autoFix.js';
 *  const result = await runAutoFix({ rawResults, projectRoot, githubRepo, githubToken, hooks });
 */
import path from 'path';
import { readFileSync, writeFileSync } from 'fs';
import { execSync }   from 'child_process';
import Anthropic      from '@anthropic-ai/sdk';
import { config }     from '../config.js';
import { GitHubClient, parseRepo } from '../utils/githubClient.js';

const MAX_FILE_CHARS = 12_000;   // chars sent to AI per file
const FIXABLE_EXTS   = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py']);

// ── AI fix generator ──────────────────────────────────────────────────────────
async function generateFix({ fileContent, relFile, findingsList }) {
  const truncated = fileContent.length > MAX_FILE_CHARS
    ? fileContent.slice(0, MAX_FILE_CHARS) + '\n// [... truncated by Fractia ...]'
    : fileContent;

  const findingsBlock = findingsList.map((f, i) =>
    `${i + 1}. [${(f.severity || f.type || 'HIGH').toUpperCase()}] ${f.title}\n` +
    `   Descripción: ${f.description}\n` +
    (f.cve      ? `   Referencia: ${f.cve}\n` : '') +
    (f.fix      ? `   Fix sugerido: ${f.fix}\n` : '') +
    (f.code_example
      ? `   Ejemplo correcto:\n${f.code_example.split('\n').map(l => '   ' + l).join('\n')}`
      : '')
  ).join('\n\n');

  const prompt =
`Eres un ingeniero de seguridad senior aplicando correcciones mínimas a un archivo de código fuente.

Archivo: ${relFile}
\`\`\`
${truncated}
\`\`\`

Vulnerabilidades a corregir:
${findingsBlock}

Instrucciones estrictas:
- Aplica el cambio MÍNIMO necesario para corregir cada vulnerabilidad listada.
- NO refactorices, NO renombres variables, NO cambies lógica no relacionada con la seguridad.
- Preserva toda la indentación, comentarios existentes y estilo de código.
- Si una vulnerabilidad requiere importar una librería que no está en el archivo, añade solo el import necesario.
- Si no puedes corregir algo de forma segura sin conocer el contexto completo del proyecto, deja ese fragmento sin cambiar y añade un comentario: // TODO(Fractia): revisar manualmente — <razón>

Devuelve ÚNICAMENTE el contenido completo del archivo corregido, sin bloques markdown, sin explicaciones, sin preámbulos.`;

  // Claude preferred, OpenAI fallback
  if (config.aiProvider === 'claude' && config.anthropicApiKey) {
    const client = new Anthropic({ apiKey: config.anthropicApiKey });
    const msg = await client.messages.create({
      model:      'claude-sonnet-4-20250514',
      max_tokens: 4096,
      messages:   [{ role: 'user', content: prompt }],
    });
    let text = msg.content.map(b => b.text || '').join('').trim();
    // Strip accidental markdown code fences
    text = text.replace(/^```[a-z]*\n?/i, '').replace(/\n?```$/i, '').trim();
    return text;
  }

  if ((config.aiProvider === 'openai' || !config.aiProvider) && config.openaiApiKey) {
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method:  'POST',
      headers: { 'Authorization': `Bearer ${config.openaiApiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model:    'gpt-4o',
        messages: [{ role: 'user', content: prompt }],
      }),
    });
    if (!res.ok) throw new Error(`OpenAI API error: ${res.status}`);
    const data = await res.json();
    let text = data.choices?.[0]?.message?.content?.trim() || '';
    text = text.replace(/^```[a-z]*\n?/i, '').replace(/\n?```$/i, '').trim();
    return text;
  }

  throw new Error('No AI provider configured. Set ANTHROPIC_API_KEY or OPENAI_API_KEY.');
}

// ── Git helpers ───────────────────────────────────────────────────────────────
function git(projectRoot, ...args) {
  return execSync(`git -C "${projectRoot}" ${args.join(' ')}`, { encoding: 'utf8', stdio: 'pipe' }).trim();
}

function getDefaultBranch(projectRoot) {
  try { return git(projectRoot, 'rev-parse --abbrev-ref HEAD'); } catch { return 'main'; }
}

// ── PR body builder ───────────────────────────────────────────────────────────
function buildPRBody(fixedFiles) {
  const fileList = fixedFiles.map(({ file, findings }) => {
    const items = findings.map(f =>
      `  - **[${(f.severity || f.type || '').toUpperCase()}]** ${f.title}` +
      (f.cve ? ` (${f.cve})` : '')
    ).join('\n');
    return `### \`${file}\`\n${items}`;
  }).join('\n\n');

  return `## 🔐 Fractia Auto-Remediation

Este PR fue generado automáticamente por el **Fractia Auto-Fix Agent** en respuesta a vulnerabilidades \
de severidad critical/high detectadas en el Code Audit.

### Archivos modificados

${fileList}

---
### ⚠️ Revisión recomendada

Aunque Fractia aplica el cambio mínimo necesario, **revisa cada diff antes de hacer merge**:
- Verifica que el fix no rompa tests existentes.
- Confirma que las dependencias añadidas (si las hay) estén en tu \`package.json\`.
- Los comentarios \`// TODO(Fractia): revisar manualmente\` marcan casos que requieren intervención humana.

_Generado por [Fractia](https://github.com/your-org/fractia) v3.0.0_`;
}

// ── Main runner ───────────────────────────────────────────────────────────────
/**
 * @param {object}   options
 * @param {object[]} options.rawResults    - módulos con findings + _codeSnippets
 * @param {string}   options.projectRoot
 * @param {string}   [options.githubRepo]  - "owner/repo"
 * @param {string}   [options.githubToken]
 * @param {object}   [options.hooks]       - { onFileStart, onFileFixed, onFileFailed, onCommit, onPR, onSkip }
 * @returns {Promise<{ fixedFiles, failedFiles, skipped, branchName, prUrl, baseBranch }>}
 */
export async function runAutoFix({ rawResults, projectRoot, githubRepo, githubToken, hooks = {} }) {
  if (!config.anthropicApiKey && !config.openaiApiKey) {
    throw new Error('Auto-Fix requiere IA (ANTHROPIC_API_KEY o OPENAI_API_KEY)');
  }

  // ── 1. Collect fixable files from _codeSnippets ──────────────────────────
  //    rawResults must include _codeSnippets before they are stripped
  const fileMap = new Map(); // filePath → { relFile, findings[] }

  for (const mod of rawResults) {
    if (!['critical', 'high'].includes(mod.severity)) continue;
    if (!mod._codeSnippets || mod.findings.length === 0) continue;

    for (const absPath of Object.keys(mod._codeSnippets)) {
      const ext = path.extname(absPath);
      if (!FIXABLE_EXTS.has(ext)) continue;

      const relFile = absPath.startsWith(projectRoot)
        ? absPath.slice(projectRoot.length + 1)
        : absPath;

      if (!fileMap.has(absPath)) fileMap.set(absPath, { relFile, absPath, findings: [] });
      fileMap.get(absPath).findings.push(
        ...mod.findings.filter(f => ['vulnerability', 'critical', 'high'].includes(f.type || f.severity))
      );
    }
  }

  // Remove files with no actionable findings after filtering
  for (const [k, v] of fileMap) {
    if (v.findings.length === 0) fileMap.delete(k);
  }

  const skipped = rawResults.reduce((n, m) => n + m.findings.length, 0) -
    [...fileMap.values()].reduce((n, v) => n + v.findings.length, 0);

  if (fileMap.size === 0) {
    hooks.onSkip?.({ reason: 'No hay hallazgos critical/high con archivos referenciados' });
    return { fixedFiles: [], failedFiles: [], skipped, branchName: null, prUrl: null };
  }

  // ── 2. Fix each file with AI ──────────────────────────────────────────────
  const fixedFiles  = [];
  const failedFiles = [];

  for (const { relFile, absPath, findings } of fileMap.values()) {
    hooks.onFileStart?.({ file: relFile, count: findings.length });

    let original;
    try { original = readFileSync(absPath, 'utf8'); } catch (e) {
      failedFiles.push({ file: relFile, error: `No se puede leer: ${e.message}` });
      hooks.onFileFailed?.({ file: relFile, error: e.message });
      continue;
    }

    let fixed;
    try {
      fixed = await generateFix({ fileContent: original, relFile, findingsList: findings });
    } catch (e) {
      failedFiles.push({ file: relFile, error: `IA falló: ${e.message}` });
      hooks.onFileFailed?.({ file: relFile, error: e.message });
      continue;
    }

    // Safety check: AI must return non-empty content of similar length (±60%)
    if (!fixed || fixed.length < original.length * 0.3) {
      failedFiles.push({ file: relFile, error: 'IA devolvió contenido sospechosamente corto — descartado' });
      hooks.onFileFailed?.({ file: relFile, error: 'output demasiado corto' });
      continue;
    }

    writeFileSync(absPath, fixed, 'utf8');
    fixedFiles.push({ file: relFile, absPath, findings });
    hooks.onFileFixed?.({ file: relFile, findings });
  }

  if (fixedFiles.length === 0) {
    return { fixedFiles, failedFiles, skipped, branchName: null, prUrl: null };
  }

  // ── 3. Git: branch → commit ───────────────────────────────────────────────
  const ts         = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const branchName = `sec-fix-${ts}`;
  const baseBranch = getDefaultBranch(projectRoot);

  let commitOk = false;
  try {
    git(projectRoot, `checkout -b ${branchName}`);
    for (const { file } of fixedFiles) {
      git(projectRoot, `add "${file}"`);
    }
    const msg =
      `security: auto-fix ${fixedFiles.length} critical/high finding(s)\n\n` +
      `Corrected by Fractia Auto-Remediation Agent\n` +
      `Files: ${fixedFiles.map(f => f.file).join(', ')}`;
    git(projectRoot, `commit -m "${msg.replace(/"/g, '\\"')}"`);
    commitOk = true;
    hooks.onCommit?.({ branch: branchName, files: fixedFiles.length });
  } catch (e) {
    return { fixedFiles, failedFiles, skipped, branchName, prUrl: null, baseBranch, commitError: e.message };
  }

  // ── 4. Push + GitHub PR (optional) ───────────────────────────────────────
  let prUrl = null;
  if (commitOk && githubToken && githubRepo) {
    try {
      git(projectRoot, `push origin ${branchName}`);

      const { owner, repo } = parseRepo(githubRepo);
      const gh  = new GitHubClient(githubToken);
      const pr  = await gh.createPR(owner, repo, {
        title: `🔐 [Fractia] Auto-fix: ${fixedFiles.length} security issue(s)`,
        body:  buildPRBody(fixedFiles),
        head:  branchName,
        base:  baseBranch,
      });
      prUrl = pr.html_url;
      hooks.onPR?.({ url: prUrl });
    } catch (e) {
      hooks.onPushFailed?.({ error: e.message });
    }
  }

  return { fixedFiles, failedFiles, skipped, branchName, prUrl, baseBranch };
}
