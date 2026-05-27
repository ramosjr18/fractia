import path from 'path';
import { readFile, grepFiles, discoverStructure, truncate } from '../utils/fileScanner.js';
import { detectProjectType } from '../utils/projectType.js';

// ─── Python / FastAPI XSS & CORS audit ───────────────────────────────────────

async function auditPython(src) {
  const findings = [];
  const recommendations = [];
  const py = ['.py'];

  // 1. CORS — check for wildcard allow_origins in FastAPI CORSMiddleware
  const corsMatches = await grepFiles(src, [/CORSMiddleware|allow_origins/i], { extensions: py });

  if (corsMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No se detectó configuración CORS (CORSMiddleware)',
      description:
        'No se encontró CORSMiddleware ni allow_origins en el código. Sin CORS configurado explícitamente, el comportamiento depende del servidor web (puede ser demasiado permisivo).',
      code_example:
        'from fastapi.middleware.cors import CORSMiddleware\n\n' +
        'app.add_middleware(\n    CORSMiddleware,\n' +
        '    allow_origins=["https://tudominio.com"],\n' +
        '    allow_credentials=True,\n' +
        '    allow_methods=["GET", "POST", "PUT", "DELETE"],\n' +
        '    allow_headers=["Authorization", "Content-Type"],\n)',
      cve: null,
    });
  } else {
    // Check for wildcard
    const uniqueFiles = [...new Set(corsMatches.map(m => m.filePath).filter(Boolean))];
    const corsContent = (await Promise.all(uniqueFiles.map(f => readFile(f).catch(() => '')))).join('\n');

    if (/allow_origins\s*=\s*\["?\*"?\]|allow_origins\s*=\s*\["\*"\]|allow_origins=\["?\*"?\]/i.test(corsContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'CORS configurado con wildcard allow_origins=["*"]',
        description:
          'allow_origins=["*"] permite que cualquier dominio haga peticiones cross-origin a tu API desde el navegador de un usuario. Con credenciales, esto es especialmente peligroso.',
        code_example:
          '# Vulnerable:\nallow_origins=["*"]\n\n' +
          '# Correcto:\nallow_origins=["https://tuapp.com", "https://app.tudominio.com"]',
        cve: null,
      });
    }

    // credentials: True with wildcard is invalid but signals misconfiguration intent
    if (/allow_credentials\s*=\s*True/i.test(corsContent) && /allow_origins.*\*/i.test(corsContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'allow_credentials=True con allow_origins wildcard',
        description:
          'Combinar allow_credentials=True con allow_origins=["*"] es inválido según la spec CORS pero indica una mala configuración. Los navegadores la rechazarán, pero corrige la intención.',
        code_example: null,
        cve: null,
      });
    }
  }

  // 2. Input sanitization for Jinja2 / templates
  const templateMatches = await grepFiles(src, [/Jinja2Templates|jinja2|from jinja2/i], { extensions: py });
  if (templateMatches.length > 0) {
    const autoescapeMatches = await grepFiles(src, [/autoescape\s*=\s*True|autoescape=select_autoescape/i], { extensions: py });
    if (autoescapeMatches.length === 0) {
      findings.push({
        type: 'vulnerability',
        title: 'Jinja2 detectado sin autoescape explícito',
        description:
          'Se usa Jinja2 para renderizar plantillas pero no se detectó autoescape=True ni select_autoescape(). Sin autoescaping, los datos de usuario insertados en plantillas HTML pueden causar XSS almacenado.',
        code_example:
          'from jinja2 import Environment, select_autoescape\n\n' +
          'env = Environment(\n    loader=FileSystemLoader("templates"),\n' +
          '    autoescape=select_autoescape(["html", "xml"])\n)',
        cve: 'CWE-79',
      });
    }
  }

  // 3. bleach / html.escape sanitization
  const sanitizeMatches = await grepFiles(src, [/bleach|html\.escape|MarkupSafe|markupsafe/i], { extensions: py });
  if (sanitizeMatches.length === 0 && templateMatches.length > 0) {
    findings.push({
      type: 'info',
      title: 'No se detectó sanitización HTML explícita (bleach/html.escape)',
      description:
        'No se encontró bleach, html.escape ni MarkupSafe para sanitizar datos de usuario antes de renderizarlos. Complementa el autoescape de Jinja2 con sanitización explícita para HTML en emails y PDFs.',
      code_example:
        '# pip install bleach\nimport bleach\n\n' +
        'clean_html = bleach.clean(user_input, tags=["b", "i", "em", "strong"], strip=True)',
      cve: null,
    });
  }

  // 4. eval() / exec() with user input
  const evalMatches = await grepFiles(src, [/\beval\s*\(|exec\s*\(\s*(?!compile)/], { extensions: py });
  const evalFiltered = evalMatches.filter(m =>
    !m.filePath.includes('test') && !m.filePath.includes('conftest') && !m.line?.trim().startsWith('#')
  );

  if (evalFiltered.length > 0) {
    const locs = evalFiltered.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'eval() o exec() detectado en código Python',
      description: `Se encontró eval()/exec() en: ${locs}. Si datos de usuario alcanzan estas llamadas, resulta en Remote Code Execution (RCE).`,
      code_example: evalFiltered[0]?.line?.trim() || null,
      cve: 'CWE-94',
    });
  }

  // 5. User input reflected in response
  const reflectedMatches = await grepFiles(src, [
    /return\s+HTMLResponse\s*\(.*(?:request\.|body\.|query\.|params\.)/,
    /return\s+Response\s*\(.*content.*(?:request\.|body\.)/,
  ], { extensions: py });

  if (reflectedMatches.length > 0) {
    const locs = reflectedMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'warning',
      title: 'Input de usuario reflejado directamente en HTMLResponse',
      description: `Datos de usuario devueltos como HTML en: ${locs}. Si Content-Type es text/html, esto es un vector de XSS reflejado.`,
      code_example: reflectedMatches[0]?.line?.trim() || null,
      cve: 'CWE-79',
    });
  }

  recommendations.push(
    'Establece allow_origins con una allowlist explícita en producción. Nunca uses ["*"] con credenciales.',
    'Asegúrate de que todos los endpoints devuelven Content-Type: application/json — esto previene XSS reflejado incluso si el input es reexpedido.',
    'Si usas Jinja2, activa siempre autoescape=True para plantillas HTML.',
    'Usa bleach para sanear HTML en emails, notificaciones y cualquier contenido generado por usuarios.',
    'Elimina eval() y exec() del código de producción. Usa ast.literal_eval() para datos simples.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 2 ? 'high' : vulnCount === 1 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20 - warnCount * 8);

  return { id: 'xss', name: 'XSS & CSRF', severity, score, findings, recommendations, _codeSnippets: {} };
}

// ─── Node.js / Express XSS & CSRF audit (original logic) ─────────────────────

async function auditNode(structure) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = structure.srcDir;
  const controllersDir = structure.dirs.controllers || path.join(src, 'controllers');
  const serverContent = structure.entryFile ? await readFile(structure.entryFile) : null;

  if (!serverContent) {
    findings.push({ type: 'warning', title: 'Server entry file not found', description: 'Cannot analyze CORS/XSS configuration.', code_example: null, cve: null });
  } else {
    _codeSnippets['server (CORS)'] = truncate(serverContent, 1500);

    if (/CORS_ORIGIN.*\|\|.*\*|\['?\*'?\]/.test(serverContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'CORS defaults to wildcard (*) when CORS_ORIGIN is unset',
        description: 'If CORS_ORIGIN env var is missing, all origins are accepted.',
        code_example: '// server CORS origin callback falls back to [\'*\']',
        cve: null,
      });
    }

    const hasCsrfMiddleware = /csrf|csurf|doubleCsrf/i.test(serverContent);
    if (!hasCsrfMiddleware) {
      const usesCookies = /cookie-parser|req\.cookies|res\.cookie/i.test(serverContent);
      if (usesCookies) {
        findings.push({
          type: 'vulnerability',
          title: 'Cookie-based auth without CSRF protection',
          description: 'The app uses cookies but no CSRF middleware is detected.',
          code_example: null,
          cve: 'CWE-352',
        });
      } else {
        findings.push({
          type: 'info',
          title: 'No CSRF middleware (acceptable for JWT Bearer auth)',
          description: 'No CSRF protection found. If authentication is purely via Authorization: Bearer headers, CSRF is not a concern.',
          code_example: null,
          cve: null,
        });
      }
    }

    const hasSanitization = /sanitize|xss|DOMPurify|validator\.escape|express-validator/i.test(serverContent);
    if (!hasSanitization) {
      const controllerMatches = await grepFiles(controllersDir, [/validator\.(escape|stripLow)|sanitize|xss/i], { extensions: ['.js'] });
      if (controllerMatches.length === 0) {
        findings.push({
          type: 'warning',
          title: 'No HTML/XSS sanitization detected in controllers',
          description: 'No use of validator.escape(), DOMPurify, or similar sanitization found.',
          code_example: null,
          cve: 'CWE-79',
        });
      }
    }
  }

  const reflectedInputMatches = await grepFiles(src, [/res\.(send|end)\s*\(.*req\.(body|params|query)/], { extensions: ['.js'] });
  if (reflectedInputMatches.length > 0) {
    const locations = reflectedInputMatches.slice(0, 3).map(m => `${m.filePath.replace(src, 'src')}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'warning',
      title: 'User input reflected directly in response',
      description: `Found res.send/end with req.body/params/query at: ${locations}. If Content-Type is text/html, this is a reflected XSS vector.`,
      code_example: reflectedInputMatches[0].line.trim(),
      cve: 'CWE-79',
    });
  }

  const sstiMatches = await grepFiles(src, [
    /res\.render\s*\([^,]+,\s*\{[^}]*req\.(body|query|params)/,
    /ejs\.render\s*\(.*req\./,
    /handlebars\.compile\s*\(.*req\./,
    /pug\.render\s*\(.*req\./,
  ], { extensions: ['.js'] });
  if (sstiMatches.length > 0) {
    const locs = sstiMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'Server-Side Template Injection (SSTI) risk',
      description: `Found template rendering with user-controlled data at: ${locs}.`,
      code_example: sstiMatches[0]?.line.trim() || null,
      cve: 'CWE-94',
    });
  }

  const domXssMatches = await grepFiles(src, [/innerHTML\s*=.*\+/, /document\.write\s*\(/, /eval\s*\(\s*.*req\.|eval\s*\(\s*.*data\./, /dangerouslySetInnerHTML/], { extensions: ['.js', '.html'], contextLines: 4 });
  const domXssFiltered = domXssMatches.filter(m => {
    const ctx = (m.line + (m.context?.before?.join(' ') || '') + (m.context?.after?.join(' ') || '')).replace(/\s+/g, ' ');
    // Ignore safe JSON-LD usage
    if (/ld\+json|JSON\.stringify/i.test(ctx)) return false;
    return true;
  });

  if (domXssFiltered.length > 0) {
    const locs = domXssFiltered.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'DOM-based XSS risk: innerHTML, document.write or dangerouslySetInnerHTML',
      description: `Found potentially dangerous DOM manipulation at: ${locs}.`,
      code_example: domXssFiltered[0]?.line?.trim() || null,
      cve: 'CWE-79',
    });
  }


  const evalMatches = await grepFiles(src, [/\beval\s*\(/, /new\s+Function\s*\(/, /vm\.runInThisContext/], { extensions: ['.js'] });
  const evalFiltered = evalMatches.filter(m => {
    if (m.line.trim().startsWith('//') || m.line.trim().startsWith('*')) return false;
    if (m.filePath.includes('.test.') || m.filePath.includes('.spec.') || m.filePath.includes('node_modules')) return false;
    return true;
  });
  if (evalFiltered.length > 0) {
    const locs = evalFiltered.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'eval() or new Function() detected in backend source',
      description: `Found dynamic code execution at: ${locs}.`,
      code_example: evalFiltered[0]?.line.trim() || null,
      cve: null,
    });
  }

  recommendations.push(
    'Set CORS_ORIGIN to an explicit allowlist; never fallback to \'*\'.',
    'Ensure all API endpoints return Content-Type: application/json.',
    'Use express-validator\'s escape() on any user input that might be rendered in HTML.',
    'Never pass req.body/query/params directly to template engines.',
    'Replace eval() and new Function() with safe alternatives.',
    'If authentication ever moves to cookies, add csurf or double-submit cookie CSRF protection.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 2 ? 'high' : vulnCount === 1 ? 'medium' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20 - warnCount * 8);

  return { id: 'xss', name: 'XSS & CSRF', severity, score, findings, recommendations, _codeSnippets };
}

// ─── Entry point ──────────────────────────────────────────────────────────────

export async function audit(depth) {
  const { isPython, src, structure } = await detectProjectType();
  if (isPython) return auditPython(src);
  return auditNode(structure);
}
