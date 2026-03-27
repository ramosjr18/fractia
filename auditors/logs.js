import path from 'path';
import { grepFiles, discoverStructure } from '../utils/fileScanner.js';
import { detectProjectType } from '../utils/projectType.js';

// ─── Python / FastAPI logging audit ──────────────────────────────────────────

async function auditPython(src) {
  const findings = [];
  const recommendations = [];
  const py = ['.py'];

  // 1. Structured logging library (loguru, structlog, standard logging)
  const logLibMatches = await grepFiles(src, [
    /from loguru|import loguru|from structlog|import structlog|logging\.getLogger|logging\.config/i,
  ], { extensions: py });

  if (logLibMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No se detectó librería de logging estructurado',
      description:
        'No se encontró loguru, structlog ni logging.getLogger en el código. Sin un logger estructurado, los logs carecen de niveles de severidad, IDs de correlación y formato JSON legible por máquina.',
      code_example:
        '# pip install loguru\nfrom loguru import logger\n\n' +
        'logger.info("Request received", user_id=user.id, path=request.url.path)',
      cve: null,
    });
  }

  // 2. print() usage instead of logger (in non-test files)
  const printMatches = await grepFiles(src, [/\bprint\s*\(/], { extensions: py });
  const printFiltered = printMatches.filter(m =>
    !m.filePath.includes('test') && !m.filePath.includes('conftest') && !m.filePath.includes('migration')
  );

  if (printFiltered.length > 10) {
    const files = [...new Set(printFiltered.map(m => path.basename(m.filePath)))];
    findings.push({
      type: 'warning',
      title: `${printFiltered.length} llamadas a print() en código de producción (${files.length} archivos)`,
      description: `Uso excesivo de print() en: ${files.slice(0, 5).join(', ')}. print() no tiene niveles de severidad, no puede ser silenciado en producción y puede exponer datos sensibles en logs.`,
      code_example:
        '# Reemplazar:\nprint(f"User {user_id} logged in")\n\n' +
        '# Con:\nlogger.info("User logged in", user_id=user_id)',
      cve: null,
    });
  }

  // 3. Sensitive data in logs — passwords, tokens, secrets
  const sensitiveLogPatterns = [
    /logger\.\w+\s*\(.*password/i,
    /logger\.\w+\s*\(.*token/i,
    /logger\.\w+\s*\(.*secret/i,
    /print\s*\(.*password/i,
    /print\s*\(.*token/i,
    /logging\.\w+\s*\(.*password/i,
  ];

  const sensitiveMatches = await grepFiles(src, sensitiveLogPatterns, { extensions: py });
  const sensitiveFiltered = sensitiveMatches.filter(m =>
    !m.filePath.includes('test') && !m.filePath.includes('conftest')
  );

  if (sensitiveFiltered.length > 0) {
    const locs = sensitiveFiltered.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'Datos sensibles (password/token/secret) logueados directamente',
      description: `Se encontraron ${sensitiveFiltered.length} ubicaciones donde contraseñas, tokens o secretos aparecen en logs en: ${locs}. Estos valores aparecerán en texto plano en los archivos de log.`,
      code_example: sensitiveFiltered[0]?.line?.trim() || null,
      cve: null,
    });
  }

  // 4. Log sanitization / redaction
  const sanitizeMatches = await grepFiles(src, [
    /sanitize|redact|mask|filter.*log|log.*filter|sensitive.*field/i,
  ], { extensions: py });

  if (sanitizeMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No se detectó sanitización/redacción de logs',
      description:
        'Sin redacción de campos sensibles en los logs, passwords, tokens y PII del cuerpo de la petición pueden aparecer en texto plano en los archivos de log.',
      code_example:
        '# Con loguru:\nlogger.opt(record=True).bind(filter=lambda r: {\n' +
        '    r["extra"].pop("password", None)\n' +
        '    return True\n})',
      cve: null,
    });
  }

  // 5. Correlation / request IDs
  const correlationMatches = await grepFiles(src, [
    /request_id|correlation_id|trace_id|x.request.id/i,
  ], { extensions: py });

  if (correlationMatches.length === 0 && logLibMatches.length > 0) {
    findings.push({
      type: 'warning',
      title: 'No se detecta propagación de IDs de correlación/traza en los logs',
      description:
        'Sin request_id o trace_id en los logs, es imposible correlacionar todos los logs de una misma petición cuando hay errores o comportamientos inesperados.',
      code_example:
        'import uuid\nfrom loguru import logger\n\n' +
        '@app.middleware("http")\nasync def request_id_middleware(request, call_next):\n' +
        '    request_id = str(uuid.uuid4())\n' +
        '    with logger.contextualize(request_id=request_id):\n' +
        '        return await call_next(request)',
      cve: null,
    });
  }

  recommendations.push(
    'Adopta loguru o structlog para logging estructurado con niveles, IDs de correlación y salida JSON.',
    'Añade una capa de redacción que filtre passwords, tokens y PII antes de cualquier salida de log.',
    'Reemplaza todos los print() en código de producción con el logger estructurado.',
    'Propaga request_id en cada petición y añádelo a todos los logs del ciclo de vida de esa petición.',
    'Configura envío de logs a un SIEM (Datadog, ELK, Grafana Loki) con alertas sobre tasas de error y fallos de auth.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 1 ? 'high' : warnCount >= 3 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 25 - warnCount * 8);

  return { id: 'logs', name: 'Logging & Monitoreo', severity, score, findings, recommendations, _codeSnippets: {} };
}

// ─── Node.js / Express logging audit (original logic) ────────────────────────

async function auditNode(structure) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = structure.srcDir;
  const controllersDir = structure.dirs.controllers || path.join(src, 'controllers');
  const servicesDir = structure.dirs.services || path.join(src, 'services');
  const workersDir = structure.dirs.workers || path.join(src, 'workers');

  const loggerMatches = await grepFiles(src, [/winston|pino|bunyan|morgan|log4js/i], { extensions: ['.js'] });
  if (loggerMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No structured logging library detected',
      description: 'No winston, pino, bunyan, morgan, or log4js usage found. Without a structured logger, logs lack severity levels and machine-readable format.',
      code_example: null,
      cve: null,
    });
  }

  const consoleDirs = [controllersDir, servicesDir].filter(Boolean);
  let totalConsoleLogs = 0;
  const consoleLogFiles = new Set();

  for (const dir of consoleDirs) {
    const matches = await grepFiles(dir, [/console\.log\s*\(/], { extensions: ['.js'] });
    for (const m of matches) {
      if (!m.filePath.includes('.test.') && !m.filePath.includes('.spec.')) {
        totalConsoleLogs++;
        consoleLogFiles.add(path.basename(m.filePath));
      }
    }
  }

  if (totalConsoleLogs > 10) {
    findings.push({
      type: 'warning',
      title: `${totalConsoleLogs} console.log() calls in controllers/services (${consoleLogFiles.size} files)`,
      description: `Excessive console.log usage in: ${[...consoleLogFiles].slice(0, 5).join(', ')}. Replace with a structured logger.`,
      code_example: null,
      cve: null,
    });
  }

  const sensitiveLogPatterns = [
    /console\.(log|info|warn|error)\s*\(.*password/i,
    /console\.(log|info|warn|error)\s*\(.*token/i,
    /console\.(log|info|warn|error)\s*\(.*secret/i,
    /logger\.\w+\s*\(.*password/i,
  ];

  const sensitiveLogMatches = await grepFiles(src, sensitiveLogPatterns, { extensions: ['.js'] });
  const sensitiveFiltered = sensitiveLogMatches.filter(m =>
    !m.filePath.includes('.test.') && !m.filePath.includes('.spec.')
  );

  if (sensitiveFiltered.length > 0) {
    const locs = sensitiveFiltered.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'Sensitive data (password/token/secret) logged directly',
      description: `Found ${sensitiveFiltered.length} location(s) at: ${locs}. These values will appear in plain text in log files.`,
      code_example: sensitiveFiltered[0]?.line.trim() || null,
      cve: null,
    });
  }

  const sanitizeMatches = await grepFiles(src, [/sanitize|redact|mask/i], { extensions: ['.js'] });
  if (sanitizeMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No log sanitization/redaction detected',
      description: 'No sanitize, redact, or mask pattern found. Sensitive fields may appear in logs.',
      code_example: null,
      cve: null,
    });
  }

  if (workersDir) {
    const workerConsoleMatches = await grepFiles(workersDir, [/console\.(log|warn|error|info)/], { extensions: ['.js'] });
    if (workerConsoleMatches.length > 0) {
      const workerFiles = [...new Set(workerConsoleMatches.map(m => path.basename(m.filePath)))];
      findings.push({
        type: 'warning',
        title: `Workers use console.log directly (${workerFiles.length} file(s))`,
        description: `Workers ${workerFiles.join(', ')} use console.log instead of a structured logger.`,
        code_example: '// Replace:\nconsole.log(\'Processing job\', jobId)\n// With:\nlogger.info(\'Processing job\', { jobId, traceId })',
        cve: null,
      });
    }

    const workerCorrelationMatches = await grepFiles(workersDir, [/correlationId|traceId|requestId/i], { extensions: ['.js'] });
    if (workerCorrelationMatches.length === 0 && workerConsoleMatches?.length > 0) {
      findings.push({
        type: 'warning',
        title: 'Workers have no correlation/trace ID propagation',
        description: 'Workers do not propagate correlation or trace IDs.',
        code_example: null,
        cve: null,
      });
    }
  }

  recommendations.push(
    'Adopt a structured logger (pino or winston) with log levels, correlation IDs, and JSON output.',
    'Add a log redaction layer that strips passwords, tokens, and sensitive PII before any log output.',
    'Replace console.log in controllers/services/workers with the structured logger.',
    'In workers, always propagate traceId and tenantId from the job payload.',
    'Set up log shipping to a SIEM with alerting on error rates and auth failures.',
  );

  const criticalCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = criticalCount >= 1 ? 'high' : warnCount >= 3 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - criticalCount * 25 - warnCount * 8);

  return { id: 'logs', name: 'Logging & Monitoreo', severity, score, findings, recommendations, _codeSnippets };
}

// ─── Entry point ──────────────────────────────────────────────────────────────

export async function audit(depth) {
  const { isPython, src, structure } = await detectProjectType();
  if (isPython) return auditPython(src);
  return auditNode(structure);
}
