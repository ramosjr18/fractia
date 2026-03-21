import path from 'path';
import { grepFiles, discoverStructure } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const structure = await discoverStructure();
  const src = structure.srcDir;
  const controllersDir = structure.dirs.controllers || path.join(src, 'controllers');
  const servicesDir = structure.dirs.services || path.join(src, 'services');
  const workersDir = structure.dirs.workers || path.join(src, 'workers');

  // --- Structured logging library detection ---
  const loggerMatches = await grepFiles(src, [
    /winston|pino|bunyan|morgan|log4js/i,
  ], { extensions: ['.js'] });

  if (loggerMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No structured logging library detected',
      description: 'No winston, pino, bunyan, morgan, or log4js usage found in source. Without a structured logger, logs lack severity levels, correlation IDs, and machine-readable format — making incident response harder.',
      code_example: null,
      cve: null,
    });
  }

  // --- console.log count in controllers/services (not tests) ---
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
      description: `Excessive console.log usage in: ${[...consoleLogFiles].slice(0, 5).join(', ')}. This leaks internal data to server logs without severity control. Replace with a structured logger that supports log levels and redaction.`,
      code_example: null,
      cve: null,
    });
  }

  // --- Sensitive data logged directly ---
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
      description: `Found ${sensitiveFiltered.length} location(s) where passwords, tokens, or secrets appear in log statements at: ${locs}. These values will appear in plain text in log files, which may be persisted to disk, shipped to log aggregators, or readable by support teams.`,
      code_example: sensitiveFiltered[0]?.line.trim() || null,
      cve: null,
    });
  }

  // --- Log sanitization check ---
  const sanitizeMatches = await grepFiles(src, [
    /sanitize|redact|mask/i,
  ], { extensions: ['.js'] });

  if (sanitizeMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No log sanitization/redaction detected',
      description: 'No sanitize, redact, or mask pattern found in source. Without log sanitization, sensitive fields (tokens, passwords, PII) from request bodies may appear in server logs.',
      code_example: null,
      cve: null,
    });
  }

  // --- Workers: console.log and correlation ID ---
  if (workersDir) {
    const workerConsoleMatches = await grepFiles(workersDir, [/console\.(log|warn|error|info)/], {
      extensions: ['.js'],
    });

    if (workerConsoleMatches.length > 0) {
      const workerFiles = [...new Set(workerConsoleMatches.map(m => path.basename(m.filePath)))];
      findings.push({
        type: 'warning',
        title: `Workers use console.log directly (${workerFiles.length} file(s))`,
        description: `Workers ${workerFiles.join(', ')} use console.log instead of a structured logger. This loses correlation IDs, tenant context, and structured fields — making worker failures impossible to trace back to requests.`,
        code_example: '// Replace:\nconsole.log(\'Processing job\', jobId)\n// With:\nlogger.info(\'Processing job\', { jobId, traceId })',
        cve: null,
      });
    }

    const workerCorrelationMatches = await grepFiles(workersDir, [
      /correlationId|traceId|requestId/i,
    ], { extensions: ['.js'] });

    if (workerCorrelationMatches.length === 0 && workerConsoleMatches.length > 0) {
      findings.push({
        type: 'warning',
        title: 'Workers have no correlation/trace ID propagation',
        description: 'Workers do not propagate correlation or trace IDs. When a worker fails, you cannot link the failure back to the original HTTP request or tenant context.',
        code_example: null,
        cve: null,
      });
    }
  }

  recommendations.push(
    'Adopt a structured logger (pino or winston) with log levels, correlation IDs, and machine-readable JSON output.',
    'Add a log redaction layer that strips passwords, tokens, and sensitive PII before any log output.',
    'Replace console.log in controllers/services/workers with the structured logger.',
    'In workers, always propagate traceId and tenantId from the job payload into every log call.',
    'Set up log shipping to a SIEM (Datadog, Splunk, ELK) with alerting on error rates and auth failures.',
  );

  const criticalCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = criticalCount >= 1 ? 'high' : warnCount >= 3 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - criticalCount * 25 - warnCount * 8);

  return { id: 'logs', name: 'Logging & Monitoreo', severity, score, findings, recommendations, _codeSnippets };
}
