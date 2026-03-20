import path from 'path';
import { readFile, readDir, grepFiles, BACKEND_SRC, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = BACKEND_SRC();
  const loggingDir = path.join(src, 'modules', 'logging', 'services');

  // --- Check SecurityLogger implementation ---
  const secLogPath = path.join(loggingDir, 'security-logger.service.js');
  const secLog = await readFile(secLogPath);

  if (secLog) {
    _codeSnippets['modules/logging/services/security-logger.service.js'] = truncate(secLog, 1500);

    // Detect if the log() method body is effectively empty (only comments/whitespace)
    const stripped = secLog
      .replace(/\/\/.*$/gm, '')          // remove line comments
      .replace(/\/\*[\s\S]*?\*\//g, '')  // remove block comments
      .replace(/\s+/g, ' ');

    const hasImplementation = /\.create\(|\.insert\(|\.log\(|prisma\.|db\.|save\(|persist\(|emit\(|winston|pino|console\.log/.test(stripped);

    if (!hasImplementation) {
      findings.push({
        type: 'vulnerability',
        title: 'SecurityLogger.log() is an empty stub — zero security events are persisted',
        description: 'The SecurityLogger service exists but its log() method has no implementation. Security events (failed logins, access denied, cross-tenant attempts, token errors) are silently dropped. Incident detection is impossible.',
        code_example: '// security-logger.service.js\nlog(event) {\n  // TODO: implement\n}',
        cve: null,
      });
    }
  } else {
    findings.push({
      type: 'warning',
      title: 'SecurityLogger service file not found',
      description: `Expected at modules/logging/services/security-logger.service.js. Security event logging may not be implemented.`,
      code_example: null,
      cve: null,
    });
  }

  // --- Check AuditLogger implementation ---
  const auditLogPath = path.join(loggingDir, 'audit-logger.service.js');
  const auditLog = await readFile(auditLogPath);

  if (auditLog) {
    _codeSnippets['modules/logging/services/audit-logger.service.js'] = truncate(auditLog, 1500);

    const stripped = auditLog
      .replace(/\/\/.*$/gm, '')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\s+/g, ' ');

    const hasImplementation = /\.create\(|\.insert\(|prisma\.|db\.|save\(|persist\(|emit\(/.test(stripped);

    if (!hasImplementation) {
      findings.push({
        type: 'vulnerability',
        title: 'AuditLogger.log() is an empty stub — no audit trail',
        description: 'The AuditLogger service is not persisting events to the database. User actions like role changes, candidate deletions, job closings, and invitations leave no audit trail. This violates compliance requirements (GDPR, SOC2).',
        code_example: '// audit-logger.service.js\nlog(event) {\n  // TODO: implement\n}',
        cve: null,
      });
    }
  }

  // --- Check LogSanitizer usage ---
  const sanitizerPath = path.join(src, 'modules', 'logging', 'services', 'log-sanitizer.service.js');
  const sanitizer = await readFile(sanitizerPath);

  if (sanitizer) {
    // Check if sanitizer is actually called anywhere else
    const usageMatches = await grepFiles(src, [/logSanitizer\.sanitize|sanitizer\.sanitize/i], {
      extensions: ['.js'],
    });

    const externalUsage = usageMatches.filter(m => !m.filePath.includes('log-sanitizer'));
    if (externalUsage.length === 0) {
      findings.push({
        type: 'warning',
        title: 'LogSanitizer is defined but never called',
        description: 'The logSanitizer service exists to redact passwords, tokens, and PII from logs, but no code outside its own file calls sanitizer.sanitize(). Sensitive data may be logged in plain text.',
        code_example: null,
        cve: null,
      });
    }
  }

  // --- Check workers for console.log usage ---
  const workersDir = path.join(src, 'workers');
  const consoleMatches = await grepFiles(workersDir, [/console\.(log|warn|error|info)/], {
    extensions: ['.js'],
  });

  if (consoleMatches.length > 0) {
    const workerFiles = [...new Set(consoleMatches.map(m => path.basename(m.filePath)))];
    findings.push({
      type: 'warning',
      title: `Workers use console.log directly (${workerFiles.length} file(s))`,
      description: `Workers ${workerFiles.join(', ')} use console.log instead of the structured logger. This loses correlation IDs, tenant context, and structured fields — making worker failures impossible to trace back to original requests.`,
      code_example: `// In workers — replace:\nconsole.log('Processing job', jobId)\n// With:\nappLogger.info('Processing job', { jobId, traceId, tenantId })`,
      cve: null,
    });
  }

  // --- Check correlation ID propagation in workers ---
  const workerFiles = await readDir(workersDir, ['.js']);
  for (const { filePath, content } of workerFiles) {
    if (!/correlationId|traceId|requestId/i.test(content)) {
      findings.push({
        type: 'warning',
        title: `Worker ${path.basename(filePath)} has no correlation ID`,
        description: `${path.basename(filePath)} does not propagate correlation/trace IDs. When this worker fails, you cannot link the failure back to the original HTTP request or tenant.`,
        code_example: null,
        cve: null,
      });
      break; // Only report once
    }
  }

  recommendations.push(
    'Implement SecurityLogger.log() to persist to a security_events table. Minimum events: login failures, 403/401 responses, cross-tenant access attempts.',
    'Implement AuditLogger.log() to persist to an audit_log table. Include: actor_id, tenant_id, action, resource_type, resource_id, timestamp.',
    'Wire LogSanitizer into AppLogger so all log calls automatically redact sensitive fields.',
    'Replace console.log in workers with the structured appLogger, passing traceId and tenantId from the job data.',
  );

  const criticalCount = findings.filter(f => f.type === 'vulnerability').length;
  const severity = criticalCount >= 2 ? 'critical' : criticalCount === 1 ? 'high' : findings.some(f => f.type === 'warning') ? 'medium' : 'ok';
  const score = Math.max(0, 100 - criticalCount * 25 - findings.filter(f => f.type === 'warning').length * 8);

  return { id: 'logs', name: 'Logging & Monitoreo', severity, score, findings, recommendations, _codeSnippets };
}
