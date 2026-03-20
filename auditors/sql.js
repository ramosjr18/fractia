import path from 'path';
import { grepFiles, readFile, BACKEND_SRC, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = BACKEND_SRC();

  // --- Scan for $queryRaw and $executeRaw usage ---
  const rawQueryMatches = await grepFiles(src, [
    /\$queryRaw/,
    /\$executeRaw/,
    /\$queryRawUnsafe/,
    /\$executeRawUnsafe/,
  ], { extensions: ['.js'], contextLines: 3 });

  // Analyze each raw query for safety
  const unsafeMatches = [];
  const safeMatches = [];

  for (const match of rawQueryMatches) {
    // $queryRawUnsafe / $executeRawUnsafe are always dangerous
    if (/\$queryRawUnsafe|\$executeRawUnsafe/.test(match.line)) {
      unsafeMatches.push(match);
      continue;
    }

    // Tagged template literals (Prisma parameterizes these safely):
    // $queryRaw`SELECT ...` or $executeRaw`SELECT ...`
    const isTaggedTemplate = /\$(?:queryRaw|executeRaw)\s*`/.test(match.line);
    // String concatenation is dangerous
    const hasStringConcat = /\+\s*(?:req\.|params\.|body\.|query\.)|\$\{.*(?:req\.|params\.|body\.|query\.)/.test(
      match.context.before.join('') + match.line + match.context.after.join('')
    );

    if (!isTaggedTemplate || hasStringConcat) {
      unsafeMatches.push(match);
    } else {
      safeMatches.push(match);
    }
  }

  if (unsafeMatches.length > 0) {
    for (const m of unsafeMatches) {
      const relPath = m.filePath.replace(src, 'src');
      findings.push({
        type: 'vulnerability',
        title: `Potentially unsafe raw query at ${relPath}:${m.lineNumber}`,
        description: `${m.line.trim()} — Either uses $queryRawUnsafe/$executeRawUnsafe or appears to concatenate user input into a SQL string. This bypasses Prisma's parameterization and is vulnerable to SQL injection.`,
        code_example: m.line.trim(),
        cve: 'CVE-2023-32066',
      });
    }
  }

  if (safeMatches.length > 0) {
    findings.push({
      type: 'info',
      title: `${safeMatches.length} raw SQL queries found (tagged templates — safe)`,
      description: `Found $queryRaw/$executeRaw usage in: ${[...new Set(safeMatches.map(m => path.basename(m.filePath)))].join(', ')}. These use Prisma's tagged template literal syntax which automatically parameterizes values. Verify that no user input is interpolated unsafely.`,
      code_example: safeMatches[0]?.line.trim() || null,
      cve: null,
    });
  }

  // --- Scan for ORM bypass patterns ---
  const ormBypassMatches = await grepFiles(src, [
    /\.query\s*\(\s*['"`].*\+/,  // string concat in query()
    /\.execute\s*\(\s*['"`].*\+/,
    /knex\.raw\s*\(/,
    /sequelize\.query\s*\(/,
  ], { extensions: ['.js'] });

  if (ormBypassMatches.length > 0) {
    findings.push({
      type: 'warning',
      title: 'Possible ORM-bypass raw query patterns detected',
      description: `Found patterns that suggest raw query string construction: ${ormBypassMatches.map(m => path.basename(m.filePath)).join(', ')}. Review these for user input injection.`,
      code_example: ormBypassMatches[0]?.line.trim() || null,
      cve: null,
    });
  }

  // --- Check for missing tenantId in queries (cross-tenant risk) ---
  const controllerFiles = await grepFiles(path.join(src, 'controllers'), [
    /prisma\.\w+\.findMany\s*\(\s*\{(?![^}]*tenantId)/,
    /prisma\.\w+\.findFirst\s*\(\s*\{(?![^}]*tenantId)/,
  ], { extensions: ['.js'], contextLines: 5 });

  // Filter out cases where tenantId might be in nearby context
  const missingTenant = controllerFiles.filter(m => {
    const fullContext = m.context.before.join('') + m.line + m.context.after.join('');
    return !/tenantId|tenant_id|runInTenantContext/.test(fullContext);
  });

  if (missingTenant.length > 0) {
    const locs = missingTenant.slice(0, 3).map(m => {
      const relPath = m.filePath.replace(src, 'src');
      return `${relPath}:${m.lineNumber}`;
    }).join(', ');
    findings.push({
      type: 'warning',
      title: 'Prisma queries may be missing tenantId filter',
      description: `Found findMany/findFirst calls without visible tenantId in context: ${locs}. In a multi-tenant app, every query must be scoped to the current tenant. Missing filters allow cross-tenant data access.`,
      code_example: missingTenant[0]?.line.trim() || null,
      cve: null,
    });
  }

  recommendations.push(
    'Never use $queryRawUnsafe or $executeRawUnsafe. Use Prisma\'s tagged template $queryRaw`...` which auto-parameterizes.',
    'Add a lint rule or test to verify every findMany/findFirst/findUnique query includes a tenantId where clause.',
    'Consider adding a Prisma middleware that automatically injects tenantId from the request context into all queries.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 1 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 30 - warnCount * 10);

  return { id: 'sql', name: 'Inyecciones SQL/NoSQL', severity, score, findings, recommendations, _codeSnippets };
}
