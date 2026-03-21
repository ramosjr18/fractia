import path from 'path';
import { grepFiles, discoverStructure } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const structure = await discoverStructure();
  const src = structure.srcDir;
  const controllersDir = structure.dirs.controllers || path.join(src, 'controllers');

  // --- Scan for $queryRaw and $executeRaw usage ---
  const rawQueryMatches = await grepFiles(src, [
    /\$queryRaw/,
    /\$executeRaw/,
    /\$queryRawUnsafe/,
    /\$executeRawUnsafe/,
  ], { extensions: ['.js'], contextLines: 3 });

  const unsafeMatches = [];
  const safeMatches = [];

  for (const match of rawQueryMatches) {
    if (/\$queryRawUnsafe|\$executeRawUnsafe/.test(match.line)) {
      unsafeMatches.push(match);
      continue;
    }
    const isTaggedTemplate = /\$(?:queryRaw|executeRaw)\s*`/.test(match.line);
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
        description: `${m.line.trim()} — Either uses $queryRawUnsafe/$executeRawUnsafe or concatenates user input into a SQL string. This bypasses parameterization and is vulnerable to SQL injection.`,
        code_example: m.line.trim(),
        cve: 'CVE-2023-32066',
      });
    }
  }

  if (safeMatches.length > 0) {
    findings.push({
      type: 'info',
      title: `${safeMatches.length} raw SQL queries found (tagged templates — safe)`,
      description: `Found $queryRaw/$executeRaw in: ${[...new Set(safeMatches.map(m => path.basename(m.filePath)))].join(', ')}. These use tagged template syntax which auto-parameterizes values.`,
      code_example: safeMatches[0]?.line.trim() || null,
      cve: null,
    });
  }

  // --- ORM bypass patterns ---
  const ormBypassMatches = await grepFiles(src, [
    /\.query\s*\(\s*['"`].*\+/,
    /\.execute\s*\(\s*['"`].*\+/,
    /knex\.raw\s*\(/,
    /sequelize\.query\s*\(/,
  ], { extensions: ['.js'] });

  if (ormBypassMatches.length > 0) {
    findings.push({
      type: 'warning',
      title: 'Possible ORM-bypass raw query patterns detected',
      description: `Found patterns suggesting raw query string construction: ${ormBypassMatches.map(m => path.basename(m.filePath)).join(', ')}. Review for user input injection.`,
      code_example: ormBypassMatches[0]?.line.trim() || null,
      cve: null,
    });
  }

  // --- Missing tenantId in queries ---
  const missingTenantMatches = await grepFiles(controllersDir, [
    /prisma\.\w+\.findMany\s*\(\s*\{(?![^}]*tenantId)/,
    /prisma\.\w+\.findFirst\s*\(\s*\{(?![^}]*tenantId)/,
  ], { extensions: ['.js'], contextLines: 5 });

  const missingTenant = missingTenantMatches.filter(m => {
    const fullContext = m.context.before.join('') + m.line + m.context.after.join('');
    return !/tenantId|tenant_id|runInTenantContext/.test(fullContext);
  });

  if (missingTenant.length > 0) {
    const locs = missingTenant.slice(0, 3).map(m => {
      return `${m.filePath.replace(src, 'src')}:${m.lineNumber}`;
    }).join(', ');
    findings.push({
      type: 'warning',
      title: 'Prisma queries may be missing tenantId filter',
      description: `Found findMany/findFirst without visible tenantId in context: ${locs}. In a multi-tenant app, every query must be scoped to the current tenant.`,
      code_example: missingTenant[0]?.line.trim() || null,
      cve: null,
    });
  }

  // --- NoSQL injection ---
  const noSqlMatches = await grepFiles(src, [
    /req\.(body|query|params)\.\w+.*\$where/,
    /req\.(body|query|params)\.\w+.*(\$gt|\$lt|\$ne|\$in)/,
    /JSON\.parse\s*\(\s*req\./,
  ], { extensions: ['.js'] });

  if (noSqlMatches.length > 0) {
    const locs = noSqlMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'Potential NoSQL injection via user-controlled query operators',
      description: `Found MongoDB query operators ($where, $gt, $lt, $ne, $in) or JSON.parse of user input at: ${locs}. Unsanitized user input passed to MongoDB queries can manipulate query logic.`,
      code_example: noSqlMatches[0]?.line.trim() || null,
      cve: 'CWE-943',
    });
  }

  // --- Second-order injection ---
  const secondOrderMatches = await grepFiles(src, [
    /findOne.*then.*query\s*\(/,
    /findOne.*then.*execute\s*\(/,
  ], { extensions: ['.js'] });

  if (secondOrderMatches.length > 0) {
    findings.push({
      type: 'warning',
      title: 'Possible second-order injection pattern detected',
      description: `Found patterns where a value retrieved from the database is passed into a subsequent query: ${secondOrderMatches.map(m => path.basename(m.filePath)).join(', ')}. If the stored value was user-supplied and not sanitized on write, it can inject into the second query.`,
      code_example: secondOrderMatches[0]?.line.trim() || null,
      cve: null,
    });
  }

  // --- Mongoose find({}) without filters ---
  const mongooseFindAllMatches = await grepFiles(controllersDir, [
    /\.find\s*\(\s*\{\s*\}\s*\)/,
  ], { extensions: ['.js'] });

  if (mongooseFindAllMatches.length > 0) {
    const locs = mongooseFindAllMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'warning',
      title: 'Mongoose .find({}) with no filters in controllers',
      description: `Found .find({}) (empty filter — returns all documents) in controllers at: ${locs}. In multi-tenant or permissioned systems this may expose all records. Ensure proper scoping before returning results.`,
      code_example: '.find({})  // Consider adding filters: .find({ tenantId, isActive: true })',
      cve: null,
    });
  }

  recommendations.push(
    'Never use $queryRawUnsafe or $executeRawUnsafe. Use Prisma\'s tagged template $queryRaw`...` which auto-parameterizes.',
    'Validate and sanitize user input before using it in any database query — especially for MongoDB operator keys ($where, $gt, etc.).',
    'Add a lint rule or test to verify every findMany/findFirst/findUnique includes appropriate scoping (tenantId, userId).',
    'Avoid passing unsanitized request values directly into MongoDB queries. Use allowlist validation for query operators.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 1 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 30 - warnCount * 10);

  return { id: 'sql', name: 'Inyecciones SQL/NoSQL', severity, score, findings, recommendations, _codeSnippets };
}
