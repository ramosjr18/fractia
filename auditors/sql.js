import path from 'path';
import { grepFiles, discoverStructure } from '../utils/fileScanner.js';
import { detectProjectType } from '../utils/projectType.js';

// ─── Python / FastAPI SQL injection audit ─────────────────────────────────────

async function auditPython(src) {
  const findings = [];
  const recommendations = [];
  const py = ['.py'];

  // 1. Raw SQL with f-strings or string concatenation — highest risk
  const rawFstringMatches = await grepFiles(src, [
    /(?:execute|cursor\.execute|db\.execute|session\.execute)\s*\(\s*f["']/,
    /(?:execute|cursor\.execute|db\.execute|session\.execute)\s*\(\s*["'][^"']*"\s*\+/,
  ], { extensions: py });

  const rawFiltered = rawFstringMatches.filter(m =>
    !m.filePath.includes('test') && !m.filePath.includes('migration') && !m.line?.trim().startsWith('#')
  );

  if (rawFiltered.length > 0) {
    for (const m of rawFiltered.slice(0, 5)) {
      findings.push({
        type: 'vulnerability',
        title: `SQL raw con f-string/concatenación en ${path.basename(m.filePath)}:${m.lineNumber}`,
        description:
          `${m.line?.trim()} — SQL construido con f-string o concatenación de strings permite SQL injection directa. ` +
          'Usar text() de SQLAlchemy con parámetros bindados es la alternativa segura.',
        code_example:
          '# Vulnerable:\nexecute(f"SELECT * FROM users WHERE id = {user_id}")\n\n' +
          '# Correcto (SQLAlchemy):\nfrom sqlalchemy import text\nsession.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})',
        cve: 'CWE-89',
      });
    }
  }

  // 2. text() with f-strings (SQLAlchemy text() but still vulnerable)
  const textFstringMatches = await grepFiles(src, [
    /text\s*\(\s*f["']/,
    /text\s*\(\s*["'][^"']*"\s*\+/,
  ], { extensions: py });

  const textFiltered = textFstringMatches.filter(m =>
    !m.filePath.includes('test') && !m.filePath.includes('migration') && !m.line?.trim().startsWith('#')
  );

  if (textFiltered.length > 0) {
    const locs = textFiltered.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'SQLAlchemy text() con f-string — parametrización bypass',
      description:
        `text() con f-string en: ${locs}. Aunque se usa SQLAlchemy, construir el string SQL con f-strings antes de pasarlo a text() bypassa completamente la parametrización.`,
      code_example:
        '# Vulnerable:\ntext(f"SELECT * FROM users WHERE id = {user_id}")\n\n' +
        '# Correcto:\ntext("SELECT * FROM users WHERE id = :id").bindparams(id=user_id)',
      cve: 'CWE-89',
    });
  }

  // 3. Safe SQLAlchemy ORM usage (info — good pattern detected)
  const ormMatches = await grepFiles(src, [
    /session\.query\s*\(|db\.query\s*\(|\.filter\s*\(|\.filter_by\s*\(|select\s*\(/,
  ], { extensions: py });

  if (ormMatches.length > 0 && rawFiltered.length === 0 && textFiltered.length === 0) {
    findings.push({
      type: 'info',
      title: `${ormMatches.length} queries via ORM (SQLAlchemy) — patrón seguro`,
      description:
        'Se detectó el uso del ORM de SQLAlchemy. Las queries ORM son parametrizadas automáticamente, protegiéndolas de SQL injection.',
      code_example: null,
      cve: null,
    });
  }

  // 4. NoSQL patterns (MongoDB via motor/pymongo)
  const noSqlMatches = await grepFiles(src, [
    /\$where|\$gt|\$lt|\$ne|\$in.*request\.|find\(\s*\{.*request\./,
  ], { extensions: py });

  if (noSqlMatches.length > 0) {
    const locs = noSqlMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'Posible NoSQL injection via operadores MongoDB con input de usuario',
      description: `Operadores MongoDB ($where, $gt, $lt, $ne, $in) con datos de usuario en: ${locs}. Si el input no está sanitizado, puede manipular la lógica de la query.`,
      code_example: noSqlMatches[0]?.line?.trim() || null,
      cve: 'CWE-943',
    });
  }

  // 5. Parameterized queries check for raw psycopg2/sqlite3 usage
  const rawDbMatches = await grepFiles(src, [
    /cursor\.execute\s*\(|conn\.execute\s*\(/,
  ], { extensions: py });

  const unsafeRaw = rawDbMatches.filter(m => {
    const line = m.line || '';
    // Check if it uses %s or ? parameterization (safe) vs f-string (already caught)
    return !line.includes('%s') && !line.includes('?') && !line.includes(':') &&
      (line.includes('f"') || line.includes("f'") || line.includes('" +') || line.includes("' +"));
  });

  // Already caught above, skip duplicates

  // 6. Second-order injection patterns
  const secondOrderMatches = await grepFiles(src, [
    /\.first\(\).*execute|\.one\(\).*execute/,
  ], { extensions: py });

  if (secondOrderMatches.length > 0) {
    findings.push({
      type: 'warning',
      title: 'Posible inyección de segundo orden detectada',
      description:
        `Patrón donde un valor obtenido de la BD se usa en una query posterior en: ${secondOrderMatches.slice(0, 2).map(m => path.basename(m.filePath)).join(', ')}. Si el valor almacenado era input de usuario no sanitizado, puede inyectarse en la segunda query.`,
      code_example: secondOrderMatches[0]?.line?.trim() || null,
      cve: null,
    });
  }

  recommendations.push(
    'Usa siempre el ORM de SQLAlchemy o queries parametrizadas con :param — nunca construyas SQL con f-strings.',
    'Si usas text() de SQLAlchemy, usa .bindparams(param=value) en lugar de f-strings.',
    'Con psycopg2 o sqlite3, usa placeholders %s o ? y pasa los valores como segundo argumento de execute().',
    'Valida y sanitiza el input de usuario antes de usarlo como filtro en queries MongoDB para prevenir operator injection.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 1 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 30 - warnCount * 10);

  return { id: 'sql', name: 'Inyecciones SQL/NoSQL', severity, score, findings, recommendations, _codeSnippets: {} };
}

// ─── Node.js / Prisma SQL injection audit (original logic) ───────────────────

async function auditNode(structure) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = structure.srcDir;
  const controllersDir = structure.dirs.controllers || path.join(src, 'controllers');

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
        description: `${m.line.trim()} — Either uses $queryRawUnsafe/$executeRawUnsafe or concatenates user input into a SQL string.`,
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
      description: `Found patterns suggesting raw query string construction: ${ormBypassMatches.map(m => path.basename(m.filePath)).join(', ')}.`,
      code_example: ormBypassMatches[0]?.line.trim() || null,
      cve: null,
    });
  }

  const missingTenantMatches = await grepFiles(controllersDir, [
    /prisma\.\w+\.findMany\s*\(\s*\{(?![^}]*tenantId)/,
    /prisma\.\w+\.findFirst\s*\(\s*\{(?![^}]*tenantId)/,
  ], { extensions: ['.js'], contextLines: 5 });

  const missingTenant = missingTenantMatches.filter(m => {
    const fullContext = m.context.before.join('') + m.line + m.context.after.join('');
    return !/tenantId|tenant_id|runInTenantContext/.test(fullContext);
  });

  if (missingTenant.length > 0) {
    const locs = missingTenant.slice(0, 3).map(m => `${m.filePath.replace(src, 'src')}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'warning',
      title: 'Prisma queries may be missing tenantId filter',
      description: `Found findMany/findFirst without visible tenantId in context: ${locs}.`,
      code_example: missingTenant[0]?.line.trim() || null,
      cve: null,
    });
  }

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
      description: `Found MongoDB query operators with user input at: ${locs}.`,
      code_example: noSqlMatches[0]?.line.trim() || null,
      cve: 'CWE-943',
    });
  }

  const secondOrderMatches = await grepFiles(src, [
    /findOne.*then.*query\s*\(/,
    /findOne.*then.*execute\s*\(/,
  ], { extensions: ['.js'] });

  if (secondOrderMatches.length > 0) {
    findings.push({
      type: 'warning',
      title: 'Possible second-order injection pattern detected',
      description: `Found patterns where a value from DB is passed to a subsequent query: ${secondOrderMatches.map(m => path.basename(m.filePath)).join(', ')}.`,
      code_example: secondOrderMatches[0]?.line.trim() || null,
      cve: null,
    });
  }

  const mongooseFindAllMatches = await grepFiles(controllersDir, [/\.find\s*\(\s*\{\s*\}\s*\)/], { extensions: ['.js'] });
  if (mongooseFindAllMatches.length > 0) {
    const locs = mongooseFindAllMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'warning',
      title: 'Mongoose .find({}) with no filters in controllers',
      description: `Found .find({}) (empty filter — returns all documents) at: ${locs}.`,
      code_example: '.find({})  // Consider adding filters: .find({ tenantId, isActive: true })',
      cve: null,
    });
  }

  recommendations.push(
    'Never use $queryRawUnsafe or $executeRawUnsafe. Use Prisma\'s tagged template $queryRaw`...`.',
    'Validate and sanitize user input before using it in any database query.',
    'Add a lint rule to verify every findMany/findFirst/findUnique includes appropriate scoping.',
    'Avoid passing unsanitized request values directly into MongoDB queries.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 1 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 30 - warnCount * 10);

  return { id: 'sql', name: 'Inyecciones SQL/NoSQL', severity, score, findings, recommendations, _codeSnippets };
}

// ─── Entry point ──────────────────────────────────────────────────────────────

export async function audit(depth) {
  const { isPython, src, structure } = await detectProjectType();
  if (isPython) return auditPython(src);
  return auditNode(structure);
}
