import path from 'path';
import { listFiles, readFile, grepFiles, discoverStructure, truncate } from '../utils/fileScanner.js';

const AUTH_MIDDLEWARE = [
  'authenticate', 'requireAuth', 'isAuthenticated', 'verifyToken',
  'authMiddleware', 'checkAuth', 'protect', 'authorize', 'guard',
  'requireOrgRole', 'requireModuleRole', 'authenticateExtension',
  'optionalAuthenticate', 'passport.authenticate', 'ensureLoggedIn',
];

/**
 * Parse a route file to find routes without auth middleware.
 */
function parseRouteFile(content, filePath) {
  const issues = [];
  const lines = content.split('\n');

  const hasGlobalAuth = AUTH_MIDDLEWARE.some(m => {
    return new RegExp(`router\\.use\\(.*\\b${m.replace('.', '\\.')}\\b`).test(content);
  });

  const routeRegex = /router\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g;
  let match;

  while ((match = routeRegex.exec(content)) !== null) {
    const method = match[1].toUpperCase();
    const routePath = match[2];
    const lineIndex = content.slice(0, match.index).split('\n').length - 1;
    const routeBlock = lines.slice(lineIndex, lineIndex + 6).join('\n');

    const hasAuth = AUTH_MIDDLEWARE.some(m => new RegExp(`\\b${m.replace('.', '\\.')}\\b`).test(routeBlock));

    if (!hasGlobalAuth && !hasAuth) {
      const isPublicOk = ['/health', '/webhook', '/callback', '/public', '/login', '/register', '/signup', '/forgot', '/reset', '/verify'].some(p => routePath.includes(p));

      // Admin/internal routes without auth are always flagged
      const isCritical = /\/admin|\/internal/.test(routePath);
      const isDebug = /\/debug|\/test|\/dev/.test(routePath);

      if (isCritical) {
        issues.push({ method, routePath, lineNumber: lineIndex + 1, filePath, severity: 'vulnerability', reason: 'admin/internal route without auth' });
      } else if (isDebug) {
        issues.push({ method, routePath, lineNumber: lineIndex + 1, filePath, severity: 'warning', reason: 'debug/test route exposed' });
      } else if (!isPublicOk) {
        issues.push({ method, routePath, lineNumber: lineIndex + 1, filePath, severity: 'warning', reason: 'no explicit auth middleware' });
      }
    }
  }

  return issues;
}

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const structure = await discoverStructure();
  const src = structure.srcDir;

  // Discover routes directory
  const routesDir = structure.dirs.routes || src;
  const routeFiles = await listFiles(routesDir, '.js');

  const criticalRoutes = [];
  const warnRoutes = [];

  for (const filePath of routeFiles) {
    const content = await readFile(filePath);
    if (!content) continue;

    const issues = parseRouteFile(content, filePath);
    for (const issue of issues) {
      if (issue.severity === 'vulnerability') criticalRoutes.push(issue);
      else warnRoutes.push(issue);
    }

    // Capture snippets for the first few route files
    const basename = path.basename(filePath);
    if (_codeSnippets && Object.keys(_codeSnippets).length < 3) {
      _codeSnippets[`routes/${basename}`] = truncate(content, 1200);
    }
  }

  // Report admin/internal routes without auth as vulnerabilities
  if (criticalRoutes.length > 0) {
    const routeList = criticalRoutes.slice(0, 5)
      .map(r => `${r.method} ${path.basename(r.filePath).replace('.routes.js', '')}${r.routePath}`)
      .join(', ');
    findings.push({
      type: 'vulnerability',
      title: `${criticalRoutes.length} admin/internal route(s) without authentication`,
      description: `Routes under /admin or /internal without auth middleware: ${routeList}${criticalRoutes.length > 5 ? ` (+${criticalRoutes.length - 5} more)` : ''}. These endpoints expose privileged operations to unauthenticated requests.`,
      code_example: null,
      cve: null,
    });
  }

  // Debug/test routes as warning
  const debugRoutes = warnRoutes.filter(r => r.reason === 'debug/test route exposed');
  if (debugRoutes.length > 0) {
    const routeList = debugRoutes.slice(0, 5)
      .map(r => `${r.method} ${path.basename(r.filePath).replace('.routes.js', '')}${r.routePath}`)
      .join(', ');
    findings.push({
      type: 'warning',
      title: `Debug/test routes detected: ${routeList}`,
      description: 'Routes matching /debug, /test, or /dev patterns are exposed. Debug endpoints in production can leak internal state or bypass controls. Gate them with auth or remove in production.',
      code_example: null,
      cve: null,
    });
  }

  // Other unprotected routes
  const genericWarnRoutes = warnRoutes.filter(r => r.reason === 'no explicit auth middleware');
  if (genericWarnRoutes.length > 0) {
    const routeList = genericWarnRoutes
      .slice(0, 10)
      .map(r => `${r.method} ${path.basename(r.filePath).replace('.routes.js', '')}${r.routePath}`)
      .join(', ');
    findings.push({
      type: 'warning',
      title: `${genericWarnRoutes.length} route(s) detected without explicit auth middleware`,
      description: `Routes without auth in their declaration: ${routeList}${genericWarnRoutes.length > 10 ? ` (+${genericWarnRoutes.length - 10} more)` : ''}. Verify each is intentionally public.`,
      code_example: null,
      cve: null,
    });
  }

  // Check for test/debug routes anywhere in source using grep
  const testRouteMatches = await grepFiles(routesDir, [
    /router\.(get|post|put|delete)\s*\(\s*['"`][^'"`]*(test|debug|dev)[^'"`]*['"`]/i,
  ], { extensions: ['.js'] });

  if (testRouteMatches.length > 0 && debugRoutes.length === 0) {
    findings.push({
      type: 'warning',
      title: 'Test/debug route patterns found in route files',
      description: `Found routes matching test/debug patterns: ${testRouteMatches.map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ')}. Review that these are not exposed in production.`,
      code_example: testRouteMatches[0]?.line.trim() || null,
      cve: null,
    });
  }

  // Check if any route index has tenant context enforcement
  const indexPath = path.join(routesDir, 'index.js');
  const indexContent = await readFile(indexPath);
  if (indexContent && !/tenantContext|runInTenantContext|setTenantId/i.test(indexContent)) {
    findings.push({
      type: 'warning',
      title: 'No explicit cross-tenant enforcement middleware visible in routes index',
      description: 'The routes/index.js does not show a global middleware enforcing tenantId scoping. If individual controllers query without tenant filtering, cross-tenant data access is possible.',
      code_example: null,
      cve: null,
    });
  }

  recommendations.push(
    'Add router.use(authenticate) at the top of every protected route file instead of per-route.',
    'Gate /admin and /internal routes with both authenticate and a role check (e.g., requireOrgRole(\'ADMIN\')).',
    'Remove or disable /debug, /test, /dev routes in production. Use NODE_ENV checks or separate router mounts.',
    'Add an integration test that verifies every non-public route returns 401 when called without a token.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 1 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 25 - warnCount * 8);

  return { id: 'api', name: 'API Endpoints', severity, score, findings, recommendations, _codeSnippets };
}
