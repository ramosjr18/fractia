import path from 'path';
import { listFiles, readFile, BACKEND_SRC, truncate } from '../utils/fileScanner.js';

const AUTH_MIDDLEWARE = ['authenticate', 'requireOrgRole', 'requireModuleRole', 'authorize', 'authenticateExtension', 'optionalAuthenticate'];

/**
 * Parse a route file to find:
 * 1. Whether router.use(authenticate) is present (protects all routes)
 * 2. Individual route definitions and their middleware chains
 */
function parseRouteFile(content, filePath) {
  const issues = [];
  const lines = content.split('\n');

  // Check for global router.use(authenticate) — protects all routes in file
  const hasGlobalAuth = AUTH_MIDDLEWARE.some(m => {
    return new RegExp(`router\\.use\\(.*\\b${m}\\b`).test(content);
  });

  // Find all route definitions: router.get/post/put/delete/patch(path, ...handlers)
  const routeRegex = /router\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g;
  let match;

  while ((match = routeRegex.exec(content)) !== null) {
    const method = match[1].toUpperCase();
    const routePath = match[2];
    const lineIndex = content.slice(0, match.index).split('\n').length - 1;

    // Get the full route declaration (look ahead up to 5 lines)
    const routeBlock = lines.slice(lineIndex, lineIndex + 6).join('\n');

    // Check if any auth middleware appears in the route block
    const hasAuth = AUTH_MIDDLEWARE.some(m => new RegExp(`\\b${m}\\b`).test(routeBlock));

    if (!hasGlobalAuth && !hasAuth) {
      // Skip known intentionally public patterns
      const isPublicOk = ['/health', '/webhook', '/callback', '/public'].some(p => routePath.includes(p));
      if (!isPublicOk) {
        issues.push({ method, routePath, lineNumber: lineIndex + 1, filePath });
      }
    }
  }

  return issues;
}

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = BACKEND_SRC();
  const routesDir = path.join(src, 'routes');

  const routeFiles = await listFiles(routesDir, '.js');
  const unprotectedRoutes = [];

  for (const filePath of routeFiles) {
    const content = await readFile(filePath);
    if (!content) continue;

    const issues = parseRouteFile(content, filePath);
    unprotectedRoutes.push(...issues);

    // Capture snippets for critical files
    const basename = path.basename(filePath);
    if (['auth.routes.js', 'admin.routes.js', 'index.js'].includes(basename)) {
      _codeSnippets[`routes/${basename}`] = truncate(content, 1500);
    }
  }

  // Check for test/debug routes exposed in production
  const authRoutesPath = path.join(routesDir, 'auth.routes.js');
  const authRoutes = await readFile(authRoutesPath);
  if (authRoutes) {
    const testRouteMatch = authRoutes.match(/router\.(get|post|put|delete)\s*\(\s*['"`][^'"`]*test[^'"`]*['"`]/i);
    if (testRouteMatch) {
      const lineNum = authRoutes.slice(0, testRouteMatch.index).split('\n').length;
      findings.push({
        type: 'vulnerability',
        title: 'Test/debug route exposed without authentication',
        description: `A route matching "test" pattern was found in auth.routes.js:${lineNum} with no auth middleware. Debug endpoints in production can leak internal state or bypass controls.`,
        code_example: testRouteMatch[0],
        cve: null,
      });
    }
  }

  // Check admin routes for legacy role checks
  const adminRoutesPath = path.join(routesDir, 'admin.routes.js');
  const adminRoutes = await readFile(adminRoutesPath);
  if (adminRoutes && /authorize\s*\(\s*['"`]admin['"`]/.test(adminRoutes)) {
    findings.push({
      type: 'warning',
      title: 'Admin routes use legacy string-based role check',
      description: 'admin.routes.js uses authorize(\'admin\', \'ADMIN\') instead of the current requireOrgRole() system. The old authorize() does string comparison which may not align with the current role hierarchy (OWNER=40, ADMIN=30, MEMBER=20, VIEWER=10). This could allow unintended access if role names drift.',
      code_example: 'authorize(\'admin\', \'ADMIN\')  // Use: requireOrgRole(\'ADMIN\')',
      cve: null,
    });
  }

  // Report unprotected routes
  if (unprotectedRoutes.length > 0) {
    const routeList = unprotectedRoutes
      .slice(0, 10)
      .map(r => `${r.method} ${path.basename(r.filePath).replace('.routes.js', '')}${r.routePath}`)
      .join(', ');

    findings.push({
      type: 'warning',
      title: `${unprotectedRoutes.length} route(s) detected without explicit auth middleware`,
      description: `Routes without authenticate/requireOrgRole in their declaration: ${routeList}${unprotectedRoutes.length > 10 ? ` (+${unprotectedRoutes.length - 10} more)` : ''}. Verify each is intentionally public.`,
      code_example: null,
      cve: null,
    });
  }

  // Check index.js for tenant context on all protected routes
  const indexPath = path.join(routesDir, 'index.js');
  const indexContent = await readFile(indexPath);
  if (indexContent && !/runInTenantContext|tenantContext|setTenantId/i.test(indexContent)) {
    findings.push({
      type: 'warning',
      title: 'No explicit cross-tenant enforcement middleware visible in routes index',
      description: 'The routes/index.js does not show a global middleware that enforces tenantId scoping on all authenticated routes. If individual controllers query without tenantId filtering, cross-tenant data access is possible.',
      code_example: null,
      cve: null,
    });
  }

  recommendations.push(
    'Add router.use(authenticate) at the top of every protected route file instead of per-route.',
    'Replace authorize(\'admin\') with requireOrgRole(\'ADMIN\') in admin routes to use the hierarchical role system.',
    'Remove or gate the /test-email route with authenticate + requireOrgRole(\'ADMIN\').',
    'Add an integration test that verifies every non-public route returns 401 when called without a token.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 1 ? 'high' : warnCount >= 2 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 25 - warnCount * 8);

  return { id: 'api', name: 'API Endpoints', severity, score, findings, recommendations, _codeSnippets };
}
