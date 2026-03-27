/**
 * auditors/nextjs.js
 * Next.js & Frontend Security Auditor
 *
 * Checks for Next.js-specific vulnerabilities and common frontend security
 * issues that don't apply to pure Express backends:
 *
 *  - Token storage in localStorage/sessionStorage (XSS attack surface)
 *  - NEXT_PUBLIC_ env vars leaking sensitive data to the client
 *  - Middleware auth gaps
 *  - API route protection
 *  - next.config.js security headers
 *  - CSRF on forms
 *  - dangerouslySetInnerHTML
 *  - force-dynamic overuse
 *  - SSE/WebSocket auth
 *  - Image/redirect domain allowlists
 */

import path from 'path';
import { readDir, readFile, grepFiles, discoverStructure, BACKEND_SRC, PROJECT_ROOT, ALL_EXTENSIONS } from '../utils/fileScanner.js';

const MODULE_ID = 'nextjs';
const MODULE_NAME = 'Next.js & Frontend Security';

export async function audit(depth = 'standard') {
  const structure = await discoverStructure();
  const root = PROJECT_ROOT();
  const srcDir = BACKEND_SRC();

  const findings = [];
  const recommendations = [];
  const codeSnippets = [];

  // Read all source files (TS + JS)
  const allFiles = await readDir(root, ALL_EXTENSIONS);

  // ────────────────────────────────────────────────────────────
  // 1. TOKEN STORAGE IN localStorage / sessionStorage
  // ────────────────────────────────────────────────────────────
  const storagePatterns = await grepFiles(root, [
    /localStorage\s*\.\s*setItem\s*\(\s*['"`].*(?:token|jwt|access|refresh|auth|session|credential)/i,
    /localStorage\s*\.\s*getItem\s*\(\s*['"`].*(?:token|jwt|access|refresh|auth|session)/i,
    /sessionStorage\s*\.\s*setItem\s*\(\s*['"`].*(?:token|jwt|access|refresh|auth)/i,
  ], { extensions: ALL_EXTENSIONS });

  if (storagePatterns.length > 0) {
    findings.push({
      type: 'vulnerability',
      title: 'Tokens de autenticacion almacenados en localStorage/sessionStorage',
      description: `Se encontraron ${storagePatterns.length} instancia(s) donde tokens JWT o credenciales se guardan en storage del navegador. Esto los expone a ataques XSS — cualquier script inyectado puede robar los tokens. Usar httpOnly cookies en su lugar.`,
      code_example: storagePatterns.slice(0, 3).map(m => `${m.filePath}:${m.lineNumber} → ${m.line}`).join('\n'),
      cve: null,
    });
    recommendations.push('Migrar tokens JWT a httpOnly secure cookies manejadas por el backend. Eliminar localStorage.setItem/getItem para tokens.');
    codeSnippets.push(...storagePatterns.slice(0, 3).map(m => m.line));
  }

  // ────────────────────────────────────────────────────────────
  // 2. NEXT_PUBLIC_ ENV VARS WITH SENSITIVE DATA
  // ────────────────────────────────────────────────────────────
  const envFile = await readFile(path.join(root, '.env')) ||
                  await readFile(path.join(root, '.env.local')) ||
                  await readFile(path.join(root, '.env.example')) || '';

  const sensitivePublicVars = [];
  const SENSITIVE_KEYWORDS = ['secret', 'key', 'token', 'password', 'private', 'credential', 'api_key', 'apikey'];

  for (const line of envFile.split('\n')) {
    if (!line.startsWith('NEXT_PUBLIC_')) continue;
    const varName = line.split('=')[0].toLowerCase();
    if (SENSITIVE_KEYWORDS.some(kw => varName.includes(kw))) {
      sensitivePublicVars.push(line.split('=')[0]);
    }
  }

  // Also check source code for process.env.NEXT_PUBLIC_ with sensitive names
  const publicEnvInCode = await grepFiles(root, [
    /process\.env\.NEXT_PUBLIC_.*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE|CREDENTIAL)/i,
  ], { extensions: ALL_EXTENSIONS });

  if (sensitivePublicVars.length > 0 || publicEnvInCode.length > 0) {
    const vars = [...sensitivePublicVars, ...publicEnvInCode.map(m => m.line.match(/NEXT_PUBLIC_\w+/)?.[0]).filter(Boolean)];
    findings.push({
      type: 'vulnerability',
      title: 'Variables NEXT_PUBLIC_ potencialmente sensibles expuestas al cliente',
      description: `Las variables NEXT_PUBLIC_ se incluyen en el bundle del navegador y son visibles para cualquier usuario. Se detectaron variables con nombres sospechosos: ${[...new Set(vars)].join(', ')}`,
      code_example: sensitivePublicVars.join('\n') || publicEnvInCode.slice(0, 2).map(m => m.line).join('\n'),
      cve: null,
    });
    recommendations.push('Mover secretos a variables server-side (sin prefijo NEXT_PUBLIC_). Acceder a ellos solo desde API routes o Server Components.');
  }

  // ────────────────────────────────────────────────────────────
  // 3. MIDDLEWARE AUTH COMPLETENESS
  // ────────────────────────────────────────────────────────────
  const middlewareFile = await readFile(path.join(root, 'middleware.ts')) ||
                         await readFile(path.join(root, 'middleware.js')) ||
                         await readFile(path.join(root, 'src', 'middleware.ts')) ||
                         await readFile(path.join(root, 'src', 'middleware.js'));

  if (middlewareFile) {
    // Check if middleware actually validates tokens server-side
    const hasTokenValidation = /verify|decode|jwt|jose|jsonwebtoken|getToken|getServerSession|auth\(\)/i.test(middlewareFile);
    const hasOnlyRedirect = /NextResponse\.redirect|NextResponse\.next/i.test(middlewareFile) && !hasTokenValidation;

    if (hasOnlyRedirect) {
      findings.push({
        type: 'warning',
        title: 'Middleware de Next.js no valida tokens server-side',
        description: 'El middleware redirige rutas pero no verifica tokens JWT ni sesiones del lado del servidor. Un atacante puede manipular localStorage y acceder a rutas protegidas. El middleware debe validar la autenticidad del token.',
        code_example: middlewareFile.slice(0, 300),
        cve: null,
      });
      recommendations.push('Implementar validacion de JWT en el middleware usando jose, next-auth getToken(), o verificacion manual con la clave secreta.');
    }

    // Check matcher coverage
    const matcherMatch = middlewareFile.match(/matcher\s*[:=]\s*(\[[\s\S]*?\])/);
    if (matcherMatch) {
      const matcher = matcherMatch[1];
      const hasApiProtection = /['"`]\/api/i.test(matcher);
      if (!hasApiProtection) {
        findings.push({
          type: 'warning',
          title: 'Middleware no protege rutas /api/',
          description: 'El matcher del middleware no incluye /api/* — las API routes de Next.js no estan cubiertas por el middleware de autenticacion.',
          code_example: `matcher: ${matcher.slice(0, 200)}`,
          cve: null,
        });
        recommendations.push('Incluir /api/:path* en el matcher del middleware para proteger API routes.');
      }
    }
  } else {
    // No middleware at all
    const hasProtectedRoutes = allFiles.some(f =>
      f.filePath.includes('/app/(dashboard)') ||
      f.filePath.includes('/app/admin') ||
      f.filePath.includes('/pages/dashboard')
    );

    if (hasProtectedRoutes) {
      findings.push({
        type: 'warning',
        title: 'No se detecta middleware.ts para proteccion de rutas',
        description: 'El proyecto tiene rutas que parecen protegidas (dashboard, admin) pero no existe un middleware.ts para validar autenticacion a nivel de servidor.',
        code_example: null,
        cve: null,
      });
      recommendations.push('Crear middleware.ts en la raiz del proyecto para validar tokens antes de que las rutas protegidas se carguen.');
    }
  }

  // ────────────────────────────────────────────────────────────
  // 4. API ROUTES WITHOUT AUTH
  // ────────────────────────────────────────────────────────────
  const apiRoutes = allFiles.filter(f =>
    (f.filePath.includes('/app/api/') || f.filePath.includes('/pages/api/')) &&
    (f.filePath.endsWith('route.ts') || f.filePath.endsWith('route.js') ||
     f.filePath.match(/\/api\/.*\.(ts|js)$/))
  );

  const unprotectedApiRoutes = [];
  for (const route of apiRoutes) {
    const hasAuth = /getServerSession|getToken|verify|jwt|auth|bearer|authorization|cookies\(\)/i.test(route.content);
    // Skip public endpoints (contact, health, theme, webhook)
    const isPublic = /contact|health|status|theme|webhook|cron|public|og/i.test(route.filePath);
    if (!hasAuth && !isPublic) {
      unprotectedApiRoutes.push(route.filePath);
    }
  }

  if (unprotectedApiRoutes.length > 0) {
    findings.push({
      type: 'warning',
      title: `${unprotectedApiRoutes.length} API route(s) sin autenticacion detectada`,
      description: `Rutas API que no verifican autenticacion: ${unprotectedApiRoutes.map(f => f.split('/api/')[1] || f).join(', ')}`,
      code_example: unprotectedApiRoutes.slice(0, 5).join('\n'),
      cve: null,
    });
    recommendations.push('Verificar que las API routes que manejan datos privados incluyan validacion de session/token.');
  }

  // ────────────────────────────────────────────────────────────
  // 5. NEXT.CONFIG.JS SECURITY HEADERS
  // ────────────────────────────────────────────────────────────
  const nextConfig = await readFile(path.join(root, 'next.config.js')) ||
                     await readFile(path.join(root, 'next.config.mjs')) ||
                     await readFile(path.join(root, 'next.config.ts'));

  if (nextConfig) {
    const hasSecurityHeaders = /headers\s*\(\s*\)|Content-Security-Policy|X-Frame-Options|Strict-Transport-Security/i.test(nextConfig);
    if (!hasSecurityHeaders) {
      findings.push({
        type: 'warning',
        title: 'next.config.js no define security headers',
        description: 'No se detectan headers de seguridad (CSP, X-Frame-Options, HSTS) en next.config.js. Estos headers protegen contra clickjacking, XSS y protocol downgrade.',
        code_example: null,
        cve: null,
      });
      recommendations.push('Configurar headers() en next.config.js con CSP, X-Frame-Options: DENY, HSTS, X-Content-Type-Options: nosniff.');
    }

    // Check image/redirect domains
    const hasWildcardDomains = /domains\s*:\s*\[\s*['"`]\*['"`]|remotePatterns.*protocol.*hostname.*\*\*/i.test(nextConfig);
    if (hasWildcardDomains) {
      findings.push({
        type: 'warning',
        title: 'Dominios wildcard en configuracion de imagenes/redirects',
        description: 'Se detectan patrones wildcard en la configuracion de dominios de Next.js. Esto puede permitir SSRF via el componente Image o redirects no controlados.',
        code_example: null,
        cve: null,
      });
      recommendations.push('Restringir dominios de imagenes y redirects a los estrictamente necesarios.');
    }
  }

  // ────────────────────────────────────────────────────────────
  // 6. dangerouslySetInnerHTML
  // ────────────────────────────────────────────────────────────
  const dangerousHTML = await grepFiles(root, [
    /dangerouslySetInnerHTML/,
  ], { extensions: ALL_EXTENSIONS });

  if (dangerousHTML.length > 0) {
    // Check if any use user-controlled input
    const userControlled = dangerousHTML.filter(m => {
      const ctx = [m.line, ...(m.context?.before || []), ...(m.context?.after || [])].join(' ');
      return /props|params|query|body|input|data|content|message|html/i.test(ctx);
    });

    if (userControlled.length > 0) {
      findings.push({
        type: 'vulnerability',
        title: 'dangerouslySetInnerHTML con datos potencialmente del usuario',
        description: `Se encontraron ${userControlled.length} uso(s) de dangerouslySetInnerHTML que parecen recibir datos dinamicos. Esto es un vector directo de XSS si el contenido no esta sanitizado con DOMPurify o similar.`,
        code_example: userControlled.slice(0, 2).map(m => `${m.filePath}:${m.lineNumber} → ${m.line}`).join('\n'),
        cve: null,
      });
      recommendations.push('Sanitizar todo HTML dinamico con DOMPurify antes de pasarlo a dangerouslySetInnerHTML. Preferir textContent o componentes React.');
    } else if (dangerousHTML.length > 0) {
      findings.push({
        type: 'info',
        title: `${dangerousHTML.length} uso(s) de dangerouslySetInnerHTML detectados`,
        description: 'Se detecta uso de dangerouslySetInnerHTML. Verificar que el contenido siempre sea sanitizado antes de renderizar.',
        code_example: dangerousHTML.slice(0, 2).map(m => `${m.filePath}:${m.lineNumber}`).join('\n'),
        cve: null,
      });
    }
  }

  // ────────────────────────────────────────────────────────────
  // 7. FORCE-DYNAMIC OVERUSE
  // ────────────────────────────────────────────────────────────
  const forceDynamic = await grepFiles(root, [
    /export\s+const\s+dynamic\s*=\s*['"`]force-dynamic['"`]/,
  ], { extensions: ALL_EXTENSIONS });

  if (forceDynamic.length > 3) {
    findings.push({
      type: 'info',
      title: `force-dynamic en ${forceDynamic.length} paginas — posible impacto en rendimiento`,
      description: 'Usar force-dynamic desactiva el caching estatico de Next.js en todas estas paginas. Esto puede ser necesario para hidratacion de Zustand/localStorage, pero aumenta la carga del servidor y el TTFB.',
      code_example: forceDynamic.slice(0, 5).map(m => m.filePath.split(root)[1]).join('\n'),
      cve: null,
    });
    recommendations.push('Revisar si todas las paginas necesitan force-dynamic. Considerar usar cookies para auth (compatible con SSG/ISR) o mover la logica de hidratacion a un Client Component boundary.');
  }

  // ────────────────────────────────────────────────────────────
  // 8. CSRF PROTECTION ON FORMS
  // ────────────────────────────────────────────────────────────
  const formPosts = await grepFiles(root, [
    /method\s*[:=]\s*['"`]POST['"`]/i,
    /fetch\s*\(.+\{\s*method\s*:\s*['"`]POST['"`]/i,
    /axios\s*\.post/i,
  ], { extensions: ALL_EXTENSIONS });

  const hasCsrf = allFiles.some(f =>
    /csrf|csrfToken|_csrf|xsrf|csurf|doubleCsrf|X-CSRF/i.test(f.content)
  );

  if (formPosts.length > 0 && !hasCsrf) {
    findings.push({
      type: 'warning',
      title: 'No se detecta proteccion CSRF en formularios',
      description: `Se encontraron ${formPosts.length} operacion(es) POST pero no se detecta implementacion de CSRF tokens. Si la app usa cookies para auth, esto permite ataques Cross-Site Request Forgery.`,
      code_example: null,
      cve: null,
    });
    recommendations.push('Implementar CSRF tokens en formularios. Si se usa Bearer token via header (no cookies), el riesgo es menor pero conviene documentarlo.');
  }

  // ────────────────────────────────────────────────────────────
  // 9. SSE / WEBSOCKET WITHOUT RECONNECT AUTH
  // ────────────────────────────────────────────────────────────
  const ssePatterns = await grepFiles(root, [
    /new\s+EventSource/,
    /new\s+WebSocket/,
  ], { extensions: ALL_EXTENSIONS });

  if (ssePatterns.length > 0) {
    const hasAuthInSSE = ssePatterns.some(m => {
      const ctx = [m.line, ...(m.context?.before || []), ...(m.context?.after || [])].join(' ');
      return /token|auth|bearer|credential/i.test(ctx);
    });

    if (!hasAuthInSSE) {
      findings.push({
        type: 'warning',
        title: 'Conexion SSE/WebSocket sin autenticacion visible',
        description: 'Se detectan conexiones EventSource o WebSocket sin inclusion explicita de tokens de autenticacion. Un atacante podria abrir conexiones no autorizadas al stream.',
        code_example: ssePatterns.slice(0, 2).map(m => `${m.filePath}:${m.lineNumber} → ${m.line}`).join('\n'),
        cve: null,
      });
      recommendations.push('Incluir token de autenticacion en la URL del SSE (como query param temporal) o usar cookies httpOnly para autenticar la conexion.');
    }
  }

  // ────────────────────────────────────────────────────────────
  // 10. EXPOSED SOURCE MAPS
  // ────────────────────────────────────────────────────────────
  if (nextConfig && /productionBrowserSourceMaps\s*:\s*true/i.test(nextConfig)) {
    findings.push({
      type: 'warning',
      title: 'Source maps habilitados en produccion',
      description: 'productionBrowserSourceMaps esta activado en next.config.js. Esto expone el codigo fuente completo de la aplicacion a cualquier usuario del navegador.',
      code_example: 'productionBrowserSourceMaps: true',
      cve: null,
    });
    recommendations.push('Desactivar productionBrowserSourceMaps en produccion. Usar source maps solo en staging o via Sentry/error tracking privado.');
  }

  // ────────────────────────────────────────────────────────────
  // SCORE & SEVERITY
  // ────────────────────────────────────────────────────────────
  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;

  let severity = 'ok';
  if (vulnCount > 0) severity = 'high';
  else if (warnCount >= 3) severity = 'medium';
  else if (warnCount > 0) severity = 'low';

  const score = Math.max(0, 100 - (vulnCount * 20) - (warnCount * 8));

  // If no findings, report clean
  if (findings.length === 0) {
    findings.push({
      type: 'info',
      title: 'No se detectaron problemas de seguridad especificos de Next.js',
      description: structure.framework === 'nextjs'
        ? 'El proyecto Next.js parece seguir buenas practicas de seguridad en los patrones analizados.'
        : 'Este modulo esta optimizado para proyectos Next.js. El proyecto actual no parece usar Next.js.',
      code_example: null,
      cve: null,
    });
  }

  return {
    id: MODULE_ID,
    name: MODULE_NAME,
    severity,
    score,
    findings,
    recommendations,
    _codeSnippets: codeSnippets,
  };
}
