import path from 'path';
import { readFile, grepFiles, discoverStructure, truncate } from '../utils/fileScanner.js';
import { detectProjectType } from '../utils/projectType.js';

// ─── Python / FastAPI headers audit ──────────────────────────────────────────

async function auditPython(src) {
  const findings = [];
  const recommendations = [];
  const py = ['.py'];

  // 1. Security headers middleware (secure, starlette-middleware, custom)
  const headersLibMatches = await grepFiles(src, [
    /from secure|import secure|SecurityHeadersMiddleware|secure\.Secure|TrustedHostMiddleware/i,
  ], { extensions: py });

  if (headersLibMatches.length === 0) {
    // Check for manual header setting
    const manualHeaderMatches = await grepFiles(src, [
      /X-Content-Type-Options|Strict-Transport-Security|X-Frame-Options|Content-Security-Policy/i,
    ], { extensions: py });

    if (manualHeaderMatches.length === 0) {
      findings.push({
        type: 'vulnerability',
        title: 'No se detectó middleware de security headers',
        description:
          'No se encontró el paquete `secure`, SecurityHeadersMiddleware ni cabeceras de seguridad (HSTS, X-Content-Type-Options, X-Frame-Options) configuradas manualmente. Sin estas cabeceras, el navegador no tiene protecciones básicas.',
        code_example:
          '# pip install secure\nimport secure\n\nsecure_headers = secure.Secure()\n\n' +
          '@app.middleware("http")\nasync def add_security_headers(request: Request, call_next):\n' +
          '    response = await call_next(request)\n' +
          '    secure_headers.framework.fastapi(response)\n' +
          '    return response',
        cve: null,
      });
    } else {
      // Check for HSTS
      const hstsMatches = await grepFiles(src, [/Strict-Transport-Security/i], { extensions: py });
      if (hstsMatches.length === 0) {
        findings.push({
          type: 'warning',
          title: 'HSTS (Strict-Transport-Security) no detectado',
          description: 'Sin HSTS, los navegadores no forzarán HTTPS, permitiendo ataques de downgrade.',
          code_example: 'response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"',
          cve: null,
        });
      }
    }
  }

  // 2. CORS wildcard check (also checked in xss.js but headers.js is the primary place)
  const corsMatches = await grepFiles(src, [/allow_origins/i], { extensions: py });
  if (corsMatches.length > 0) {
    const uniqueFiles = [...new Set(corsMatches.map(m => m.filePath).filter(Boolean))];
    const corsContent = (await Promise.all(uniqueFiles.map(f => readFile(f).catch(() => '')))).join('\n');

    if (/allow_origins\s*=\s*\[["']\*["']\]/i.test(corsContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'CORS wildcard allow_origins=["*"] detectado',
        description: 'Cualquier dominio puede hacer peticiones cross-origin a tu API.',
        code_example: 'allow_origins=["https://tuapp.com"]  # Especifica orígenes explícitos',
        cve: null,
      });
    }
  }

  // 3. Trusted hosts / Host header injection
  const trustedHostMatches = await grepFiles(src, [/TrustedHostMiddleware|allowed_hosts/i], { extensions: py });
  if (trustedHostMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'TrustedHostMiddleware no configurado',
      description:
        'Sin TrustedHostMiddleware, el backend acepta peticiones con cualquier cabecera Host. Esto puede facilitar ataques de Host Header Injection, cache poisoning y password reset poisoning.',
      code_example:
        'from starlette.middleware.trustedhost import TrustedHostMiddleware\n\n' +
        'app.add_middleware(\n    TrustedHostMiddleware,\n    allowed_hosts=["tudominio.com", "*.tudominio.com"]\n)',
      cve: null,
    });
  }

  // 4. Server header / framework fingerprint
  const serverHeaderMatches = await grepFiles(src, [/server.*header|Server.*=.*uvicorn|hide.*server/i], { extensions: py });
  // Uvicorn exposes "uvicorn" as Server header by default — check if suppressed
  const uvicornConfigMatches = await grepFiles(src, [/server_header\s*=\s*False|headers.*server/i], { extensions: py });
  if (uvicornConfigMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'Uvicorn expone el header Server por defecto',
      description:
        'Uvicorn envía Server: uvicorn por defecto, revelando el servidor a atacantes. Suprime esta cabecera en la configuración de arranque.',
      code_example: 'uvicorn.run(app, ..., server_header=False)',
      cve: null,
    });
  }

  // 5. Referrer-Policy
  const referrerMatches = await grepFiles(src, [/Referrer-Policy|referrer_policy/i], { extensions: py });
  if (referrerMatches.length === 0 && headersLibMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'Referrer-Policy no configurado explícitamente',
      description:
        'Sin Referrer-Policy, el navegador puede enviar la URL completa (incluyendo tokens en query params) como cabecera Referer a terceros.',
      code_example: 'response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"',
      cve: null,
    });
  }

  recommendations.push(
    'Instala el paquete `secure` e integra Secure() como middleware HTTP para todas las security headers de una vez.',
    'Configura TrustedHostMiddleware con la lista explícita de hosts permitidos.',
    'Suprime el header Server en Uvicorn con server_header=False.',
    'Establece allow_origins con allowlist explícita. Nunca uses ["*"] en producción.',
    'Configura Referrer-Policy: strict-origin-when-cross-origin para prevenir leakage de tokens.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 2 ? 'high' : vulnCount >= 1 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20 - warnCount * 10);

  return { id: 'headers', name: 'Headers & CORS', severity, score, findings, recommendations, _codeSnippets: {} };
}

// ─── Node.js / Express headers audit (original logic) ────────────────────────

async function auditNode(structure) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = structure.srcDir;
  const serverContent = structure.entryFile ? await readFile(structure.entryFile) : null;

  if (!serverContent) {
    findings.push({ type: 'warning', title: 'Server entry file not found', description: 'Could not read server entry to analyze Helmet/CORS/header configuration.', code_example: null, cve: null });
    return { id: 'headers', name: 'Headers & CORS', severity: 'medium', score: 50, findings, recommendations, _codeSnippets };
  }

  _codeSnippets['server.js'] = truncate(serverContent, 2000);

  if (!serverContent.includes('helmet')) {
    findings.push({
      type: 'vulnerability',
      title: 'Helmet.js not detected',
      description: 'No Helmet import or usage found. HTTP security headers are not being set.',
      code_example: null,
      cve: null,
    });
  } else {
    if (/crossOriginResourcePolicy.*cross-origin/i.test(serverContent)) {
      findings.push({
        type: 'warning',
        title: 'Cross-Origin-Resource-Policy set to "cross-origin" — CORP disabled',
        description: 'Helmet\'s crossOriginResourcePolicy is overridden to "cross-origin", allowing any site to embed your resources.',
        code_example: 'helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } })  // Weakens isolation',
        cve: null,
      });
    }

    if (!/contentSecurityPolicy\s*:/.test(serverContent)) {
      findings.push({
        type: 'info',
        title: 'Content-Security-Policy uses Helmet defaults',
        description: 'No custom CSP configured. For API-only backends, consider explicitly configuring or disabling it.',
        code_example: '// For API servers:\nhelmet({ contentSecurityPolicy: false })',
        cve: null,
      });
    }

    if (/hsts.*false/i.test(serverContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'HSTS is explicitly disabled',
        description: 'Strict-Transport-Security header is turned off. Browsers will not enforce HTTPS-only connections.',
        code_example: null,
        cve: null,
      });
    }

    if (!/permissionsPolicy|featurePolicy/i.test(serverContent)) {
      findings.push({
        type: 'info',
        title: 'Permissions-Policy header not configured',
        description: 'No Permissions-Policy configuration found. This header lets you control which browser APIs the page can use.',
        code_example: 'helmet({ permissionsPolicy: { policy: { camera: [], microphone: [], geolocation: [] } } })',
        cve: null,
      });
    }

    if (!/referrerPolicy/i.test(serverContent)) {
      findings.push({
        type: 'info',
        title: 'Referrer-Policy not explicitly configured',
        description: 'Without it, the browser may send the full URL as Referer header to third parties.',
        code_example: 'helmet({ referrerPolicy: { policy: \'strict-origin-when-cross-origin\' } })',
        cve: null,
      });
    }
  }

  if (!/app\.disable\s*\(\s*['"`]x-powered-by['"`]\s*\)|hidePoweredBy/i.test(serverContent)) {
    findings.push({
      type: 'warning',
      title: 'X-Powered-By header not removed',
      description: 'Express sends X-Powered-By: Express by default, advertising the framework version.',
      code_example: 'app.disable(\'x-powered-by\')',
      cve: null,
    });
  }

  const corsMatch = serverContent.match(/origin\s*:\s*([^\n,}]+)/);
  if (corsMatch) {
    const originConfig = corsMatch[1].trim();
    if (originConfig.includes("'*'") || originConfig.includes('"*"')) {
      findings.push({
        type: 'vulnerability',
        title: 'CORS is configured with wildcard origin (*)',
        description: 'CORS origin is set to "*". Any website can make cross-origin requests to your API.',
        code_example: 'cors({ origin: \'*\' })',
        cve: null,
      });
    }

    if (/CORS_ORIGIN.*\|\|.*\[.*\*/.test(serverContent) || /\|\|\s*\['?\*'?\]/.test(serverContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'CORS defaults to wildcard when CORS_ORIGIN env var is unset',
        description: 'The CORS configuration falls back to ["*"] if CORS_ORIGIN is not set.',
        code_example: 'const origins = process.env.CORS_ORIGIN?.split(",") || [\'*\']',
        cve: null,
      });
    }
  }

  if (serverContent.includes('credentials: true') && /origin.*\*/.test(serverContent)) {
    findings.push({
      type: 'vulnerability',
      title: 'credentials: true with wildcard origin',
      description: 'Using credentials: true with wildcard origin indicates a misconfiguration.',
      code_example: 'cors({ origin: \'*\', credentials: true })',
      cve: null,
    });
  }

  const cookieMatches = await grepFiles(src, [/res\.cookie\s*\(/, /Set-Cookie/i], { extensions: ['.js'], contextLines: 3 });
  for (const match of cookieMatches) {
    const context = match.line + match.context.after.join('\n');
    const missingHttpOnly = !/httpOnly\s*:\s*true/i.test(context);
    const missingSecure = !/secure\s*:\s*true/i.test(context);
    if (missingHttpOnly || missingSecure) {
      const missing = [missingHttpOnly && 'httpOnly', missingSecure && 'secure'].filter(Boolean).join(', ');
      findings.push({
        type: 'vulnerability',
        title: `Cookie set without ${missing} flag(s)`,
        description: `Found res.cookie() at ${path.basename(match.filePath)}:${match.lineNumber} missing ${missing}.`,
        code_example: `res.cookie('name', value, { httpOnly: true, secure: true, sameSite: 'strict' })`,
        cve: null,
      });
      break;
    }
  }

  recommendations.push(
    'Set CORS_ORIGIN to an explicit allowlist in production. Never use * in production.',
    'Change crossOriginResourcePolicy back to "same-site".',
    'Add app.disable(\'x-powered-by\') to remove the Express fingerprint.',
    'Configure Permissions-Policy to restrict unused browser APIs.',
    'Set Referrer-Policy to strict-origin-when-cross-origin.',
    'Always set httpOnly: true and secure: true on all authentication cookies.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const warnCount = findings.filter(f => f.type === 'warning').length;
  const severity = vulnCount >= 2 ? 'high' : vulnCount >= 1 ? 'medium' : warnCount >= 1 ? 'low' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20 - warnCount * 10);

  return { id: 'headers', name: 'Headers & CORS', severity, score, findings, recommendations, _codeSnippets };
}

// ─── Entry point ──────────────────────────────────────────────────────────────

export async function audit(depth) {
  const { isPython, src, structure } = await detectProjectType();
  if (isPython) return auditPython(src);
  return auditNode(structure);
}
