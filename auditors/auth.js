import path from 'path';
import { readFile, grepFiles, discoverStructure, truncate } from '../utils/fileScanner.js';
import { detectProjectType } from '../utils/projectType.js';

// ─── Python / FastAPI auth audit ──────────────────────────────────────────────

async function auditPython(src) {
  const findings = [];
  const recommendations = [];
  const py = ['.py'];

  // 1. JWT library detection
  const jwtMatches = await grepFiles(src, [/python.jose|PyJWT|jose\.jwt|jwt\.decode|jwt\.encode/i], { extensions: py });

  if (jwtMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'No JWT library detected (python-jose / PyJWT)',
      description: 'No se encontró python-jose, PyJWT ni patrones jwt.decode en el código fuente. Si el backend usa JWTs, asegúrate de verificar la firma correctamente.',
      code_example:
        'from jose import jwt, JWTError\n\n' +
        'def decode_token(token: str):\n' +
        '    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])',
      cve: null,
    });
  } else {
    // Check algorithms are explicitly set
    const uniqueFiles = [...new Set(jwtMatches.map(m => m.filePath).filter(Boolean))];
    const jwtContent = (await Promise.all(uniqueFiles.map(f => readFile(f).catch(() => '')))).join('\n');

    if (!/algorithms\s*=\s*\[/i.test(jwtContent)) {
      findings.push({
        type: 'vulnerability',
        title: 'jwt.decode() sin algorithms explícito — riesgo de ataque alg:none',
        description:
          'jwt.decode() llamado sin parámetro algorithms=[]. Sin esto, la librería puede aceptar tokens con alg:none o algoritmos inesperados, permitiendo falsificar tokens sin conocer el secreto.',
        code_example:
          '# Vulnerable:\njwt.decode(token, SECRET_KEY)\n\n' +
          '# Correcto:\njwt.decode(token, SECRET_KEY, algorithms=["HS256"])',
        cve: 'CVE-2022-29217',
      });
    }

    // Check for token revocation / blacklist
    if (!/blacklist|revoke|denylist|jti|token_blacklist/i.test(jwtContent)) {
      findings.push({
        type: 'warning',
        title: 'No hay mecanismo de revocación de tokens JWT',
        description:
          'No se detectó blacklist, jti tracking ni endpoint de revocación. Un token robado permanece válido hasta su expiración. Implementa una denylist en Redis para logout y cambio de contraseña.',
        code_example:
          '# En Redis:\nredis_client.setex(f"blacklist:{jti}", expires_in, "1")\n\n' +
          '# Al verificar:\nif redis_client.get(f"blacklist:{jti}"):\n    raise HTTPException(401, "Token revocado")',
        cve: null,
      });
    }

    // Check for refresh token
    if (!/refresh_token|refreshToken/i.test(jwtContent)) {
      findings.push({
        type: 'warning',
        title: 'No se detectó implementación de refresh token',
        description:
          'Sin refresh tokens, los access tokens tienen expiración larga o los usuarios deben re-autenticarse frecuentemente. Implementa tokens de acceso cortos (15m) + refresh tokens de larga duración.',
        code_example: null,
        cve: null,
      });
    }
  }

  // 2. Password hashing — passlib, bcrypt, argon2
  const hashMatches = await grepFiles(src, [/passlib|bcrypt|argon2|CryptContext|pwd_context/i], { extensions: py });

  if (hashMatches.length === 0) {
    findings.push({
      type: 'vulnerability',
      title: 'No se detectó librería de hashing de contraseñas (passlib/bcrypt/argon2)',
      description:
        'Sin passlib, bcrypt ni argon2, las contraseñas podrían estar guardadas en texto plano o con hash inseguro (MD5/SHA1). Usa passlib con bcrypt o argon2id.',
      code_example:
        'from passlib.context import CryptContext\n\n' +
        'pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")\n\n' +
        'def hash_password(password: str) -> str:\n' +
        '    return pwd_context.hash(password)\n\n' +
        'def verify_password(plain: str, hashed: str) -> bool:\n' +
        '    return pwd_context.verify(plain, hashed)',
      cve: null,
    });
  } else {
    // Check bcrypt rounds if using bcrypt directly
    const uniqueFiles = [...new Set(hashMatches.map(m => m.filePath).filter(Boolean))];
    const hashContent = (await Promise.all(uniqueFiles.map(f => readFile(f).catch(() => '')))).join('\n');

    const roundsMatch = hashContent.match(/rounds\s*=\s*(\d+)/);
    if (roundsMatch) {
      const rounds = parseInt(roundsMatch[1]);
      if (rounds < 10) {
        findings.push({
          type: 'vulnerability',
          title: `bcrypt rounds demasiado bajo (${rounds})`,
          description: `bcrypt configurado con ${rounds} rounds. OWASP recomienda mínimo 10 (idealmente 12). Valores bajos aceleran los ataques offline de fuerza bruta.`,
          code_example: `CryptContext(schemes=["bcrypt"], bcrypt__rounds=${rounds})  # Aumentar a 12`,
          cve: null,
        });
      }
    }
  }

  // 3. MFA / TOTP
  const totpMatches = await grepFiles(src, [/pyotp|TOTP|totp|authenticator|speakeasy/i], { extensions: py });

  if (totpMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'No se detectó MFA/TOTP (pyotp)',
      description:
        'No se encontró pyotp ni patrones TOTP. La autenticación multifactor es recomendada para cuentas privilegiadas y operaciones sensibles.',
      code_example:
        '# pip install pyotp\nimport pyotp\n\n' +
        'totp = pyotp.TOTP(user.totp_secret)\nif not totp.verify(code):\n    raise HTTPException(401, "Código MFA inválido")',
      cve: null,
    });
  }

  // 4. Account lockout
  const lockoutMatches = await grepFiles(src, [
    /failed_attempts|login_attempts|locked_until|account_locked|MAX_LOGIN_ATTEMPTS/i,
  ], { extensions: py });

  if (lockoutMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No se detectó mecanismo de bloqueo de cuenta',
      description:
        'No se encontraron patrones de failed_attempts, locked_until ni MAX_LOGIN_ATTEMPTS. Sin bloqueo de cuenta, los ataques de fuerza bruta no están acotados incluso con rate limiting por IP.',
      code_example:
        'MAX_FAILED = 5\nLOCKOUT_MINUTES = 30\n\n' +
        'if user.failed_attempts >= MAX_FAILED:\n' +
        '    if user.locked_until and datetime.utcnow() < user.locked_until:\n' +
        '        raise HTTPException(429, "Cuenta bloqueada temporalmente")',
      cve: null,
    });
  }

  // 5. Password minimum length in Pydantic schemas
  const schemaMatches = await grepFiles(src, [/min_length\s*=\s*(\d+)/], { extensions: py });
  for (const m of schemaMatches) {
    const lineMatch = m.line?.match(/min_length\s*=\s*(\d+)/);
    if (lineMatch && parseInt(lineMatch[1]) < 10 && /password/i.test(m.line)) {
      findings.push({
        type: 'vulnerability',
        title: `Longitud mínima de contraseña insuficiente (${lineMatch[1]} caracteres) en ${path.basename(m.filePath)}`,
        description: `Schema Pydantic con min_length=${lineMatch[1]} en campo password. NIST SP 800-63B recomienda mínimo 12 caracteres.`,
        code_example: `password: str = Field(..., min_length=${lineMatch[1]})  # Cambiar a min_length=12`,
        cve: null,
      });
      break;
    }
  }

  // 6. Tokens in query params
  const tokenQueryMatches = await grepFiles(src, [/token=|api_key=|apikey=/i], { extensions: py });
  if (tokenQueryMatches.length > 0) {
    const locs = tokenQueryMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'warning',
      title: 'Tokens pasados como query parameters',
      description: `Encontrado token/api_key en query strings en: ${locs}. Los tokens en URLs son logueados por servidores, proxies y navegadores.`,
      code_example: '# Evitar: GET /api/data?token=abc123\n# Usar: Authorization: Bearer <token>',
      cve: null,
    });
  }

  recommendations.push(
    'Usa jwt.decode() con algorithms=["HS256"] explícito para prevenir el ataque alg:none.',
    'Implementa una denylist en Redis para revocación de tokens en logout y cambio de contraseña.',
    'Usa passlib con bcrypt (rounds>=12) o argon2id para hashing de contraseñas.',
    'Añade bloqueo de cuenta tras 5 intentos fallidos con cooldown progresivo.',
    'Implementa refresh tokens con expiración larga + access tokens de 15 minutos.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const severity = vulnCount >= 2 ? 'critical' : vulnCount === 1 ? 'high' : findings.some(f => f.type === 'warning') ? 'medium' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20 - findings.filter(f => f.type === 'warning').length * 7);

  return { id: 'auth', name: 'Autenticación & JWT', severity, score, findings, recommendations, _codeSnippets: {} };
}

// ─── Node.js / Express auth audit (original logic) ────────────────────────────

async function auditNode(structure) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = structure.srcDir;
  const middlewareDir = structure.dirs.middleware || path.join(src, 'middleware');
  const controllersDir = structure.dirs.controllers || path.join(src, 'controllers');
  const modelsDir = structure.dirs.models || path.join(src, 'models');
  const schemasDir = structure.dirs.schemas || modelsDir;

  // --- Auth middleware ---
  const authFileNames = ['auth.js', 'auth.middleware.js', 'jwt.js', 'jwt.middleware.js', 'authenticate.js'];
  let authMiddleware = null;
  let authMiddlewarePath = null;
  for (const name of authFileNames) {
    const candidate = path.join(middlewareDir, name);
    const content = await readFile(candidate);
    if (content) { authMiddleware = content; authMiddlewarePath = candidate; break; }
  }
  if (!authMiddleware) {
    const jwtMatches = await grepFiles(src, [/jwt\.verify\s*\(/], { extensions: ['.js'] });
    if (jwtMatches.length > 0) {
      authMiddlewarePath = jwtMatches[0].filePath;
      authMiddleware = await readFile(authMiddlewarePath);
    }
  }

  if (authMiddleware) {
    _codeSnippets[path.relative(src, authMiddlewarePath)] = truncate(authMiddleware, 2000);

    if (/\|\|\s*['"`][^'"`]+['"`]/.test(authMiddleware) && authMiddleware.includes('JWT_SECRET')) {
      findings.push({
        type: 'vulnerability',
        title: 'JWT_SECRET has a hardcoded fallback value',
        description: 'jwt.verify() uses `process.env.JWT_SECRET || \'default-secret\'`. If JWT_SECRET is unset, any attacker knowing the fallback can forge valid tokens.',
        code_example: 'jwt.verify(token, process.env.JWT_SECRET || \'default-secret\')',
        cve: null,
      });
    }

    if (/jwt\.verify\(/.test(authMiddleware) && !/algorithms/.test(authMiddleware)) {
      findings.push({
        type: 'vulnerability',
        title: 'jwt.verify() called without specifying allowed algorithms',
        description: 'Without `algorithms: [\'HS256\']`, the library accepts tokens signed with any algorithm. The "alg:none" attack or algorithm confusion could allow forging tokens.',
        code_example: '// Vulnerable:\njwt.verify(token, secret)\n// Fixed:\njwt.verify(token, secret, { algorithms: [\'HS256\'] })',
        cve: 'CVE-2022-21449',
      });
    }

    if (!/blacklist|revoke|tokenBlacklist|jti|denylist/i.test(authMiddleware)) {
      findings.push({
        type: 'warning',
        title: 'No JWT token revocation mechanism',
        description: 'Once issued, JWT tokens cannot be invalidated before expiry. No blacklist, jti tracking, or revocation endpoint found.',
        code_example: null,
        cve: null,
      });
    }

    if (!/refreshToken|refresh_token/i.test(authMiddleware)) {
      findings.push({
        type: 'warning',
        title: 'No refresh token implementation detected',
        description: 'Without refresh tokens, access tokens must have long expiry (increasing exposure window).',
        code_example: null,
        cve: null,
      });
    }
  } else {
    findings.push({
      type: 'info',
      title: 'No JWT auth middleware found',
      description: 'Could not locate auth middleware (checked middleware/auth.js, auth.middleware.js, jwt.js and searched for jwt.verify across source).',
      code_example: null,
      cve: null,
    });
  }

  // --- Auth controller ---
  const authCtrlNames = ['auth.controller.js', 'auth.js', 'authentication.controller.js', 'login.controller.js'];
  let authController = null;
  let authControllerPath = null;
  for (const name of authCtrlNames) {
    const candidate = path.join(controllersDir, name);
    const content = await readFile(candidate);
    if (content) { authController = content; authControllerPath = candidate; break; }
  }
  if (!authController) {
    const bcryptMatches = await grepFiles(src, [/bcrypt\.hash\s*\(/], { extensions: ['.js'] });
    if (bcryptMatches.length > 0) {
      authControllerPath = bcryptMatches[0].filePath;
      authController = await readFile(authControllerPath);
    }
  }

  if (authController) {
    _codeSnippets[path.relative(src, authControllerPath)] = truncate(authController, 2000);

    const bcryptMatch = authController.match(/bcrypt\.hash\([^,]+,\s*(\d+)\)/);
    if (bcryptMatch && parseInt(bcryptMatch[1]) < 10) {
      findings.push({
        type: 'vulnerability',
        title: `bcrypt cost factor too low (${bcryptMatch[1]})`,
        description: `bcrypt.hash() uses ${bcryptMatch[1]} rounds. Minimum recommended is 10 (OWASP).`,
        code_example: `bcrypt.hash(password, ${bcryptMatch[1]})  // Increase to 12`,
        cve: null,
      });
    }

    if (/EmailVerificationOtp|otp/i.test(authController) && !/expiresAt|expire/i.test(authController)) {
      findings.push({
        type: 'warning',
        title: 'OTP codes may not have enforced expiry',
        description: 'OTP verification found but no clear expiresAt validation detected.',
        code_example: null,
        cve: null,
      });
    }

    const expiryMatches = authController.matchAll(/expiresIn\s*:\s*['"`]?(\d+[dhmy]|30d|90d|1y)['"`]?/gi);
    const longExpiries = ['30d', '90d', '1y'];
    for (const m of expiryMatches) {
      const val = m[1];
      if (longExpiries.includes(val) || (parseInt(val) > 604800 && /^\d+$/.test(val))) {
        findings.push({
          type: 'warning',
          title: `JWT expiresIn is set to a very long value: '${val}'`,
          description: `Token expiry of '${val}' gives attackers a large window. OWASP recommends 15–60 minutes.`,
          code_example: `expiresIn: '${val}'  // Consider '15m' or '1h'`,
          cve: null,
        });
        break;
      }
    }
  }

  // --- Schema checks ---
  const schemaSearchDirs = [modelsDir, schemasDir].filter(Boolean);
  const schemaPatterns = ['auth.schema.js', 'user.schema.js', 'invitation.schema.js', 'auth.model.js', 'user.model.js'];

  for (const dir of [...new Set(schemaSearchDirs)]) {
    for (const name of schemaPatterns) {
      const schemaPath = path.join(dir, name);
      const schema = await readFile(schemaPath);
      if (!schema) continue;

      for (const line of schema.split('\n')) {
        if (!/password|contraseña/i.test(line)) continue;
        const minMatch = line.match(/\.min\((\d+)\)/);
        if (minMatch && parseInt(minMatch[1]) < 10) {
          findings.push({
            type: 'vulnerability',
            title: `Weak password minimum length (${minMatch[1]} chars) in ${name}`,
            description: `${name} enforces .min(${minMatch[1]}) for passwords. NIST recommends at least 12 characters.`,
            code_example: `z.string().min(${minMatch[1]})  // Should be at least .min(12)`,
            cve: null,
          });
          break;
        }
      }
    }
  }

  // --- MFA/TOTP ---
  const totpMatches = await grepFiles(src, [/totp|speakeasy|otplib|authenticator/i], { extensions: ['.js'] });
  if (totpMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'No MFA/TOTP implementation detected',
      description: 'No TOTP library (speakeasy, otplib) found. MFA is recommended for privileged accounts.',
      code_example: null,
      cve: null,
    });
  }

  // --- req.user without check ---
  if (controllersDir) {
    const reqUserMatches = await grepFiles(controllersDir, [/req\.user\.\w+/], { extensions: ['.js'], contextLines: 3 });
    const unsafeReqUser = reqUserMatches.filter(m => {
      const context = (m.context.before.join(' ') + m.line).replace(/\s+/g, ' ');
      // Detect common guards: if check, optional chaining, or explicit helper
      return !/if\s*\(\s*!?\s*req\.user\b|req\.user\s*&&|req\.user\s*\?|requireUser\s*\(|authenticate|isAuthenticated/i.test(context);
    });
    if (unsafeReqUser.length > 0) {
      const locs = unsafeReqUser.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
      findings.push({
        type: 'warning',
        title: 'req.user accessed without prior existence check',
        description: `Found ${unsafeReqUser.length} location(s) at: ${locs}.`,
        code_example: 'req.user.id  // Should check: if (!req.user) return res.status(401).json(...)',
        cve: null,
      });
    }
  }

  // --- Tokens in query params ---
  const tokenQueryMatches = await grepFiles(src, [/token=|api_key=|apikey=|\?token=\$\{/i], { extensions: ['.js'] });
  if (tokenQueryMatches.length > 0) {
    const locs = tokenQueryMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'warning',
      title: 'Tokens passed in URL query parameters',
      description: `Found token/api_key in query strings at: ${locs}.`,
      code_example: '// Avoid: GET /api/data?token=abc123\n// Use: Authorization: Bearer <token>',
      cve: null,
    });
  }

  // --- Account lockout ---
  const lockoutMatches = await grepFiles(src, [/lockedUntil|loginAttempts|failedAttempts/i], { extensions: ['.js'] });
  if (lockoutMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No account lockout mechanism detected',
      description: 'No lockedUntil, loginAttempts, or failedAttempts pattern found.',
      code_example: null,
      cve: null,
    });
  }

  recommendations.push(
    'Remove the JWT_SECRET fallback — throw at startup if unset.',
    'Add algorithms option: jwt.verify(token, secret, { algorithms: [\'HS256\'] }).',
    'Increase password minimum to 12 characters in all schemas.',
    'Implement JWT token revocation using a Redis-backed jti denylist.',
    'Use short-lived access tokens (15m–1h) paired with refresh tokens.',
    'Add account lockout after N failed login attempts.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const severity = vulnCount >= 2 ? 'critical' : vulnCount === 1 ? 'high' : findings.some(f => f.type === 'warning') ? 'medium' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20 - findings.filter(f => f.type === 'warning').length * 7);

  return { id: 'auth', name: 'Autenticación & JWT', severity, score, findings, recommendations, _codeSnippets };
}

// ─── Entry point ──────────────────────────────────────────────────────────────

export async function audit(depth) {
  const { isPython, src, structure } = await detectProjectType();
  if (isPython) return auditPython(src);
  return auditNode(structure);
}
