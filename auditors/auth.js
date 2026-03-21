import path from 'path';
import { readFile, grepFiles, discoverStructure, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const structure = await discoverStructure();
  const src = structure.srcDir;
  const middlewareDir = structure.dirs.middleware || path.join(src, 'middleware');
  const controllersDir = structure.dirs.controllers || path.join(src, 'controllers');
  const modelsDir = structure.dirs.models || path.join(src, 'models');
  const schemasDir = structure.dirs.schemas || modelsDir;

  // --- Auth middleware ---
  const authMiddlewarePath = path.join(middlewareDir, 'auth.js');
  const authMiddleware = await readFile(authMiddlewarePath);

  if (authMiddleware) {
    _codeSnippets['middleware/auth.js'] = truncate(authMiddleware, 2000);

    // 1. JWT fallback secret
    if (/\|\|\s*['"`][^'"`]+['"`]/.test(authMiddleware) && authMiddleware.includes('JWT_SECRET')) {
      findings.push({
        type: 'vulnerability',
        title: 'JWT_SECRET has a hardcoded fallback value',
        description: 'jwt.verify() uses `process.env.JWT_SECRET || \'default-secret\'`. If JWT_SECRET is unset, any attacker knowing the fallback can forge valid tokens for any user.',
        code_example: 'jwt.verify(token, process.env.JWT_SECRET || \'default-secret\')',
        cve: null,
      });
    }

    // 2. No algorithms option in jwt.verify
    if (/jwt\.verify\(/.test(authMiddleware) && !/algorithms/.test(authMiddleware)) {
      findings.push({
        type: 'vulnerability',
        title: 'jwt.verify() called without specifying allowed algorithms',
        description: 'Without `algorithms: [\'HS256\']`, the library accepts tokens signed with any algorithm. The "alg:none" attack or algorithm confusion (RS256→HS256) could allow forging tokens without the secret.',
        code_example: '// Vulnerable:\njwt.verify(token, secret)\n// Fixed:\njwt.verify(token, secret, { algorithms: [\'HS256\'] })',
        cve: 'CVE-2022-21449',
      });
    }

    // 3. No token revocation / blacklist
    if (!/blacklist|revoke|tokenBlacklist|jti|denylist/i.test(authMiddleware)) {
      findings.push({
        type: 'warning',
        title: 'No JWT token revocation mechanism',
        description: 'Once issued, JWT tokens cannot be invalidated before expiry. A stolen token remains valid until it expires. No blacklist, jti tracking, or revocation endpoint found.',
        code_example: null,
        cve: null,
      });
    }

    // 4. No refresh token logic
    if (!/refreshToken|refresh_token/i.test(authMiddleware)) {
      findings.push({
        type: 'warning',
        title: 'No refresh token implementation detected',
        description: 'Without refresh tokens, users must re-authenticate when access tokens expire, or access tokens are set with long expiry (increasing exposure window). Check auth controller for token duration.',
        code_example: null,
        cve: null,
      });
    }
  } else {
    findings.push({
      type: 'info',
      title: 'Auth middleware file not found',
      description: `Could not read ${authMiddlewarePath}`,
      code_example: null,
      cve: null,
    });
  }

  // --- Auth controller: bcrypt rounds + token expiry ---
  const authControllerPath = path.join(controllersDir, 'auth.controller.js');
  const authController = await readFile(authControllerPath);
  if (authController) {
    _codeSnippets['controllers/auth.controller.js'] = truncate(authController, 2000);

    const bcryptMatch = authController.match(/bcrypt\.hash\([^,]+,\s*(\d+)\)/);
    if (bcryptMatch) {
      const rounds = parseInt(bcryptMatch[1]);
      if (rounds < 10) {
        findings.push({
          type: 'vulnerability',
          title: `bcrypt cost factor too low (${rounds})`,
          description: `bcrypt.hash() uses ${rounds} rounds. Minimum recommended is 10 (OWASP). Lower values make offline brute force attacks significantly faster.`,
          code_example: `bcrypt.hash(password, ${rounds})  // Increase to 12`,
          cve: null,
        });
      }
    }

    if (/EmailVerificationOtp|otp/i.test(authController)) {
      if (!/expiresAt|expire/i.test(authController)) {
        findings.push({
          type: 'warning',
          title: 'OTP codes may not have enforced expiry',
          description: 'OTP verification found but no clear expiresAt validation detected in auth controller. Unexpiring OTP codes can be exploited long after issuance.',
          code_example: null,
          cve: null,
        });
      }
    }

    // 5. Token expiry too long
    const expiryMatches = authController.matchAll(/expiresIn\s*:\s*['"`]?(\d+[dhmy]|30d|90d|1y)['"`]?/gi);
    const longExpiries = ['30d', '90d', '1y'];
    for (const m of expiryMatches) {
      const val = m[1];
      if (longExpiries.includes(val) || (parseInt(val) > 604800 && /^\d+$/.test(val))) {
        findings.push({
          type: 'warning',
          title: `JWT expiresIn is set to a very long value: '${val}'`,
          description: `Token expiry of '${val}' gives attackers a large window to exploit stolen tokens. OWASP recommends access tokens expire in 15–60 minutes. Use short-lived access tokens with refresh tokens.`,
          code_example: `expiresIn: '${val}'  // Consider '15m' or '1h'`,
          cve: null,
        });
        break;
      }
    }
  }

  // --- Schema checks: password minimum length ---
  const schemaSearchDirs = [modelsDir, schemasDir].filter(Boolean);
  const schemaPatterns = ['auth.schema.js', 'user.schema.js', 'invitation.schema.js', 'auth.model.js', 'user.model.js'];

  for (const dir of [...new Set(schemaSearchDirs)]) {
    for (const name of schemaPatterns) {
      const schemaPath = path.join(dir, name);
      const schema = await readFile(schemaPath);
      if (!schema) continue;

      const lines = schema.split('\n');
      for (const line of lines) {
        if (!/password|contraseña/i.test(line)) continue;
        const minMatch = line.match(/\.min\((\d+)\)/);
        if (minMatch && parseInt(minMatch[1]) < 10) {
          findings.push({
            type: 'vulnerability',
            title: `Weak password minimum length (${minMatch[1]} chars) in ${name}`,
            description: `${name} enforces .min(${minMatch[1]}) for passwords. NIST SP 800-63B recommends at least 12 characters. Short minimums facilitate brute force attacks.`,
            code_example: `z.string().min(${minMatch[1]})  // Should be at least .min(12)`,
            cve: null,
          });
          break;
        }
      }
    }
  }

  // --- New check: Absence of MFA/TOTP ---
  const totpMatches = await grepFiles(src, [
    /totp|speakeasy|otplib|authenticator/i,
  ], { extensions: ['.js'] });

  if (totpMatches.length === 0) {
    findings.push({
      type: 'info',
      title: 'No MFA/TOTP implementation detected',
      description: 'No TOTP library (speakeasy, otplib) or authenticator pattern found in source. Multi-factor authentication is recommended for privileged accounts and sensitive operations.',
      code_example: null,
      cve: null,
    });
  }

  // --- New check: req.user used without existence check ---
  if (controllersDir) {
    const reqUserMatches = await grepFiles(controllersDir, [
      /req\.user\.\w+/,
    ], { extensions: ['.js'], contextLines: 3 });

    const unsafeReqUser = reqUserMatches.filter(m => {
      const context = m.context.before.join('\n') + m.line;
      return !/if\s*\(\s*!?\s*req\.user\b|req\.user\s*&&|req\.user\s*\?/.test(context);
    });

    if (unsafeReqUser.length > 0) {
      const locs = unsafeReqUser.slice(0, 3).map(m => {
        return `${path.basename(m.filePath)}:${m.lineNumber}`;
      }).join(', ');
      findings.push({
        type: 'warning',
        title: 'req.user accessed without prior existence check',
        description: `Found ${unsafeReqUser.length} location(s) where req.user.property is read without verifying req.user is defined first: ${locs}. If auth middleware is skipped or misconfigured, this causes an unhandled TypeError.`,
        code_example: 'req.user.id  // Should check: if (!req.user) return res.status(401).json(...)',
        cve: null,
      });
    }
  }

  // --- New check: Tokens in query params ---
  const tokenQueryMatches = await grepFiles(src, [
    /token=|api_key=|apikey=/i,
  ], { extensions: ['.js'] });

  if (tokenQueryMatches.length > 0) {
    const locs = tokenQueryMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'warning',
      title: 'Tokens passed in URL query parameters',
      description: `Found token/api_key in query strings at: ${locs}. Tokens in URLs are logged by servers, proxies, and browsers — exposing them to unintended parties.`,
      code_example: '// Avoid: GET /api/data?token=abc123\n// Use: Authorization: Bearer <token>',
      cve: null,
    });
  }

  // --- New check: No account lockout ---
  const lockoutMatches = await grepFiles(src, [
    /lockedUntil|loginAttempts|failedAttempts/i,
  ], { extensions: ['.js'] });

  if (lockoutMatches.length === 0) {
    findings.push({
      type: 'warning',
      title: 'No account lockout mechanism detected',
      description: 'No lockedUntil, loginAttempts, or failedAttempts pattern found. Without account lockout, brute force attacks against passwords are unbounded even when rate limiting is in place.',
      code_example: null,
      cve: null,
    });
  }

  recommendations.push(
    'Remove the JWT_SECRET fallback: if it\'s unset, throw at startup. Add: if (!process.env.JWT_SECRET) throw new Error(\'JWT_SECRET is required\').',
    'Add algorithms option: jwt.verify(token, secret, { algorithms: [\'HS256\'] }).',
    'Increase password minimum to 12 characters in all schemas.',
    'Implement JWT token revocation using a Redis-backed jti denylist for critical operations (logout, password change).',
    'Use short-lived access tokens (15m–1h) paired with refresh tokens instead of long-lived tokens.',
    'Add account lockout after N failed login attempts using lockedUntil field.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const severity = vulnCount >= 2 ? 'critical' : vulnCount === 1 ? 'high' : findings.some(f => f.type === 'warning') ? 'medium' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20 - findings.filter(f => f.type === 'warning').length * 7);

  return { id: 'auth', name: 'Autenticación & JWT', severity, score, findings, recommendations, _codeSnippets };
}
