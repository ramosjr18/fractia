import path from 'path';
import { readFile, BACKEND_SRC, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = BACKEND_SRC();

  // --- auth middleware ---
  const authMiddlewarePath = path.join(src, 'middleware', 'auth.js');
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

  // --- Auth schemas: password length ---
  const schemaFiles = [
    path.join(src, 'models', 'auth.schema.js'),
    path.join(src, 'models', 'user.schema.js'),
    path.join(src, 'models', 'invitation.schema.js'),
  ];

  for (const schemaPath of schemaFiles) {
    const schema = await readFile(schemaPath);
    if (!schema) continue;

    // Only look for .min() on lines that are clearly about passwords
    const lines = schema.split('\n');
    for (const line of lines) {
      if (!/password|contraseña/i.test(line)) continue;
      const minMatch = line.match(/\.min\((\d+)\)/);
      if (minMatch && parseInt(minMatch[1]) < 10) {
        const relPath = schemaPath.replace(BACKEND_SRC(), 'src');
        findings.push({
          type: 'vulnerability',
          title: `Weak password minimum length (${minMatch[1]} chars) in ${path.basename(schemaPath)}`,
          description: `${relPath} enforces .min(${minMatch[1]}) for passwords. NIST SP 800-63B recommends at least 12 characters for memorized secrets. Short minimums facilitate brute force attacks.`,
          code_example: `z.string().min(${minMatch[1]})  // Should be at least .min(12)`,
          cve: null,
        });
        break; // One finding per schema file
      }
    }
  }

  // --- Auth controller: bcrypt rounds ---
  const authControllerPath = path.join(src, 'controllers', 'auth.controller.js');
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

    // Check for OTP expiry
    if (/EmailVerificationOtp|otp/i.test(authController)) {
      const hasExpiry = /expiresAt|expire/i.test(authController);
      const hasAttemptLimit = /attempt|lockedUntil/i.test(authController);
      if (!hasExpiry) {
        findings.push({
          type: 'warning',
          title: 'OTP codes may not have enforced expiry',
          description: 'OTP verification found but no clear expiresAt validation detected in auth controller. Unexpiring OTP codes can be exploited long after issuance.',
          code_example: null,
          cve: null,
        });
      }
    }
  }

  recommendations.push(
    'Remove the JWT_SECRET fallback: if it\'s unset, throw at startup. Add: if (!process.env.JWT_SECRET) throw new Error(\'JWT_SECRET is required\').',
    'Add algorithms option: jwt.verify(token, secret, { algorithms: [\'HS256\'] }).',
    'Increase password minimum to 12 characters in all Zod schemas.',
    'Implement JWT token revocation using a Redis-backed jti denylist for critical operations (logout, password change).',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const severity = vulnCount >= 2 ? 'critical' : vulnCount === 1 ? 'high' : findings.some(f => f.type === 'warning') ? 'medium' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20 - findings.filter(f => f.type === 'warning').length * 7);

  return { id: 'auth', name: 'Autenticación & JWT', severity, score, findings, recommendations, _codeSnippets };
}
