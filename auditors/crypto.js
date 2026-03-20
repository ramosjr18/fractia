import path from 'path';
import { readFile, grepFiles, BACKEND_SRC, BACKEND_ROOT, truncate } from '../utils/fileScanner.js';

export async function audit(depth) {
  const findings = [];
  const recommendations = [];
  const _codeSnippets = {};

  const src = BACKEND_SRC();

  // --- bcrypt rounds ---
  const authControllerPath = path.join(src, 'controllers', 'auth.controller.js');
  const authController = await readFile(authControllerPath);

  if (authController) {
    const bcryptMatch = authController.match(/bcrypt(?:js)?\.hash\s*\([^,]+,\s*(\d+)\)/);
    if (bcryptMatch) {
      const rounds = parseInt(bcryptMatch[1]);
      if (rounds >= 12) {
        findings.push({
          type: 'info',
          title: `bcrypt cost factor: ${rounds} (good)`,
          description: `bcrypt.hash() uses ${rounds} rounds, which meets OWASP recommendations (≥10). At ${rounds} rounds, offline brute force is computationally expensive.`,
          code_example: null,
          cve: null,
        });
      } else if (rounds >= 10) {
        findings.push({
          type: 'info',
          title: `bcrypt cost factor: ${rounds} (acceptable)`,
          description: `${rounds} rounds meets the minimum but consider upgrading to 12+ as hardware speeds improve.`,
          code_example: null,
          cve: null,
        });
      } else {
        findings.push({
          type: 'vulnerability',
          title: `bcrypt cost factor too low: ${rounds}`,
          description: `bcrypt.hash() uses only ${rounds} rounds. OWASP minimum is 10. Lower values make offline dictionary attacks significantly faster.`,
          code_example: `bcrypt.hash(password, ${rounds})  // Increase to 12`,
          cve: null,
        });
      }
    }
  }

  // --- JWT algorithm ---
  const authMiddlewarePath = path.join(src, 'middleware', 'auth.js');
  const authMiddleware = await readFile(authMiddlewarePath);

  if (authMiddleware) {
    _codeSnippets['middleware/auth.js (crypto)'] = truncate(authMiddleware.slice(0, 1000), 1000);

    if (!/algorithms\s*:\s*\[/.test(authMiddleware)) {
      findings.push({
        type: 'vulnerability',
        title: 'jwt.verify() does not restrict allowed algorithms',
        description: 'Without algorithms: [\'HS256\'], the JWT library accepts tokens signed with any algorithm, including "none". An attacker can craft an unsigned token (alg: none) or exploit algorithm confusion.',
        code_example: '// Fix:\njwt.verify(token, secret, { algorithms: [\'HS256\'] })',
        cve: 'CVE-2022-21449',
      });
    }

    // Check for RS256 (asymmetric) usage
    if (!/RS256|ES256|PS256/i.test(authMiddleware)) {
      findings.push({
        type: 'info',
        title: 'Using symmetric HS256 algorithm',
        description: 'HS256 is symmetric — any service with the secret can both verify and ISSUE tokens. For multi-service architectures, RS256 (asymmetric) is preferred: only the auth service has the private key, other services verify with the public key only.',
        code_example: null,
        cve: null,
      });
    }
  }

  // --- Weak crypto patterns in source ---
  const weakCryptoMatches = await grepFiles(src, [
    /createHash\s*\(\s*['"`]md5['"`]/i,
    /createHash\s*\(\s*['"`]sha1['"`]/i,
    /Math\.random\s*\(\s*\)/,
  ], { extensions: ['.js'] });

  for (const match of weakCryptoMatches) {
    const relPath = match.filePath.replace(BACKEND_ROOT(), 'backend');
    if (/Math\.random/.test(match.line)) {
      // Only flag if it's used for security-sensitive context
      if (/token|secret|password|otp|code|key/i.test(match.context.before.join('') + match.line)) {
        findings.push({
          type: 'vulnerability',
          title: 'Math.random() used in security-sensitive context',
          description: `${relPath}:${match.lineNumber} — Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.randomUUID() for tokens and secrets.`,
          code_example: match.line.trim(),
          cve: null,
        });
      }
    } else {
      findings.push({
        type: 'vulnerability',
        title: `Weak hash algorithm detected: ${match.line.trim()}`,
        description: `${relPath}:${match.lineNumber} — MD5 and SHA1 are cryptographically broken. Use SHA-256 or higher for any security purpose.`,
        code_example: match.line.trim(),
        cve: 'CVE-2004-2761',
      });
    }
  }

  recommendations.push(
    'Specify algorithms in jwt.verify(): jwt.verify(token, secret, { algorithms: [\'HS256\'] }).',
    'Never use Math.random() for security tokens — use crypto.randomBytes(32).toString(\'hex\').',
    'Replace MD5/SHA1 with SHA-256 for any non-password hashing needs.',
    'Consider migrating to RS256 (asymmetric JWT) if microservices are added in the future.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const severity = vulnCount >= 2 ? 'high' : vulnCount === 1 ? 'medium' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20);

  return { id: 'crypto', name: 'Criptografía', severity, score, findings, recommendations, _codeSnippets };
}
