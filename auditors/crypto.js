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

  // --- bcrypt rounds ---
  const authControllerPath = path.join(controllersDir, 'auth.controller.js');
  const authController = await readFile(authControllerPath);

  if (authController) {
    const bcryptMatch = authController.match(/bcrypt(?:js)?\.hash\s*\([^,]+,\s*(\d+)\)/);
    if (bcryptMatch) {
      const rounds = parseInt(bcryptMatch[1]);
      if (rounds >= 12) {
        findings.push({
          type: 'info',
          title: `bcrypt cost factor: ${rounds} (good)`,
          description: `bcrypt.hash() uses ${rounds} rounds, which meets OWASP recommendations (≥10).`,
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
  const authMiddlewarePath = path.join(middlewareDir, 'auth.js');
  const authMiddleware = await readFile(authMiddlewarePath);

  if (authMiddleware) {
    _codeSnippets['middleware/auth.js (crypto)'] = truncate(authMiddleware.slice(0, 1000), 1000);

    if (!/algorithms\s*:\s*\[/.test(authMiddleware)) {
      findings.push({
        type: 'vulnerability',
        title: 'jwt.verify() does not restrict allowed algorithms',
        description: 'Without algorithms: [\'HS256\'], the JWT library accepts tokens signed with any algorithm, including "none". An attacker can craft an unsigned token or exploit algorithm confusion.',
        code_example: '// Fix:\njwt.verify(token, secret, { algorithms: [\'HS256\'] })',
        cve: 'CVE-2022-21449',
      });
    }

    if (!/RS256|ES256|PS256/i.test(authMiddleware)) {
      findings.push({
        type: 'info',
        title: 'Using symmetric HS256 algorithm',
        description: 'HS256 is symmetric — any service with the secret can both verify and issue tokens. For multi-service architectures, RS256 (asymmetric) is preferred.',
        code_example: null,
        cve: null,
      });
    }
  }

  // --- Weak crypto patterns ---
  const weakCryptoMatches = await grepFiles(src, [
    /createHash\s*\(\s*['"`]md5['"`]/i,
    /createHash\s*\(\s*['"`]sha1['"`]/i,
    /Math\.random\s*\(\s*\)/,
  ], { extensions: ['.js'] });

  for (const match of weakCryptoMatches) {
    const relPath = match.filePath.replace(src, 'src');
    if (/Math\.random/.test(match.line)) {
      if (/token|secret|password|otp|code|key/i.test(match.context.before.join('') + match.line)) {
        findings.push({
          type: 'vulnerability',
          title: 'Math.random() used in security-sensitive context',
          description: `${relPath}:${match.lineNumber} — Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.randomUUID().`,
          code_example: match.line.trim(),
          cve: null,
        });
      }
    } else {
      findings.push({
        type: 'vulnerability',
        title: `Weak hash algorithm detected: ${match.line.trim()}`,
        description: `${relPath}:${match.lineNumber} — MD5 and SHA1 are cryptographically broken. Use SHA-256 or higher.`,
        code_example: match.line.trim(),
        cve: 'CVE-2004-2761',
      });
    }
  }

  // --- Static IV in AES ---
  const staticIvMatches = await grepFiles(src, [
    /createCipheriv\s*\([^)]+,\s*['"`][^'"`]+['"`]\s*,\s*['"`][^'"`]+['"`]/,
    /iv\s*=\s*['"`][^'"`]+['"`]/,
    /Buffer\.from\s*\(\s*['"`][0]{8,}/,
  ], { extensions: ['.js'] });

  if (staticIvMatches.length > 0) {
    const locs = staticIvMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'Static IV detected in AES encryption',
      description: `Found hardcoded initialization vector at: ${locs}. A static IV makes AES-CBC encryption deterministic — identical plaintexts produce identical ciphertexts, revealing patterns to attackers. Always generate a random IV per encryption with crypto.randomBytes(16).`,
      code_example: staticIvMatches[0]?.line.trim() || null,
      cve: null,
    });
  }

  // --- ECB mode ---
  const ecbMatches = await grepFiles(src, [
    /createCipher\b(?!iv)/,
    /aes.*ecb/i,
    /'aes-\d+-ecb'/i,
  ], { extensions: ['.js'] });

  if (ecbMatches.length > 0) {
    const locs = ecbMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'AES ECB mode (or legacy createCipher) detected',
      description: `Found ECB mode or deprecated createCipher() at: ${locs}. ECB mode encrypts each block independently, making patterns in plaintext visible in ciphertext. Use AES-GCM or AES-CBC with a random IV via createCipheriv().`,
      code_example: ecbMatches[0]?.line.trim() || null,
      cve: null,
    });
  }

  // --- Cipher key derived from password without KDF ---
  const cipherPasswordMatches = await grepFiles(src, [
    /createCipheriv.*password/i,
    /createCipheriv.*secret/i,
  ], { extensions: ['.js'] });

  if (cipherPasswordMatches.length > 0) {
    const locs = cipherPasswordMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'warning',
      title: 'Encryption key may be derived directly from a password without a KDF',
      description: `Found createCipheriv() with a variable named 'password' or 'secret' at: ${locs}. Passwords have low entropy and must be run through a key derivation function (PBKDF2, scrypt, Argon2) before use as a cipher key.`,
      code_example: 'crypto.scryptSync(password, salt, 32)  // Use KDF before createCipheriv()',
      cve: null,
    });
  }

  // --- createHash for passwords (no salt) ---
  const hashPasswordMatches = await grepFiles(src, [
    /createHash.*password/i,
  ], { extensions: ['.js'] });

  if (hashPasswordMatches.length > 0) {
    const locs = hashPasswordMatches.slice(0, 3).map(m => `${path.basename(m.filePath)}:${m.lineNumber}`).join(', ');
    findings.push({
      type: 'vulnerability',
      title: 'crypto.createHash() used for password hashing (no salt)',
      description: `Found createHash() in a password-related context at: ${locs}. Plain hashes (even SHA-256) without a salt are vulnerable to rainbow table attacks and offline brute force. Use bcrypt, scrypt, or Argon2.`,
      code_example: '// Replace:\ncrypto.createHash(\'sha256\').update(password).digest(\'hex\')\n// With:\nawait bcrypt.hash(password, 12)',
      cve: null,
    });
  }

  recommendations.push(
    'Specify algorithms in jwt.verify(): jwt.verify(token, secret, { algorithms: [\'HS256\'] }).',
    'Never use Math.random() for security tokens — use crypto.randomBytes(32).toString(\'hex\').',
    'Replace MD5/SHA1 with SHA-256 for any non-password hashing needs.',
    'Always generate a fresh random IV for every AES encryption: crypto.randomBytes(16).',
    'Use AES-GCM instead of AES-CBC — it provides authenticated encryption (prevents tampering).',
    'Use bcrypt, scrypt, or Argon2 for password hashing — never plain SHA-256.',
    'Run passwords through a KDF (scrypt, PBKDF2) before using as cipher keys.',
  );

  const vulnCount = findings.filter(f => f.type === 'vulnerability').length;
  const severity = vulnCount >= 2 ? 'high' : vulnCount === 1 ? 'medium' : 'ok';
  const score = Math.max(0, 100 - vulnCount * 20);

  return { id: 'crypto', name: 'Criptografía', severity, score, findings, recommendations, _codeSnippets };
}
