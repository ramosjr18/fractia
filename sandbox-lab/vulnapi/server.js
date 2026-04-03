// ============================================================
//  VulnAPI — Servidor Express intencionalmente vulnerable
//  Para uso exclusivo con Fractia Sandbox
// ============================================================

import express from 'express';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ❌ CORS wildcard — detectado por Code Engine (CORS module)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Headers', '*');
  next();
});

// ❌ Sin Helmet — detectado por Code Engine (headers module)
// ❌ Sin rate limiting — detectado por Code Engine (ddos module)
// ❌ Stack traces expuestos — detectado por Code Engine (infra module)

// Base de datos simulada en memoria
const users = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
  { id: 2, username: 'user', password: 'password', role: 'user' },
  { id: 3, username: 'test', password: '123456', role: 'user' },
];

const products = [
  { id: 1, name: 'Widget A', price: 9.99, secret: 'INTERNAL-SKU-001' },
  { id: 2, name: 'Widget B', price: 19.99, secret: 'INTERNAL-SKU-002' },
];

// ── Rutas públicas ─────────────────────────────────────────

app.get('/', (req, res) => {
  res.json({
    name: 'VulnAPI',
    version: '1.0.0',
    endpoints: [
      'POST /login',
      'GET  /users',
      'GET  /products?search=<term>',
      'GET  /admin/users',
      'GET  /debug/config',
      'POST /token/verify',
      'GET  /profile?user=<username>',
      'GET  /file?path=<path>',
      'POST /eval',
    ]
  });
});

// ── VULNERABILIDAD: Inyección SQL simulada ─────────────────
// ❌ Concatenación directa de input en query — detectado por sql.js
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Simulación de query vulnerable: SELECT * FROM users WHERE username='${username}'
  // En una DB real, esto sería inyectable
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.status(401).json({ error: 'Usuario no encontrado' });
  }

  // ❌ Comparación de contraseña en texto plano (sin bcrypt) — detectado por auth.js
  if (user.password !== password) {
    return res.status(401).json({ error: 'Contraseña incorrecta' });
  }

  // ❌ JWT con secret débil — detectado por auth.js
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    'secret123',         // SECRET DÉBIL
    { expiresIn: '7d', algorithm: 'HS256' }
  );

  // ❌ PII en logs — detectado por logging.js
  console.log(`[LOGIN] username=${username} password=${password} ip=${req.ip}`);

  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

// ── VULNERABILIDAD: Endpoint admin sin autenticación ──────
// ❌ Ruta /admin sin middleware de auth — detectado por api.js
app.get('/admin/users', (req, res) => {
  // Devuelve todos los usuarios con contraseñas en texto plano
  res.json({ users });
});

// ── VULNERABILIDAD: Debug endpoint expuesto ───────────────
// ❌ /debug en producción — detectado por api.js e infra.js
app.get('/debug/config', (req, res) => {
  res.json({
    node_env: process.env.NODE_ENV || 'development',
    port: process.env.PORT || 4000,
    jwt_secret: 'secret123',                             // ❌ Secret expuesto
    aws_key: 'AKIAIOSFODNN7EXAMPLE',                     // ❌ AWS key falsa (detectado por secrets.js)
    openai_key: 'sk-proj-examplekeyforpractice1234567',  // ❌ OpenAI key falsa
    db_password: 'root:password@localhost',              // ❌ DB creds
    version: process.version,
    uptime: process.uptime(),
  });
});

// ── VULNERABILIDAD: XSS reflejado ─────────────────────────
// ❌ Input reflejado sin sanitizar — detectado por xss.js
app.get('/products', (req, res) => {
  const { search } = req.query;

  const filtered = products.filter(p =>
    p.name.toLowerCase().includes((search || '').toLowerCase())
  );

  // ❌ Reflejo directo del input en respuesta HTML (cuando Accept: text/html)
  if (req.headers.accept?.includes('text/html')) {
    return res.send(`
      <html>
        <body>
          <h1>Resultados para: ${search}</h1>
          ${filtered.map(p => `<p>${p.name} - $${p.price}</p>`).join('')}
        </body>
      </html>
    `);
  }

  res.json({ search, results: filtered });
});

// ── VULNERABILIDAD: IDOR (Insecure Direct Object Reference) ─
// ❌ Sin validación de ownership — detectado por api.js
app.get('/profile', (req, res) => {
  const { user } = req.query;
  const found = users.find(u => u.username === user);

  if (!found) return res.status(404).json({ error: 'Usuario no encontrado' });

  // ❌ Devuelve datos sensibles incluyendo contraseña
  res.json(found);
});

// ── VULNERABILIDAD: Path Traversal ────────────────────────
// ❌ Lectura de archivos sin sanitizar path — detectado por infra.js
app.get('/file', (req, res) => {
  const { path: filePath } = req.query;

  // En un servidor real, esto permitiría leer /etc/passwd, ../secrets, etc.
  res.json({
    warning: 'En un entorno real, esto permitiría path traversal',
    requested_path: filePath,
    simulated_content: `Contenido de: ${filePath}`,
  });
});

// ── VULNERABILIDAD: eval() ────────────────────────────────
// ❌ eval de input de usuario — detectado por xss.js
app.post('/eval', (req, res) => {
  const { expression } = req.body;

  let result;
  try {
    // ❌ eval directo — crítico
    result = eval(expression); // eslint-disable-line no-eval
  } catch (err) {
    // ❌ Stack trace expuesto — detectado por infra.js
    return res.status(500).json({ error: err.message, stack: err.stack });
  }

  res.json({ expression, result: String(result) });
});

// ── VULNERABILIDAD: JWT sin verificación ──────────────────
app.post('/token/verify', (req, res) => {
  const { token } = req.body;

  try {
    // ❌ Acepta algoritmo 'none' — detectado por auth.js
    const decoded = jwt.decode(token); // decode, no verify
    res.json({ valid: true, payload: decoded });
  } catch (err) {
    res.status(400).json({ valid: false, error: err.message });
  }
});

// ── VULNERABILIDAD: Sin paginación ni límites ─────────────
// ❌ Sin rate limiting — detectado por ddos.js
app.get('/users', (req, res) => {
  res.json({ total: users.length, users });
});

// ── Error handler que expone stack traces ─────────────────
// ❌ Stack traces en producción — detectado por infra.js
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({
    error: err.message,
    stack: err.stack,           // ❌ Stack expuesto
    pid: process.pid,
  });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  VulnAPI corriendo en http://0.0.0.0:${PORT}`);
  console.log('  ⚠️  Servidor intencionalmente vulnerable para Fractia Sandbox\n');
});
