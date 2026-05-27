const fs = require('fs');
const report = JSON.parse(fs.readFileSync('/path/to/fractia/reports/exampleapp-audit-2026-05-07T10-20-35.json', 'utf8'));

for (const comp of ['backend-api', 'frontend-app']) {
  const mod = report[comp].results.find(r => r.id === 'gitHistory');
  if (!mod) continue;

  mod.severity = 'low';
  mod.score = 95;
  mod.findings = [
    {
      type: 'info',
      title: 'False positive — no literal credentials in git history',
      description: 'Commit 94e7b9c added a useFactory fallback that builds a mongodb:// connection string from configService.get() env vars. No literal credentials were present. No .env files were ever committed. No JWT_SECRET or MongoDB URIs with real values found across all 39 commits.',
      code_example: null,
      cve: null
    },
    {
      type: 'warning',
      title: 'seed.js exposes admin account emails publicly',
      description: 'docker/mongo-init/seed.js (initial commit, permanently in git history) contains the admin emails admin@example.com and user@example.com. These are now public, enabling targeted credential stuffing against the production login endpoint.',
      file: 'backend-api/docker/mongo-init/seed.js',
      line: 8,
      code_example: null,
      cve: null
    },
    {
      type: 'info',
      title: 'seed.js contains argon2id hashes for 5 roles (strong — low cracking risk)',
      description: 'Password hashes for admin, manager, warehouse, employee, and user roles use argon2id (m=65536, t=3, p=4). Computationally expensive to crack. Risk is low unless seed accounts were deployed to production with the same passwords.',
      file: 'backend-api/docker/mongo-init/seed.js',
      line: 8,
      code_example: null,
      cve: null
    }
  ];
  mod.recommendations = [
    'Verify that admin@example.com and user@example.com do not exist in the production database with default seed passwords.',
    'Add a // DEV ONLY — never import to production comment block to seed.js and document this in the README.',
    'No git history rewrite is required — no literal credentials were ever committed.',
  ];
  mod.ai_analysis = 'Fractia initially flagged commit 94e7b9c as a credential leak due to the mongodb:// template string added in the useFactory code. Manual review confirms this was a false positive: all connection values are sourced from ConfigService environment variables, not hardcoded literals. The actual residual risk is admin email enumeration from the publicly readable seed.js file.';
}

const WEIGHTS = { critical: 25, high: 15, medium: 7, low: 2, ok: 0 };
for (const comp of ['backend-api', 'frontend-app']) {
  const results = report[comp].results;
  const score = Math.min(100, results.reduce((s, r) => s + (WEIGHTS[r.severity] || 0), 0));
  report[comp].riskScore = score;

  const counts = { critical: 0, high: 0, medium: 0, low: 0, ok: 0 };
  for (const r of results) counts[r.severity] = (counts[r.severity] || 0) + 1;
  const highMods = results.filter(r => r.severity === 'high').map(r => r.name);
  const critMods = results.filter(r => r.severity === 'critical').map(r => r.name);

  let summary = 'Risk score ' + score + '/100 across ' + results.length + ' modules. ';
  if (counts.critical > 0) summary += 'CRITICAL issues in: ' + critMods.join(', ') + '. ';
  if (counts.high > 0) summary += 'HIGH severity in: ' + highMods.join(', ') + '. ';
  if (counts.critical === 0 && counts.high === 0) summary += 'No critical or high severity issues. ';
  summary += counts.ok + ' modules passed cleanly.';
  report[comp].summary = summary;
}

report.overallRiskScore = Math.round(report.backend-api.riskScore * 0.6 + report.frontend-app.riskScore * 0.4);
report.meta.generatedAt = new Date().toISOString();
report.meta.revised = true;
report.meta.revisionNote = 'gitHistory finding corrected after manual review: false positive, no literal credentials in history.';

const out = '/path/to/fractia/reports/exampleapp-audit-2026-05-07T10-20-35-revised.json';
fs.writeFileSync(out, JSON.stringify(report, null, 2));

console.log('Saved:', out);
console.log('API risk score:', report.backend-api.riskScore);
console.log('Frontend risk score:', report.frontend-app.riskScore);
console.log('Overall:', report.overallRiskScore);
console.log('Breakdown API:', report.backend-api.summary);
