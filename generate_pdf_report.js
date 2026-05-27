#!/usr/bin/env node
/**
 * Fractia — PDF Report Generator
 * Generates a styled PDF from a Fractia JSON audit report.
 * Usage: node generate_pdf_report.js <path-to-json-report>
 */
import PDFDocument from 'pdfkit';
import { createWriteStream, readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Args ─────────────────────────────────────────────────────────────────────
const jsonPath = process.argv[2];
if (!jsonPath) {
  console.error('Usage: node generate_pdf_report.js <report.json>');
  process.exit(1);
}

const report   = JSON.parse(readFileSync(path.resolve(jsonPath), 'utf8'));
const outPath  = path.resolve(jsonPath).replace(/\.json$/, '.pdf');

// ── Theme ─────────────────────────────────────────────────────────────────────
const C = {
  bg:       '#0d1117',
  surface:  '#161b22',
  border:   '#30363d',
  text:     '#e6edf3',
  muted:    '#8b949e',
  accent:   '#58a6ff',
  critical: '#ff453a',
  high:     '#ff9f0a',
  medium:   '#ffd60a',
  low:      '#30d158',
  ok:       '#30d158',
  white:    '#ffffff',
};

const SEV_COLOR = { critical: C.critical, high: C.high, medium: C.medium, low: C.low, ok: C.ok };
const SEV_LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', ok: 'OK' };
const SEV_ICON  = { critical: '●', high: '●', medium: '●', low: '●', ok: '✓' };

// ── Document ──────────────────────────────────────────────────────────────────
const doc = new PDFDocument({
  size: 'A4',
  margins: { top: 0, bottom: 0, left: 0, right: 0 },
  bufferPages: true,
  info: {
    Title: `Fractia Security Audit — ${report.meta?.target || 'Report'}`,
    Author: 'Fractia v3.0.0',
    Subject: 'Security Analysis Report',
  },
});

const stream = createWriteStream(outPath);
doc.pipe(stream);

const W  = doc.page.width;   // 595.28
const H  = doc.page.height;  // 841.89
const ML = 48;                // margin left
const MR = W - 48;           // margin right
const CW = MR - ML;          // content width

// ── Helpers ───────────────────────────────────────────────────────────────────
let cursorY = 0;

function fillPage(color = C.bg) {
  doc.rect(0, 0, W, H).fill(color);
}

function heading1(text, y) {
  doc.font('Helvetica-Bold').fontSize(26).fillColor(C.white);
  doc.text(text, ML, y, { width: CW });
  return doc.y + 6;
}

function heading2(text, color = C.accent) {
  checkPageBreak(40);
  doc.font('Helvetica-Bold').fontSize(14).fillColor(color);
  doc.text(text, ML, cursorY, { width: CW });
  cursorY = doc.y + 8;
}

function heading3(text, color = C.text) {
  checkPageBreak(30);
  doc.font('Helvetica-Bold').fontSize(11).fillColor(color);
  doc.text(text, ML, cursorY, { width: CW });
  cursorY = doc.y + 4;
}

function body(text, color = C.muted, indent = 0) {
  checkPageBreak(20);
  doc.font('Helvetica').fontSize(9).fillColor(color);
  doc.text(text, ML + indent, cursorY, { width: CW - indent });
  cursorY = doc.y + 3;
}

function codeBlock(text) {
  const lines = String(text).split('\n').slice(0, 6);
  const blockH = lines.length * 13 + 14;
  checkPageBreak(blockH + 4);
  doc.roundedRect(ML, cursorY, CW, blockH, 4).fill('#1c2128');
  doc.font('Courier').fontSize(8).fillColor('#79c0ff');
  doc.text(lines.join('\n'), ML + 10, cursorY + 7, { width: CW - 20 });
  cursorY = doc.y + 10;
}

function divider(color = C.border) {
  checkPageBreak(10);
  doc.moveTo(ML, cursorY).lineTo(MR, cursorY).lineWidth(0.5).stroke(color);
  cursorY += 10;
}

function spacer(n = 10) { cursorY += n; }

function checkPageBreak(needed = 60) {
  if (cursorY + needed > H - 40) {
    doc.addPage();
    fillPage();
    drawPageFooter();
    cursorY = 40;
  }
}

function severityBadge(sev, x, y) {
  const col   = SEV_COLOR[sev] || C.muted;
  const label = SEV_LABEL[sev] || sev.toUpperCase();
  const bw    = label.length * 6.5 + 14;
  doc.roundedRect(x, y - 2, bw, 16, 3).fill(col + '33');
  doc.font('Helvetica-Bold').fontSize(8).fillColor(col);
  doc.text(label, x + 7, y + 1, { width: bw - 14 });
  return bw + 8;
}

function scoreBar(score, x, y, width = 180) {
  const pct = Math.min(100, score);
  const filled = Math.round(pct / 100 * width);
  const col = pct >= 80 ? C.critical : pct >= 50 ? C.high : pct >= 25 ? C.medium : C.ok;
  doc.roundedRect(x, y, width, 8, 2).fill(C.border);
  if (filled > 0) doc.roundedRect(x, y, filled, 8, 2).fill(col);
  doc.font('Helvetica-Bold').fontSize(8).fillColor(C.text);
  doc.text(`${pct}/100`, x + width + 8, y - 1);
}

function drawPageFooter() {
  const range = doc.bufferedPageRange();
  const pageNum = range.start + range.count;
  doc.font('Helvetica').fontSize(7.5).fillColor(C.muted);
  doc.text(
    `Fractia v3.0.0  ·  Confidential Security Report  ·  ${new Date(report.meta?.generatedAt || Date.now()).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}`,
    ML, H - 24, { width: CW - 40 }
  );
  doc.text(`Page ${pageNum}`, MR - 50, H - 24, { width: 50, align: 'right' });
  doc.moveTo(ML, H - 32).lineTo(MR, H - 32).lineWidth(0.4).stroke(C.border);
}

// ── Cover Page ────────────────────────────────────────────────────────────────
fillPage();

// Top accent bar
doc.rect(0, 0, W, 6).fill(C.critical);

// Logo wordmark area
doc.font('Helvetica-Bold').fontSize(42).fillColor(C.white);
doc.text('FRACTIA', ML, 90);
doc.font('Helvetica').fontSize(13).fillColor(C.muted);
doc.text('Full-Stack Security Platform  ·  v3.0.0', ML, 140);

// Divider line
doc.moveTo(ML, 170).lineTo(MR, 170).lineWidth(1).stroke(C.border);

// Report title block
doc.font('Helvetica-Bold').fontSize(22).fillColor(C.accent);
doc.text('Security Audit Report', ML, 200);
doc.font('Helvetica-Bold').fontSize(18).fillColor(C.white);
doc.text(report.meta?.target || 'Project', ML, 232);

// Meta table
const metaItems = [
  ['Date',       new Date(report.meta?.generatedAt || Date.now()).toLocaleString('en-US', { dateStyle: 'full', timeStyle: 'short' })],
  ['Mode',       (report.meta?.depth || 'full').toUpperCase()],
  ['AI Engine',  (report.meta?.aiProvider || 'claude').toUpperCase()],
  ['Components', (report.meta?.components || []).join(', ')],
];
let metaY = 290;
for (const [k, v] of metaItems) {
  doc.font('Helvetica-Bold').fontSize(9).fillColor(C.muted).text(k.toUpperCase(), ML, metaY, { width: 100 });
  doc.font('Helvetica').fontSize(9).fillColor(C.text).text(v, ML + 110, metaY, { width: CW - 110 });
  metaY += 20;
}

// Overall score card
const scoreCardY = 430;
doc.roundedRect(ML, scoreCardY, CW, 120, 8).fill(C.surface);
doc.roundedRect(ML, scoreCardY, CW, 120, 8).lineWidth(1).stroke(C.border);

doc.font('Helvetica-Bold').fontSize(11).fillColor(C.muted);
doc.text('OVERALL RISK SCORE', ML + 24, scoreCardY + 18);
const hasCritical = (report.backend-api?.results || []).some(r => r.severity === 'critical');
const scoreColor  = hasCritical ? C.critical : C.high;
doc.font('Helvetica-Bold').fontSize(56).fillColor(scoreColor);
doc.text(`${report.overallRiskScore}`, ML + 24, scoreCardY + 34);
doc.font('Helvetica').fontSize(18).fillColor(C.muted).text('/100', ML + 24 + 86, scoreCardY + 52);

// Score bar on card
doc.roundedRect(ML + 180, scoreCardY + 20, 340, 10, 3).fill(C.border);
const filled2 = Math.round(report.overallRiskScore / 100 * 340);
doc.roundedRect(ML + 180, scoreCardY + 20, filled2, 10, 3).fill(scoreColor);

// Component scores
const compY = scoreCardY + 74;
doc.font('Helvetica').fontSize(9).fillColor(C.muted);
doc.text('backend-api', ML + 180, compY);
doc.text('frontend-app', ML + 180, compY + 18);
scoreBar(report.backend-api?.riskScore || 0, ML + 265, compY + 1, 240);
scoreBar(report.frontend-app?.riskScore || 0, ML + 265, compY + 19, 240);

// Severity legend
const legendY = 580;
doc.font('Helvetica-Bold').fontSize(9).fillColor(C.muted);
doc.text('FINDINGS BREAKDOWN', ML, legendY);

const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
const allResults = [...(report.backend-api?.results || []), ...(report.frontend-app?.results || [])];
for (const r of allResults) {
  if (sevCounts[r.severity] !== undefined) sevCounts[r.severity]++;
}
// Deduplicate (both components have same findings - shared git repo)
for (const k of Object.keys(sevCounts)) sevCounts[k] = Math.round(sevCounts[k] / 2);

let lx = ML;
for (const [sev, count] of Object.entries(sevCounts)) {
  const col = SEV_COLOR[sev];
  doc.roundedRect(lx, legendY + 16, 100, 56, 6).fill(C.surface);
  doc.roundedRect(lx, legendY + 16, 100, 56, 6).lineWidth(0.5).stroke(col + '66');
  doc.font('Helvetica-Bold').fontSize(28).fillColor(col).text(String(count), lx + 12, legendY + 22);
  doc.font('Helvetica').fontSize(8).fillColor(C.muted).text(SEV_LABEL[sev], lx + 12, legendY + 56);
  lx += 112;
}

// Bottom disclaimer
doc.font('Helvetica').fontSize(8).fillColor(C.muted);
doc.text(
  'This report is confidential. Generated by automated static analysis. Findings should be verified before remediation.',
  ML, H - 70, { width: CW, align: 'center' }
);

// Cover footer line
doc.moveTo(0, H - 6).lineTo(W, H - 6).lineWidth(6).stroke(C.accent);

// ── Page 2: Table of Contents + Summary ──────────────────────────────────────
doc.addPage();
fillPage();
drawPageFooter();
cursorY = 48;

heading2('Table of Contents', C.white);
spacer(4);
divider();
const toc = [
  ['1.', 'Executive Summary', '3'],
  ['2.', 'High Severity Findings', '4'],
  ['3.', 'Medium Severity Findings', '7'],
  ['4.', 'Low Severity Findings', '9'],
  ['5.', 'Passed Modules', '10'],
  ['6.', 'Dependency CVEs', '10'],
  ['7.', 'Remediation Roadmap', '11'],
];
for (const [num, title, pg] of toc) {
  checkPageBreak(22);
  doc.font('Helvetica-Bold').fontSize(10).fillColor(C.accent).text(num, ML, cursorY, { width: 24, continued: false });
  doc.font('Helvetica').fontSize(10).fillColor(C.text).text(title, ML + 28, cursorY, { width: CW - 80, continued: false });
  doc.font('Helvetica').fontSize(10).fillColor(C.muted).text(pg, MR - 30, cursorY, { width: 30, align: 'right' });
  cursorY = Math.max(cursorY + 18, doc.y + 2);
  doc.moveTo(ML + 28, cursorY - 6).lineTo(MR - 35, cursorY - 6).lineWidth(0.3).dash(2, { space: 3 }).stroke(C.border);
  doc.undash();
}

// ── Page 3+: Executive Summary ────────────────────────────────────────────────
doc.addPage();
fillPage();
drawPageFooter();
cursorY = 48;

heading2('1. Executive Summary');
spacer(4);
divider();

body(`This report presents the results of a full-mode static application security testing (SAST) analysis of the ExampleApp platform, covering both the backend API (backend-api — NestJS + MongoDB) and the frontend application (frontend-app — Next.js 15 + Redux). The analysis was performed by Fractia v3.0.0 with AI enrichment via Claude.`, C.text);
spacer(8);

// Summary table header
checkPageBreak(140);
const tableX   = ML;
const colW     = [160, 80, 60, 50, 60, 50, 50];
const tableW   = colW.reduce((a, b) => a + b, 0);
const headers  = ['Component', 'Risk Score', 'Critical', 'High', 'Medium', 'Low', 'OK'];
const tableRowH = 26;

// Draw table
function tableRow(cells, y, bg, textColor = C.text, bold = false) {
  doc.rect(tableX, y, tableW, tableRowH).fill(bg);
  let cx = tableX;
  for (let i = 0; i < cells.length; i++) {
    doc.font(bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(9).fillColor(textColor);
    doc.text(String(cells[i]), cx + 8, y + 8, { width: colW[i] - 10 });
    cx += colW[i];
  }
  // bottom border
  doc.moveTo(tableX, y + tableRowH).lineTo(tableX + tableW, y + tableRowH).lineWidth(0.4).stroke(C.border);
}

tableRow(headers, cursorY, C.surface, C.muted, true);
cursorY += tableRowH;

function countSev(results, sev) {
  return (results || []).filter(r => r.severity === sev).length;
}

for (const [compKey, label] of [['backend-api', 'backend-api (NestJS + MongoDB)'], ['frontend-app', 'frontend-app (Next.js 15)']]) {
  const comp = report[compKey];
  const results = comp?.results || [];
  const row = [
    label,
    `${comp?.riskScore}/100`,
    countSev(results, 'critical'),
    countSev(results, 'high'),
    countSev(results, 'medium'),
    countSev(results, 'low'),
    countSev(results, 'ok'),
  ];
  tableRow(row, cursorY, '#1a2030', C.text);
  cursorY += tableRowH;
}

// Overall row — compute counts dynamically
const _apiRes = report.backend-api?.results || [];
const _overallCounts = ['critical','high','medium','low','ok'].map(s => String(_apiRes.filter(r => r.severity === s).length));
tableRow(['OVERALL', `${report.overallRiskScore}/100`, ..._overallCounts], cursorY, C.surface, C.accent, true);
cursorY += tableRowH + 16;

body('The platform scored 100/100 (maximum risk) driven by four high-severity issues: absent rate limiting, unverified JWT middleware, dangerouslySetInnerHTML XSS exposure, and nine HIGH-severity dependency CVEs. A previously flagged CRITICAL finding (MongoDB credentials in git history) was reclassified as LOW after manual review — the commit contained env-var template code, not literal credentials.', C.text);

// ── Findings Pages ────────────────────────────────────────────────────────────
function findingCard(finding, recs, aiAnalysis, sectionLabel) {
  checkPageBreak(120);

  // Card background
  const sev   = finding.severity || 'medium';
  const col   = SEV_COLOR[sev] || C.muted;
  const cardY = cursorY;

  // Left accent bar
  doc.rect(ML, cardY, 4, 2).fill(col); // will expand below

  // Title row
  doc.font('Helvetica-Bold').fontSize(11).fillColor(C.white);
  doc.text(finding.name || finding.id || sectionLabel, ML + 14, cursorY, { width: CW - 100 });
  const titleH = doc.y - cursorY;
  severityBadge(sev, MR - 85, cursorY);
  cursorY = doc.y + 6;

  // Left accent bar — full height
  doc.rect(ML, cardY, 4, cursorY - cardY + 4).fill(col);

  // Score
  if (finding.score !== undefined) {
    doc.font('Helvetica').fontSize(8).fillColor(C.muted).text(`Score: ${finding.score}/100`, ML + 14, cursorY);
    cursorY = doc.y + 6;
  }

  // Findings
  for (const f of (finding.findings || [])) {
    checkPageBreak(60);
    const fIcon = f.type === 'vulnerability' ? '⚠' : f.type === 'warning' ? '▲' : '●';
    const fColor = f.type === 'vulnerability' ? C.critical : f.type === 'warning' ? C.high : C.muted;
    doc.font('Helvetica-Bold').fontSize(9).fillColor(fColor).text(`${fIcon}  ${f.title}`, ML + 14, cursorY, { width: CW - 20 });
    cursorY = doc.y + 2;
    if (f.description) {
      body(f.description.slice(0, 400), C.muted, 22);
    }
    if (f.cve) {
      doc.font('Helvetica-Bold').fontSize(8).fillColor(C.accent).text(`CVE/CWE: ${f.cve}`, ML + 22, cursorY);
      cursorY = doc.y + 4;
    }
    if (f.file) {
      doc.font('Courier').fontSize(8).fillColor(C.accent).text(`${f.file}:${f.line || '?'}`, ML + 22, cursorY, { width: CW - 30 });
      cursorY = doc.y + 4;
    }
    if (f.code_example) {
      codeBlock(f.code_example);
    }
    spacer(4);
  }

  // Recommendations
  if (recs && recs.length > 0) {
    checkPageBreak(30);
    doc.font('Helvetica-Bold').fontSize(9).fillColor(C.accent).text('Recommendations', ML + 14, cursorY);
    cursorY = doc.y + 4;
    for (const rec of recs.slice(0, 4)) {
      checkPageBreak(20);
      doc.font('Helvetica').fontSize(8.5).fillColor(C.text).text(`→  ${rec.slice(0, 220)}`, ML + 22, cursorY, { width: CW - 30 });
      cursorY = doc.y + 3;
    }
  }

  // AI analysis
  if (aiAnalysis) {
    checkPageBreak(40);
    spacer(4);
    doc.roundedRect(ML + 14, cursorY, CW - 18, 0, 4).fill('#1c2128'); // placeholder
    const aiStartY = cursorY;
    doc.font('Helvetica-Bold').fontSize(8).fillColor('#ae8fff').text('AI ANALYSIS', ML + 22, cursorY + 6);
    cursorY = doc.y + 2;
    doc.font('Helvetica').fontSize(8).fillColor(C.muted).text(aiAnalysis.slice(0, 500), ML + 22, cursorY, { width: CW - 30 });
    cursorY = doc.y + 6;
    doc.roundedRect(ML + 14, aiStartY, CW - 18, cursorY - aiStartY, 4).lineWidth(0.5).stroke('#ae8fff44');
  }

  spacer(16);
  divider(C.border);
  spacer(6);
}

// ── Section: High ─────────────────────────────────────────────────────────────
doc.addPage();
fillPage();
drawPageFooter();
cursorY = 48;

const apiResults = report.backend-api?.results || [];

heading2('2. High Severity Findings', C.high);
spacer(4);
divider(C.high + '44');

const highMods = apiResults.filter(r => r.severity === 'high');
for (const mod of highMods) {
  findingCard(mod, mod.recommendations, mod.ai_analysis);
}

// ── Section: Medium ───────────────────────────────────────────────────────────
checkPageBreak(60);
heading2('3. Medium Severity Findings', C.medium);
spacer(4);
divider(C.medium + '44');

const mediumMods = apiResults.filter(r => r.severity === 'medium');
for (const mod of mediumMods) {
  findingCard(mod, mod.recommendations, mod.ai_analysis);
}

// ── Section: Low ─────────────────────────────────────────────────────────────
checkPageBreak(60);
heading2('4. Low Severity Findings', C.low);
spacer(4);
divider(C.low + '44');

const lowMods = apiResults.filter(r => r.severity === 'low');
for (const mod of lowMods) {
  findingCard(mod, mod.recommendations, mod.ai_analysis);
}

// ── Section: Passed ───────────────────────────────────────────────────────────
checkPageBreak(80);
heading2('5. Passed Modules', C.ok);
spacer(4);
divider(C.ok + '44');

const okMods = apiResults.filter(r => r.severity === 'ok');
for (const mod of okMods) {
  checkPageBreak(40);
  doc.font('Helvetica-Bold').fontSize(10).fillColor(C.ok).text(`✓  ${mod.name || mod.id}`, ML, cursorY);
  cursorY = doc.y + 4;
  if (mod.recommendations?.length) {
    for (const rec of mod.recommendations.slice(0, 2)) {
      body(`→  ${rec.slice(0, 220)}`, C.muted, 18);
    }
  }
  spacer(8);
}

// ── Section: Dependency CVEs ──────────────────────────────────────────────────
const depMod = apiResults.find(r => r.id === 'deps');
if (depMod) {
  checkPageBreak(80);
  heading2('6. Dependency CVEs', C.high);
  spacer(4);
  divider(C.high + '44');

  const vulnFindings = (depMod.findings || []).filter(f => f.type === 'vulnerability' && f.title !== depMod.findings[0]?.title);
  const auditFinding = (depMod.findings || [])[0];
  if (auditFinding) {
    body(auditFinding.description || '', C.text);
    spacer(6);
  }

  // CVE table
  const cveCols = [220, 260, 70];
  const cveHeaders = ['Package', 'Description', 'Severity'];
  const cveTableW = cveCols.reduce((a, b) => a + b, 0);

  checkPageBreak(40);
  // header
  let cveX = ML;
  for (let i = 0; i < cveHeaders.length; i++) {
    doc.rect(cveX, cursorY, cveCols[i], 22).fill(C.surface);
    doc.font('Helvetica-Bold').fontSize(8.5).fillColor(C.muted).text(cveHeaders[i], cveX + 6, cursorY + 6, { width: cveCols[i] - 8 });
    cveX += cveCols[i];
  }
  doc.moveTo(ML, cursorY + 22).lineTo(ML + cveTableW, cursorY + 22).lineWidth(0.4).stroke(C.border);
  cursorY += 22;

  for (const f of (depMod.findings || []).filter(f => f.title !== auditFinding?.title)) {
    checkPageBreak(28);
    cveX = ML;
    const rowBg = (depMod.findings.indexOf(f) % 2 === 0) ? '#151b23' : C.bg;
    const cells = [
      f.title?.split(' —')[0] || '-',
      (f.description || '').split('. ')[0].slice(0, 80),
      'HIGH',
    ];
    const rowH = 22;
    for (let i = 0; i < cells.length; i++) {
      doc.rect(cveX, cursorY, cveCols[i], rowH).fill(rowBg);
      const textColor = i === 2 ? C.high : C.text;
      doc.font(i === 2 ? 'Helvetica-Bold' : 'Helvetica').fontSize(8).fillColor(textColor);
      doc.text(cells[i], cveX + 6, cursorY + 6, { width: cveCols[i] - 8 });
      cveX += cveCols[i];
    }
    doc.moveTo(ML, cursorY + rowH).lineTo(ML + cveTableW, cursorY + rowH).lineWidth(0.3).stroke(C.border);
    cursorY += rowH;
  }
  spacer(12);
}

// ── Section: Remediation Roadmap ──────────────────────────────────────────────
checkPageBreak(200);
heading2('7. Remediation Roadmap', C.accent);
spacer(4);
divider();

const roadmap = [
  { priority: 'P0', label: 'IMMEDIATE', color: C.high, items: [
    { action: 'Install @nestjs/throttler — add rate limits on all auth and public routes', effort: '1 hr' },
    { action: 'Fix middleware.ts to verify JWT server-side using jose or next-auth getToken()', effort: '2 hrs' },
    { action: 'Add /api/:path* to Next.js middleware matcher', effort: '15 min' },
  ]},
  { priority: 'P1', label: 'THIS SPRINT', color: C.high, items: [
    { action: 'Sanitize dangerouslySetInnerHTML in ConfirmModal.tsx with DOMPurify', effort: '30 min' },
    { action: 'npm audit fix + manual version bumps for remaining HIGH CVEs', effort: '1 hr' },
    { action: 'Configure security headers in next.config.ts (CSP, HSTS, X-Frame-Options)', effort: '1 hr' },
    { action: 'Verify admin@example.com / user@example.com not in prod DB with seed passwords', effort: '15 min' },
  ]},
  { priority: 'P2', label: 'NEXT SPRINT', color: C.medium, items: [
    { action: 'Install Helmet.js in NestJS main.ts', effort: '30 min' },
    { action: 'Add startup env var validation (throw if JWT_SECRET / MONGODB_URI missing)', effort: '30 min' },
    { action: 'Configure trust proxy for reverse proxy deployments', effort: '15 min' },
    { action: 'Adopt pino structured logger with redaction for sensitive fields', effort: '2 hrs' },
    { action: 'Set up npm audit as CI/CD gate (fail on HIGH+)', effort: '30 min' },
  ]},
  { priority: 'P3', label: 'BACKLOG', color: C.low, items: [
    { action: 'Implement account lockout (loginAttempts + lockedUntil in User schema)', effort: '4 hrs' },
    { action: 'Add Cloudflare Turnstile CAPTCHA on /register and /forgot-password', effort: '2 hrs' },
    { action: 'Add MFA / TOTP support (otplib) for privileged accounts', effort: '4 hrs' },
    { action: 'Add server keepAliveTimeout / headersTimeout to prevent Slowloris', effort: '30 min' },
  ]},
];

for (const section of roadmap) {
  checkPageBreak(80);
  // Section header
  doc.roundedRect(ML, cursorY, CW, 28, 4).fill(section.color + '22');
  doc.roundedRect(ML, cursorY, 4, 28, 2).fill(section.color);
  doc.font('Helvetica-Bold').fontSize(10).fillColor(section.color).text(`${section.priority} — ${section.label}`, ML + 14, cursorY + 8);
  cursorY += 34;

  for (const item of section.items) {
    checkPageBreak(28);
    doc.rect(ML, cursorY, CW, 22).fill('#141a22');
    doc.moveTo(ML, cursorY + 22).lineTo(ML + CW, cursorY + 22).lineWidth(0.3).stroke(C.border);
    doc.font('Helvetica').fontSize(9).fillColor(C.text).text(item.action, ML + 14, cursorY + 6, { width: CW - 100 });
    doc.font('Helvetica').fontSize(8.5).fillColor(C.muted).text(item.effort, MR - 70, cursorY + 7, { width: 65, align: 'right' });
    cursorY += 22;
  }
  spacer(12);
}

// ── Back Cover ────────────────────────────────────────────────────────────────
doc.addPage();
fillPage();

doc.rect(0, 0, W, 6).fill(C.accent);
doc.rect(0, H - 6, W, 6).fill(C.accent);

doc.font('Helvetica-Bold').fontSize(20).fillColor(C.white);
doc.text('End of Report', ML, H / 2 - 60, { width: CW, align: 'center' });
doc.font('Helvetica').fontSize(10).fillColor(C.muted);
doc.text('Generated by Fractia v3.0.0  ·  AI-powered security analysis', ML, H / 2 - 30, { width: CW, align: 'center' });
doc.font('Helvetica').fontSize(9).fillColor(C.muted);
doc.text(
  'This report is confidential and intended solely for the ExampleApp development team.\nFindings represent the state of the codebase at the time of analysis.',
  ML, H / 2 + 10, { width: CW, align: 'center' }
);

// ── Finalize ──────────────────────────────────────────────────────────────────
const range = doc.bufferedPageRange();
for (let i = range.start; i < range.start + range.count; i++) {
  doc.switchToPage(i);
}

doc.end();

stream.on('finish', () => {
  console.log(`\n  PDF report saved → ${outPath}\n`);
});
