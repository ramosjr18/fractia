#!/usr/bin/env node
/**
 * ExampleApp Full Security Audit — runs SAST on both backend-api and frontend-app
 * Usage: node run_exampleapp_audit.js
 */
import path from 'path';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Config override ──────────────────────────────────────────────────────────
import { config } from './config.js';

const EXAMPLEAPP_ROOT  = '/path/to/workspace/ExampleApp';
const API_TARGET     = path.join(EXAMPLEAPP_ROOT, 'backend-api');
const FRONT_TARGET   = path.join(EXAMPLEAPP_ROOT, 'frontend-app');
const REPORTS_DIR    = path.join(__dirname, 'reports');
const TIMESTAMP      = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const REPORT_FILE    = path.join(REPORTS_DIR, `exampleapp-audit-${TIMESTAMP}.json`);

if (!existsSync(REPORTS_DIR)) mkdirSync(REPORTS_DIR, { recursive: true });

// Set AI provider (Claude since ANTHROPIC_API_KEY is set)
config.aiProvider = process.env.AI_PROVIDER || 'claude';

const { runCodeAudit, ALL_MODULES } = await import('./engines/codeAudit.js');

// ── Progress helpers ─────────────────────────────────────────────────────────
const SEV_ICON = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', ok: '✅' };

function printModuleResult(mod, result, ms) {
  const icon = SEV_ICON[result.severity] || '⚪';
  const count = result.findings?.length || 0;
  console.log(`   ${icon} ${mod.padEnd(14)} ${result.severity.toUpperCase().padEnd(10)} ${count} findings  (${ms}ms)`);
}

async function scanTarget(label, targetPath, depth) {
  console.log(`\n${'═'.repeat(64)}`);
  console.log(`  🎯  ${label}`);
  console.log(`  📁  ${targetPath}`);
  console.log(`  🔍  Mode: ${depth}`);
  console.log(`${'═'.repeat(64)}\n`);

  config.projectRoot = targetPath;

  const hooks = {
    onModuleStart: (mod) => process.stdout.write(`   ⏳ scanning ${mod}...\r`),
    onModuleComplete: (mod, result, ms) => {
      process.stdout.write('\x1b[2K');
      printModuleResult(mod, result, ms);
    },
  };

  const scan = await runCodeAudit(ALL_MODULES, depth, hooks);
  return scan;
}

// ── Run ──────────────────────────────────────────────────────────────────────
console.log('\n');
console.log('  ██╗   ██╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗████████╗');
console.log('  ██║   ██║██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔════╝╚══██╔══╝');
console.log('  ██║   ██║██║     ██║   ██║██╔██╗ ██║█████╗  ██║        ██║   ');
console.log('  ██║   ██║██║     ██║   ██║██║╚██╗██║██╔══╝  ██║        ██║   ');
console.log('  ╚██████╔╝╚██████╗╚██████╔╝██║ ╚████║███████╗╚██████╗   ██║   ');
console.log('   ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝   ╚═╝   ');
console.log('\n  SECURITY AUDIT  ·  Powered by Fractia v3.0.0');
console.log('  Target: ExampleApp (backend-api + frontend-app)');
console.log(`  Time:   ${new Date().toISOString()}\n`);

const DEPTH = 'full';

const [apiScan, frontScan] = await Promise.all([
  scanTarget('BACKEND-API  (NestJS + MongoDB)', API_TARGET, DEPTH),
  scanTarget('FRONTEND-APP  (Next.js 15 + Redux)', FRONT_TARGET, DEPTH),
]);

// ── Consolidated Report ──────────────────────────────────────────────────────
const report = {
  meta: {
    target: 'ExampleApp',
    components: ['backend-api', 'frontend-app'],
    generatedAt: new Date().toISOString(),
    depth: DEPTH,
    aiProvider: config.aiProvider,
  },
  backend-api: {
    path: API_TARGET,
    riskScore: apiScan.riskScore,
    summary: apiScan.summary,
    meta: apiScan.meta,
    results: apiScan.results,
  },
  frontend-app: {
    path: FRONT_TARGET,
    riskScore: frontScan.riskScore,
    summary: frontScan.summary,
    meta: frontScan.meta,
    results: frontScan.results,
  },
  overallRiskScore: Math.round((apiScan.riskScore * 0.6 + frontScan.riskScore * 0.4)),
};

// Save JSON report
writeFileSync(REPORT_FILE, JSON.stringify(report, null, 2));

// ── Print Summary ────────────────────────────────────────────────────────────
console.log(`\n${'═'.repeat(64)}`);
console.log('  📊  CONSOLIDATED RESULTS');
console.log(`${'═'.repeat(64)}\n`);

function printScanSummary(label, scan) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, ok: 0 };
  for (const r of scan.results) counts[r.severity] = (counts[r.severity] || 0) + 1;

  console.log(`  ── ${label} ──────────────────────────────────────`);
  console.log(`     Risk Score : ${scan.riskScore}/100`);
  console.log(`     Critical   : ${counts.critical}  |  High: ${counts.high}  |  Medium: ${counts.medium}  |  Low: ${counts.low}  |  OK: ${counts.ok}`);
  console.log(`     ${scan.summary}`);

  const critical = scan.results.filter(r => r.severity === 'critical');
  const high     = scan.results.filter(r => r.severity === 'high');

  if (critical.length > 0) {
    console.log('\n     🔴 CRITICAL modules:');
    for (const r of critical) {
      console.log(`        • ${r.name || r.id}`);
      for (const f of (r.findings || []).slice(0, 3)) {
        console.log(`          – ${f.title}${f.file ? ` [${f.file}:${f.line || '?'}]` : ''}`);
      }
    }
  }
  if (high.length > 0) {
    console.log('\n     🟠 HIGH modules:');
    for (const r of high) {
      console.log(`        • ${r.name || r.id}`);
      for (const f of (r.findings || []).slice(0, 3)) {
        console.log(`          – ${f.title}${f.file ? ` [${f.file}:${f.line || '?'}]` : ''}`);
      }
    }
  }
  console.log('');
}

printScanSummary('BACKEND-API (backend)', apiScan);
printScanSummary('FRONTEND-APP (frontend)', frontScan);

console.log(`${'─'.repeat(64)}`);
console.log(`  🎯  OVERALL RISK SCORE : ${report.overallRiskScore}/100  (60% API + 40% Frontend)`);
console.log(`${'─'.repeat(64)}`);
console.log(`\n  💾  Full report saved → ${REPORT_FILE}\n`);
