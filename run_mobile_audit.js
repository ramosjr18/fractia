/**
 * ExampleApp audit driver — runs Fractia Code Engine + Flutter Engine non-interactively.
 *
 * Outputs three JSON files into <ExampleApp>/.audit/ :
 *   - fractia-code.json     (Code Engine, all modules, depth=standard)
 *   - fractia-flutter-user.json   (Flutter Engine, apps/exampleapp_user)
 *   - fractia-flutter-driver.json (Flutter Engine, apps/exampleapp_driver)
 *
 * Plus a combined fractia-raw.json (everything in one envelope).
 */
import path from 'path';
import { mkdirSync, writeFileSync, existsSync } from 'fs';
import { config } from './config.js';
import { runCodeAudit, ALL_MODULES, calculateRiskScore, generateSummary } from './engines/codeAudit.js';
import { runMobileAudit, MOBILE_MODULES, isMobileProject } from './engines/flutterRunner.js';

const ExampleApp_ROOT = process.env.PROJECT_ROOT || process.argv[2];
if (!ExampleApp_ROOT) {
  console.error('Usage: PROJECT_ROOT=/path/to/project node run_mobile_audit.js  (or pass the path as the first arg)');
  process.exit(1);
}
const AUDIT_DIR = path.join(ExampleApp_ROOT, '.audit');
if (!existsSync(AUDIT_DIR)) mkdirSync(AUDIT_DIR, { recursive: true });

// No AI — keep deterministic, no external calls.
config.aiProvider = 'none';

function ts() { return new Date().toISOString(); }

function logModule(prefix) {
  return (mod, res, ms) => {
    const icon = res.severity === 'ok' ? '✓'
               : res.severity === 'critical' ? '✗'
               : res.severity === 'high' ? '!' : '~';
    const cnt = res.findings?.length || 0;
    console.log(`  ${prefix} [${icon}] ${mod.padEnd(12)} ${res.severity.padEnd(8)} ${String(cnt).padStart(3)} findings  ${ms}ms`);
  };
}

async function runCode() {
  console.log(`\n=== Code Engine — ${ExampleApp_ROOT} ===`);
  config.projectRoot = ExampleApp_ROOT;
  const out = await runCodeAudit(ALL_MODULES, 'standard', {
    onModuleComplete: logModule('code  '),
  });
  return out;
}

async function runFlutter(label, appPath) {
  console.log(`\n=== Flutter Engine — ${appPath} ===`);
  if (!isMobileProject(appPath)) {
    console.log(`  (not a Flutter project — skipping)`);
    return null;
  }
  const hooks = {
    onModuleComplete: ({ module: m, result, ms }) => {
      const icon = result.severity === 'ok' ? '✓'
                 : result.severity === 'critical' ? '✗'
                 : result.severity === 'high' ? '!' : '~';
      const cnt = result.findings?.length || 0;
      console.log(`  fl-${label.padEnd(6)} [${icon}] ${m.padEnd(12)} ${result.severity.padEnd(8)} ${String(cnt).padStart(3)} findings  ${ms}ms`);
    },
  };
  return runMobileAudit(MOBILE_MODULES, appPath, hooks);
}

async function main() {
  console.log(`ExampleApp audit — ${ts()}`);
  console.log(`Target: ${ExampleApp_ROOT}`);

  const codeResult = await runCode();
  const userResult = await runFlutter('user',   path.join(ExampleApp_ROOT, 'apps/exampleapp_user'));
  const drvResult  = await runFlutter('driver', path.join(ExampleApp_ROOT, 'apps/exampleapp_driver'));

  // Write each engine's raw output to its own file.
  const codeReport = {
    meta: {
      engine: 'code',
      tool: 'Fractia v3.0.0',
      projectRoot: ExampleApp_ROOT,
      modules: ALL_MODULES,
      depth: 'standard',
      generatedAt: ts(),
    },
    summary: codeResult.summary,
    risk_score: codeResult.riskScore,
    modules: codeResult.results,
  };
  writeFileSync(path.join(AUDIT_DIR, 'fractia-code.json'),
    JSON.stringify(codeReport, null, 2));

  if (userResult) {
    writeFileSync(path.join(AUDIT_DIR, 'fractia-flutter-user.json'),
      JSON.stringify({
        meta: {
          engine: 'flutter',
          tool: 'Fractia v3.0.0',
          projectRoot: path.join(ExampleApp_ROOT, 'apps/exampleapp_user'),
          modules: MOBILE_MODULES,
          generatedAt: ts(),
        },
        summary: {
          riskScore: userResult.riskScore,
          worstSeverity: userResult.worstSeverity,
          totalFindings: userResult.totalFindings,
          dartFilesScanned: userResult.dartFilesScanned,
          counts: userResult.counts,
        },
        risk_score: userResult.riskScore,
        modules: userResult.results,
      }, null, 2));
  }

  if (drvResult) {
    writeFileSync(path.join(AUDIT_DIR, 'fractia-flutter-driver.json'),
      JSON.stringify({
        meta: {
          engine: 'flutter',
          tool: 'Fractia v3.0.0',
          projectRoot: path.join(ExampleApp_ROOT, 'apps/exampleapp_driver'),
          modules: MOBILE_MODULES,
          generatedAt: ts(),
        },
        summary: {
          riskScore: drvResult.riskScore,
          worstSeverity: drvResult.worstSeverity,
          totalFindings: drvResult.totalFindings,
          dartFilesScanned: drvResult.dartFilesScanned,
          counts: drvResult.counts,
        },
        risk_score: drvResult.riskScore,
        modules: drvResult.results,
      }, null, 2));
  }

  // Combined envelope.
  const combined = {
    meta: {
      tool: 'Fractia v3.0.0',
      target: ExampleApp_ROOT,
      generatedAt: ts(),
      engines: ['code', 'flutter'],
    },
    code: codeReport,
    flutter_user: userResult ? {
      meta: { projectRoot: path.join(ExampleApp_ROOT, 'apps/exampleapp_user'), modules: MOBILE_MODULES },
      summary: {
        riskScore: userResult.riskScore,
        worstSeverity: userResult.worstSeverity,
        totalFindings: userResult.totalFindings,
        dartFilesScanned: userResult.dartFilesScanned,
        counts: userResult.counts,
      },
      modules: userResult.results,
    } : null,
    flutter_driver: drvResult ? {
      meta: { projectRoot: path.join(ExampleApp_ROOT, 'apps/exampleapp_driver'), modules: MOBILE_MODULES },
      summary: {
        riskScore: drvResult.riskScore,
        worstSeverity: drvResult.worstSeverity,
        totalFindings: drvResult.totalFindings,
        dartFilesScanned: drvResult.dartFilesScanned,
        counts: drvResult.counts,
      },
      modules: drvResult.results,
    } : null,
  };
  writeFileSync(path.join(AUDIT_DIR, 'fractia-raw.json'),
    JSON.stringify(combined, null, 2));

  console.log('\n=== Done ===');
  console.log(`Code risk:          ${codeResult.riskScore}/100`);
  if (userResult) console.log(`Flutter user risk:  ${userResult.riskScore}/100  (${userResult.totalFindings} findings)`);
  if (drvResult)  console.log(`Flutter driver risk: ${drvResult.riskScore}/100  (${drvResult.totalFindings} findings)`);
  console.log(`Outputs: ${AUDIT_DIR}`);
}

main().catch(err => {
  console.error('Audit failed:', err.message);
  console.error(err.stack);
  process.exit(1);
});
