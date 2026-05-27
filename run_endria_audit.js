import { config } from './config.js';
import { runCodeAudit, ALL_MODULES } from './engines/codeAudit.js';
import { writeFileSync } from 'fs';

// Establecemos la ruta del proyecto objetivo (ExampleApp)
config.projectRoot = '/path/to/project';
// Podemos establecer el proveedor de IA si se cuenta con clave (por ejemplo: 'none', 'claude', 'openai')
config.aiProvider = process.env.ANTHROPIC_API_KEY ? 'claude' : (process.env.OPENAI_API_KEY ? 'openai' : 'none');

async function main() {
  console.log(`🚀 Iniciando Full Code Audit para: ${config.projectRoot}`);
  console.log(`🧠 AI Provider configurado: ${config.aiProvider}`);
  console.log('--------------------------------------------------');

  const result = await runCodeAudit(ALL_MODULES, 'full', {
    onModuleStart: (mod) => process.stdout.write(`⏳ Analizando ${mod}... \r`),
    onModuleComplete: (mod, res, timeMs) => {
      process.stdout.write('\x1b[2K\r'); // Limpia la línea actual
      const icon = res.severity === 'ok' ? '✅' : (res.severity === 'critical' ? '🚨' : '⚠️');
      console.log(`${icon} [${mod}] - Severidad: ${res.severity.toUpperCase()} (${res.findings.length} hallazgos) - ${timeMs}ms`);
    },
  });

  writeFileSync('./exampleapp_full_findings.json', JSON.stringify(result, null, 2));
  console.log('\n📝 Resultados detallados guardados en exampleapp_full_findings.json');

  console.log('\n==================================================');
  console.log('📊 RESUMEN DE LA AUDITORÍA');
  console.log('==================================================');
  console.log(`🛑 Risk Score: ${result.riskScore}/100`);
  console.log(`📝 Detalle: ${result.summary}`);
  console.log(`⏱️  Duración total: ${result.meta.scanDurationMs}ms`);
  console.log('==================================================');
}

main().catch(err => {
  console.error('❌ Error durante la auditoría:', err.message);
  process.exit(1);
});
