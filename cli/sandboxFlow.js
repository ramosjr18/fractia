import readline from 'readline';
import chalk from 'chalk';
import { spawn, execSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { box, divider, colors, t } from './theme.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SANDBOX_SCRIPT = path.join(__dirname, '..', 'sandbox-lab', 'sandbox.sh');

function ask(prompt) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(prompt, ans => { rl.close(); resolve(ans.trim()); }));
}

function clearScreen() {
  process.stdout.write('\x1bc');
}

/**
 * Ejecuta una acción del sandbox de forma síncrona o asíncrona
 */
async function runSandboxAction(action, isInteractive = false) {
  return new Promise((resolve) => {
    const proc = spawn('bash', [SANDBOX_SCRIPT, action], {
      stdio: isInteractive ? 'inherit' : ['ignore', 'pipe', 'pipe'],
      cwd: path.join(__dirname, '..', 'sandbox-lab')
    });

    let output = '';
    if (!isInteractive) {
      proc.stdout.on('data', (data) => output += data.toString());
      proc.stderr.on('data', (data) => output += data.toString());
    }

    proc.on('close', (code) => {
      resolve({ code, output });
    });
  });
}

/**
 * Obtiene el estado simplificado de los contenedores
 */
function getLabStatus() {
  const services = [
    { id: 'fractia-sandbox', name: 'Sandbox (tools)' },
    { id: 'fractia-dvwa', name: 'DVWA' },
    { id: 'fractia-juiceshop', name: 'Juice Shop' },
    { id: 'fractia-vulnapi', name: 'VulnAPI' },
    { id: 'fractia-webgoat', name: 'WebGoat' }
  ];

  const results = [];
  for (const s of services) {
    try {
      const status = execSync(`docker inspect --format='{{.State.Status}}' ${s.id} 2>/dev/null`).toString().trim();
      results.push({ ...s, status });
    } catch (e) {
      results.push({ ...s, status: 'stopped' });
    }
  }
  return results;
}

export async function runSandboxFlow(directAction = null) {
  if (directAction) {
    console.log(`\n  ${chalk.hex('#a78bfa')('◌')} Ejecutando acción: ${chalk.bold(directAction)}…\n`);
    await runSandboxAction(directAction, true);
    return;
  }

  clearScreen();
  console.log('');
  console.log(box(chalk.bold('Fractia Sandbox Lab'), { color: '#a78bfa' }));
  console.log(`  ${colors.dim('Entorno aislado para pruebas de seguridad')}`);
  console.log(`  ${divider(52)}`);
  console.log('');

  const status = getLabStatus();
  console.log(`  ${chalk.bold('Estado del Laboratorio:')}`);
  for (const s of status) {
    const icon = s.status === 'running' ? chalk.hex('#00f5a0')('●') : chalk.hex('#ff2d55')('○');
    const label = s.status === 'running' ? s.name : `${s.name} (detenido)`;
    console.log(`    ${icon} ${label}`);
  }
  console.log('');

  console.log(`  ${divider(52)}`);
  console.log(t.option('[1]', 'Iniciar laboratorio completo (up)'));
  console.log(t.option('[2]', 'Abrir shell en Sandbox (shell)'));
  console.log(t.option('[3]', 'Detener laboratorio (stop)'));
  console.log(t.option('[4]', 'Construir / Reconstruir imágenes (build)'));
  console.log(t.option('[5]', 'Ver logs en tiempo real'));
  console.log(t.option('[6]', 'Eliminar todo (nuke)'));
  console.log(t.option('[q]', 'Volver al menú principal'));
  console.log('');

  const ans = await ask(colors.accent2('  ▸ ') + colors.text('Opción: '));

  switch (ans.toLowerCase()) {
    case '1': await runSandboxAction('up', true); break;
    case '2': await runSandboxAction('shell', true); break;
    case '3': await runSandboxAction('down', true); break;
    case '4': await runSandboxAction('build', true); break;
    case '5': 
      console.log('\n  [1] sandbox [2] dvwa [3] juiceshop [4] vulnapi [5] webgoat [6] todos');
      const l = await ask('  Logs de: ');
      const map = { 1: 'sandbox', 2: 'dvwa', 3: 'juiceshop', 4: 'vulnapi', 5: 'webgoat', 6: '' };
      if (map[l] !== undefined) {
        spawn('docker', ['compose', '-f', 'docker-compose.sandbox.yml', 'logs', '-f', map[l]], {
          stdio: 'inherit',
          cwd: path.join(__dirname, '..', 'sandbox-lab')
        });
        return; // Exit flow to let logs take over
      }
      break;
    case '6': await runSandboxAction('nuke', true); break;
    case 'q': return;
    default: break;
  }

  await ask(colors.dim('\n  Enter para continuar... '));
  return runSandboxFlow();
}
