// ============================================================
//  Integración del Sandbox Manager en fractia.js
//  Añade esta opción al menú principal de tu CLI
// ============================================================

// 1. Importa 'child_process' al inicio del archivo
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ──────────────────────────────────────────────────────────
// 2. Función para lanzar el Sandbox Manager
// ──────────────────────────────────────────────────────────

async function launchSandbox() {
  const sandboxScript = path.join(__dirname, 'sandbox.sh');

  // Asegura que el script tenga permisos de ejecución
  const chmod = spawn('chmod', ['+x', sandboxScript]);
  await new Promise(resolve => chmod.on('close', resolve));

  // Lanza sandbox.sh pasando el control total al proceso hijo
  // (stdin/stdout/stderr heredados = interactividad completa)
  const sandbox = spawn('bash', [sandboxScript], {
    stdio: 'inherit',
    detached: false,
    cwd: __dirname,
  });

  return new Promise((resolve) => {
    sandbox.on('close', (code) => {
      resolve(code);
    });
  });
}

// ──────────────────────────────────────────────────────────
// 3. Añade esta opción al array/objeto de tu menú principal
//    (ajusta según cómo estés manejando el menú en fractia.js)
// ──────────────────────────────────────────────────────────

// Ejemplo si usas inquirer:
const sandboxChoice = {
  name: '⚡ Sandbox Manager    — Entorno Docker de pruebas',
  value: 'sandbox',
  short: 'Sandbox',
};

// Ejemplo si usas un switch/case con números:
// case '8':  ← Añade el número que siga en tu menú
//   await launchSandbox();
//   break;

// ──────────────────────────────────────────────────────────
// 4. En el handler del menú, añade el case correspondiente:
// ──────────────────────────────────────────────────────────

// switch (answer) {
//   ...tus cases existentes...
//
//   case 'sandbox':
//     await launchSandbox();
//     break;
// }

// ──────────────────────────────────────────────────────────
// 5. Opcionalmente, añade estos scripts al package.json:
// ──────────────────────────────────────────────────────────

// "scripts": {
//   "sandbox":        "bash sandbox.sh",
//   "sandbox:build":  "bash sandbox.sh build",
//   "sandbox:up":     "bash sandbox.sh up",
//   "sandbox:shell":  "bash sandbox.sh shell",
//   "sandbox:down":   "bash sandbox.sh down",
//   "sandbox:status": "bash sandbox.sh status",
//   "sandbox:nuke":   "bash sandbox.sh nuke"
// }
//
// Uso: npm run sandbox
//      npm run sandbox:up
//      npm run sandbox:shell

export { launchSandbox };
