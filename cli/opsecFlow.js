import readline from 'readline';
import chalk from 'chalk';
import { divider, colors, t, box } from './theme.js';
import { config } from '../config.js';
import { runOpSecCheck, getPublicIP } from '../utils/opsec.js';
import torManager from '../utils/torManager.js';
import { writeFileSync, readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function ask(prompt) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(prompt, ans => { rl.close(); resolve(ans.trim()); }));
}

function clearScreen() {
  process.stdout.write('\x1bc');
}

function saveToEnv(key, value) {
  const envPath = path.join(__dirname, '..', '.env');
  let content = '';
  try { content = readFileSync(envPath, 'utf8'); } catch { }
  const lines = content.split('\n');
  const idx = lines.findIndex(l => l.startsWith(`${key}=`));
  if (idx >= 0) lines[idx] = `${key}=${value}`;
  else lines.push(`${key}=${value}`);
  writeFileSync(envPath, lines.join('\n'), 'utf8');
}

export async function runOpSecFlow() {
  clearScreen();
  console.log('');
  console.log(box(chalk.bold('OpSec & Anonimato'), { color: '#ae63e4' }));
  console.log(`  ${colors.dim('Panel de control de tu huella digital')}`);
  console.log(`  ${divider(52)}`);
  console.log('');

  process.stdout.write(`  ${chalk.hex('#ae63e4')('◌')} Realizando chequeo de seguridad…\r`);
  const status = await runOpSecCheck();
  process.stdout.write('\r\x1b[2K');

  const statusColor = status.status === 'secure' ? '#00f5a0' : status.status === 'warning' ? '#ff9f1c' : '#ff2d55';
  const statusLabel = status.status === 'secure' ? 'SEGURO' : status.status === 'warning' ? 'AVISO' : '¡FUGA DETECTADA!';
  
  console.log(`  Status: ${chalk.hex(statusColor).bold(statusLabel)}`);
  console.log('');

  // ── Capas ───────────────────────────────────────────────────────────
  console.log(`  ${chalk.hex('#ae63e4').bold('Capa 1 — IP Pública')}`);
  console.log(`    IP:      ${chalk.bold(status.ip)}`);
  console.log(`    Proxy:   ${config.proxy ? chalk.hex('#00f5a0')(config.proxy) : colors.dim('No configurado')}`);
  
  const torStatus = status.tor.active ? chalk.hex('#00f5a0')('Activo (Puerto 9050)') : colors.dim('Inactivo');
  console.log(`    Tor:     ${torStatus}`);
  console.log(`    Stealth: ${config.stealthMode ? chalk.hex('#00f5a0')('Activo') : colors.dim('Inactivo')}`);
  console.log('');

  console.log(`  ${chalk.hex('#ae63e4').bold('Capa 2 — Fingerprint')}`);
  console.log(`    OS:      ${chalk.bold(status.fingerprint.os)}`);
  console.log(`    TTL:     ${chalk.hex('#38bdf8')(status.fingerprint.ttl)}  ${colors.dim(`(RFC 1700)`)}`);
  console.log('');

  console.log(`  ${chalk.hex('#ae63e4').bold('Capa 3 y 5 — Herramientas')}`);
  console.log(`    User-Agent: ${colors.dim(config.userAgent.slice(0, 45) + '...')}`);
  if (status.mac.leaked) {
    console.log(`    ${chalk.hex('#ff2d55')('⚠')} MAC: ${chalk.hex('#ff2d55')(status.mac.vm)} detectable en red local.`);
  } else {
    console.log(`    MAC:        ${colors.dim('Limpia (interna)')}`);
  }
  console.log('');

  if (status.issues.length > 0) {
    console.log(`  ${chalk.hex('#ff9f1c').bold('Hallazgos:')}`);
    for (const issue of status.issues) {
      console.log(`    ${chalk.hex('#ff9f1c')('·')} ${issue}`);
    }
    console.log('');
  }

  console.log(`  ${divider(52)}`);
  console.log(t.option('[p]', 'Configurar Proxy / SOCKS5'));
  console.log(t.option('[t]', status.tor.active ? 'DETENER Tor Stealth Bridge' : 'ACTIVAR Tor Stealth Bridge'));
  if (status.tor.active) {
    console.log(t.option('[n]', 'Nueva Identidad Tor (Rotar IP)'));
  }
  console.log(t.option('[u]', 'Cambiar User-Agent'));
  console.log(t.option('[s]', `Modo Stealth ${config.stealthMode ? chalk.hex('#00f5a0')('[ON]') : colors.dim('[OFF]')}`));
  console.log(t.option('[b]', 'Establecer esta IP como "Base" (Home)'));
  console.log(t.option('[i]', 'Glosario de Capas (Info)'));
  console.log(t.option('[q]', 'Volver'));
  console.log('');

  const ans = await ask(colors.accent2('  ▸ ') + colors.text('Opción: '));

  switch (ans.toLowerCase()) {
    case 'p': await configureProxy(); break;
    case 't': 
      if (status.tor.active) {
        torManager.stop();
      } else {
        process.stdout.write(`  ${chalk.hex('#ae63e4')('◌')} Lanzando Tor Stealth Bridge…\r`);
        await torManager.start();
        process.stdout.write('\r\x1b[2K');
      }
      break;
    case 'n':
      if (status.tor.active) {
        process.stdout.write(`  ${chalk.hex('#ae63e4')('◌')} Rotando IP de salida…\r`);
        await torManager.renewIdentity();
        process.stdout.write('\r\x1b[2K');
      }
      break;
    case 'u': await configureUA(); break;
    case 's': 
      config.stealthMode = !config.stealthMode;
      saveToEnv('FRACTIA_STEALTH', config.stealthMode);
      break;
    case 'b':
      const currentIP = await getPublicIP('');
      if (currentIP) {
        config.baseIP = currentIP;
        saveToEnv('FRACTIA_BASE_IP', currentIP);
        console.log(`\n  ${chalk.hex('#00f5a0')('✓')} IP Base establecida: ${currentIP}`);
        await new Promise(r => setTimeout(r, 1500));
      }
      break;
    case 'i': await showOpSecGlossary(); break;
    case 'q': return;
    default: break;
  }
  
  return runOpSecFlow();
}

async function configureProxy() {
  console.log('\n  Introduce la URL del proxy (ej: http://1.2.3.4:8080 o socks5://host:port)');
  console.log('  Deja en blanco para desactivar.');
  const url = await ask(colors.accent2('  ▸ ') + colors.text('Proxy URL: '));
  config.proxy = url;
  saveToEnv('FRACTIA_PROXY', url);
  console.log(`\n  ${chalk.hex('#34d399')('✓')} Proxy configurado.`);
  await new Promise(r => setTimeout(r, 1000));
}

async function configureUA() {
  console.log('\n  Selecciona o introduce un User-Agent:');
  console.log(t.option('[1]', 'Chrome (Windows)  - Standard'));
  console.log(t.option('[2]', 'Safari (iPhone)   - Mobile'));
  console.log(t.option('[3]', 'Custom            - Escribir manualmente'));
  
  const choice = await ask(colors.accent2('  ▸ ') + colors.text('Opción: '));
  let ua = '';
  if (choice === '1') ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
  else if (choice === '2') ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';
  else if (choice === '3') ua = await ask(colors.accent2('  ▸ ') + colors.text('User-Agent: '));
  
  if (ua) {
    config.userAgent = ua;
    saveToEnv('FRACTIA_USER_AGENT', ua);
    console.log(`\n  ${chalk.hex('#34d399')('✓')} User-Agent actualizado.`);
    await new Promise(r => setTimeout(r, 1000));
  }
}

async function showOpSecGlossary() {
  clearScreen();
  console.log('');
  console.log(box(chalk.bold('OpSec — Lo que ven de ti'), { color: '#00b4d8' }));
  console.log('');
  console.log(`  ${chalk.bold('Capa 1 — IP Pública')}`);
  console.log(`  Es tu dirección en Internet. El target solo ve esto.`);
  console.log('');
  console.log(`  ${chalk.bold('Capa 2 — Fingerprinting (TTL)')}`);
  console.log(`  Linux/macOS usan TTL 64. Windows usa TTL 128.`);
  console.log(`  Analizando paquetes, saben qué sistema operativo usas.`);
  console.log('');
  console.log(`  ${chalk.bold('Capa 3 — MAC Address')}`);
  console.log(`  Nunca sale de tu red local, pero revela si usas una VM`);
  console.log(`  (VirtualBox, VMware) a tu router o IDS locales.`);
  console.log('');
  console.log(`  ${chalk.bold('Capa 5 — User-Agent')}`);
  console.log(`  Es el header HTTP que más delata la herramienta usada`);
  console.log(`  (curl, nmap, sqlmap) si no se modifica.`);
  console.log('');
  await ask(colors.dim('  Presiona Enter para volver... '));
}
