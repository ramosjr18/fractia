import http from 'http';
import https from 'https';
import os from 'os';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { config } from '../config.js';

/**
 * Capa 1: Obtener IP Pública (con soporte opcional de proxy)
 */
export async function getPublicIP(proxyUrl = config.proxy) {
  const url = 'https://api.ipify.org?format=json';
  
  return new Promise((resolve) => {
    try {
      const options = {
        timeout: 5000,
        headers: { 'User-Agent': config.userAgent }
      };

      if (proxyUrl) {
        if (proxyUrl.startsWith('socks')) {
          options.agent = new SocksProxyAgent(proxyUrl);
        } else {
          options.agent = new HttpsProxyAgent(proxyUrl);
        }
      }

      const req = https.get(url, options, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            const json = JSON.parse(data);
            resolve(json.ip);
          } catch {
            resolve(null);
          }
        });
      });

      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
    } catch {
      resolve(null);
    }
  });
}

/**
 * Capa 2: Fingerprint del Sistema (TTL + OS)
 */
export function getFingerprint() {
  const platform = os.platform(); // 'darwin', 'linux', 'win32'
  let ttl = 64;
  let osName = 'Linux / macOS';

  if (platform === 'win32') {
    ttl = 128;
    osName = 'Windows';
  } else if (platform === 'darwin') {
    osName = 'macOS';
  }

  return {
    os: osName,
    ttl,
    platform,
    arch: os.arch(),
    hostname: os.hostname(),
  };
}

/**
 * Capa 3: MAC Address Prefix (Local only)
 * Detecta si estamos en una VM conocida.
 */
export function getMACStatus() {
  const interfaces = os.networkInterfaces();
  const vms = {
    '00:0C:29': 'VMware',
    '00:50:56': 'VMware',
    '08:00:27': 'VirtualBox',
    '00:1C:42': 'Parallels'
  };

  for (const name of Object.keys(interfaces)) {
    for (const net of interfaces[name]) {
      if (net.mac && net.mac !== '00:00:00:00:00:00') {
        const prefix = net.mac.toUpperCase().slice(0, 8);
        if (vms[prefix]) {
          return { mac: net.mac, vm: vms[prefix], leaked: true };
        }
      }
    }
  }

  return { leaked: false };
}

/**
 * Capa 4 & 5: Analizar si las herramientas del sistema delatan el entorno.
 */
export function getToolingStatus() {
  return {
    userAgent: config.userAgent,
    stealthMode: config.stealthMode,
  };
}

/**
 * Check de anonimato completo
 */
export async function runOpSecCheck() {
  const ip = await getPublicIP();
  const fingerprint = getFingerprint();
  const mac = getMACStatus();
  
  let status = 'secure'; // secure | warning | leaked
  const issues = [];

  if (!ip) {
    status = 'warning';
    issues.push('No se pudo verificar la IP pública (posible bloqueo o red offline).');
  } else if (config.baseIP && ip === config.baseIP) {
    status = 'leaked';
    issues.push(`¡ALERTA DE FUGA! Tu IP pública real (${ip}) está expuesta.`);
  } else if (!config.proxy && config.stealthMode) {
    status = 'warning';
    issues.push('Modo Stealth activado pero no hay Proxy configurado.');
  }

  if (mac.leaked) {
    issues.push(`Entorno virtual detectado (${mac.vm}) via MAC address.`);
  }

  return {
    status,
    ip: ip || 'Desconocida',
    fingerprint,
    mac,
    issues,
    timestamp: new Date().toISOString()
  };
}
