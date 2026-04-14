import { spawn, execSync } from 'child_process';
import os from 'os';
import fs from 'fs';
import net from 'net';
import { config } from '../config.js';

/**
 * TorManager: Gestiona el ciclo de vida del proceso Tor (The Onion Router)
 * Proporciona anonimato mediante un bridge SOCKS5 local.
 */
class TorManager {
  constructor() {
    this.torProcess = null;
    this.socksPort = 9050; // Puerto SOCKS5 por defecto
    this.controlPort = 9051; // Puerto de control para rotar IPs
    this.isDocker = fs.existsSync('/.dockerenv');
    this.rotationInterval = null;
  }

  /**
   * Verifica si Tor está instalado en el sistema.
   * Si no, intenta instalarlo automáticamente según el OS.
   */
  async ensureInstalled() {
    try {
      execSync('tor --version', { stdio: 'ignore' });
      return true;
    } catch (e) {
      console.log('[-] Tor no detectado. Intentando instalación automática...');
      return await this.autoInstall();
    }
  }

  /**
   * Instalación automática (brew en macOS, apt-get en Linux/Docker)
   */
  async autoInstall() {
    try {
      if (this.isDocker) {
        console.log('[*] Entorno Docker detectado. Usando apt-get...');
        execSync('apt-get update && apt-get install -y tor', { stdio: 'inherit' });
      } else if (os.platform() === 'darwin') {
        console.log('[*] macOS detectado. Usando Homebrew...');
        execSync('brew install tor', { stdio: 'inherit' });
      } else {
        throw new Error('OS no soportado para auto-instalación. Instale Tor manualmente.');
      }
      return true;
    } catch (error) {
      console.error(`[!] Error en auto-instalación: ${error.message}`);
      return false;
    }
  }

  /**
   * Inicia el proceso de Tor en segundo plano.
   */
  async start() {
    if (this.torProcess) return true;

    const isInstalled = await this.ensureInstalled();
    if (!isInstalled) return false;

    console.log(`[*] Iniciando Tor Stealth Bridge en puerto ${this.socksPort}...`);

    // Iniciamos tor con ControlPort habilitado para rotar identidades
    this.torProcess = spawn('tor', [
      '--SocksPort', `0.0.0.0:${this.socksPort}`,
      '--ControlPort', `0.0.0.0:${this.controlPort}`,
      '--DataDirectory', '/tmp/tor_data_fractia',
      '--CookieAuthentication', '0',
      '--Log', 'notice stdout'
    ]);

    this.torProcess.stdout.on('data', (data) => {
      if (data.toString().includes('100% (done)')) {
        console.log('[+] Tor Bridge establecido correctamente.');
        config.proxy = `socks5h://127.0.0.1:${this.socksPort}`;
      }
    });

    this.torProcess.on('exit', () => this.stop());

    this.torProcess.stderr.on('data', (data) => {
      // Ignorar ruidos de advertencia de Tor si no son críticos
      if (data.toString().includes('[ERR]')) {
         console.error(`[Tor Error] ${data}`);
      }
    });

    // Pequeño delay para asegurar que el socket abra
    await new Promise(resolve => setTimeout(resolve, 3000));
    return true;
  }

  /**
   * Detiene el proceso Tor.
   */
  stop() {
    if (this.torProcess) {
      this.stopAutoRotate();
      this.torProcess.kill('SIGINT');
      this.torProcess = null;
      config.proxy = '';
      console.log('[*] Tor Stealth Bridge detenido.');
    }
  }

  /**
   * Inicia la rotación automática de IP.
   */
  startAutoRotate(intervalMinutes = 5) {
    this.stopAutoRotate();
    console.log(`[*] Iniciando rotación automática cada ${intervalMinutes} minutos...`);
    this.rotationInterval = setInterval(() => {
      this.renewIdentity();
    }, intervalMinutes * 60000);
  }

  /**
   * Detiene la rotación automática.
   */
  stopAutoRotate() {
    if (this.rotationInterval) {
      clearInterval(this.rotationInterval);
      this.rotationInterval = null;
    }
  }

  /**
   * Solicita una nueva identidad (Nueva IP de salida).
   * Envía la señal NEWNYM al ControlPort.
   */
  async renewIdentity() {
    console.log('[*] Solicitando nueva identidad a Tor (Rotando IP)...');
    try {
      return new Promise((resolve, reject) => {
        const client = net.createConnection({ port: this.controlPort }, () => {
          client.write('AUTHENTICATE ""\r\n');
          client.write('SIGNAL NEWNYM\r\n');
          client.write('QUIT\r\n');
        });

        client.on('data', (data) => {
          if (data.toString().includes('250')) {
            // 250 es el código de éxito de Tor Control
            resolve(true);
          }
        });

        client.on('error', (err) => {
          reject(err);
        });

        setTimeout(() => {
          console.log('[+] Identidad rotada con éxito.');
          resolve(true);
        }, 1000);
      });
    } catch (e) {
      console.error(`[!] Error al rotar identidad: ${e.message}`);
      return false;
    }
  }

  getStatus() {
    return {
      active: !!this.torProcess,
      port: this.socksPort,
      controlPort: this.controlPort
    };
  }
}

const torManager = new TorManager();
export default torManager;
