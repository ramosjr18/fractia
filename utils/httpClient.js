import http from 'http';
import https from 'https';
import { URL } from 'url';
import { config } from '../config.js';
import { getProxyAgent } from './proxyAgent.js';

/**
 * HttpClient centralizado para Fractia.
 * Gestiona automáticamente:
 * - Proxy SOCKS5/HTTP desde config.proxy
 * - User-Agent de la configuración
 * - Timeouts y manejo de errores
 */
export async function request(url, options = {}) {
  const parsedUrl = new URL(url);
  const isHttps = parsedUrl.protocol === 'https:';
  const protocol = isHttps ? https : http;

  const defaultHeaders = {
    'User-Agent': config.userAgent,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  };

  const requestOptions = {
    method: options.method || 'GET',
    hostname: parsedUrl.hostname,
    port: parsedUrl.port || (isHttps ? 443 : 80),
    path: parsedUrl.pathname + parsedUrl.search,
    headers: { ...defaultHeaders, ...(options.headers || {}) },
    timeout: options.timeout || (config.proxy ? 60000 : 15000),
    rejectUnauthorized: false, // Útil para entornos de prueba / Sandbox
  };

  const agent = getProxyAgent();
  if (agent) {
    requestOptions.agent = agent;
  }

  return new Promise((resolve, reject) => {
    const req = protocol.request(requestOptions, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Timeout tras ${requestOptions.timeout}ms`));
    });

    if (options.body) {
      req.write(options.body);
    }
    
    req.end();
  });
}

export const httpClient = {
  get: (url, options = {}) => request(url, { ...options, method: 'GET' }),
  post: (url, body, options = {}) => request(url, { ...options, method: 'POST', body }),
};
