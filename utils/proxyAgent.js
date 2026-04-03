import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { config } from '../config.js';

/**
 * Devuelve un agente de proxy (SOCKS o HTTP) basado en la configuración global.
 * Útil para integrar en SDKs como OpenAI, Anthropic o Peticiones nativas.
 */
export function getProxyAgent() {
  if (!config.proxy) return null;

  try {
    if (config.proxy.startsWith('socks')) {
      return new SocksProxyAgent(config.proxy);
    } else {
      return new HttpsProxyAgent(config.proxy);
    }
  } catch (err) {
    console.error(`[proxyAgent] Error creando agente para ${config.proxy}:`, err.message);
    return null;
  }
}
