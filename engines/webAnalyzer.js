/**
 * Web Analyzer Engine
 * Identifica el stack tecnológico de un sitio web.
 */
import { config } from '../config.js';
import { httpClient } from '../utils/httpClient.js';
import { URL } from 'url';

export const meta = {
  id: 'web-analyzer',
  name: 'Web Analyzer',
  description: 'Identifica CMS, Frameworks, Librerías UI y Analíticas',
};

// ── Technology Fingerprints ──────────────────────────────────────────────────
const FINGERPRINTS = [
  // CMS
  { 
    name: 'WordPress',      
    cat: 'cms',       
    pattern: /wp-content|wp-includes/i,         
    src: 'html',
    versionPatterns: [
      { regex: /<meta\s+name=["']generator["']\s+content=["']WordPress\s+([0-9.]+)/i, group: 1 },
      { regex: /[?&]ver=([0-9.]+(?:\-[a-z0-9]+)?)/i, group: 1 }
    ]
  },
  { 
    name: 'Ghost',          
    cat: 'cms',       
    pattern: /ghost-sdk/i,                       
    src: 'html',
    versionPatterns: [
      { regex: /<meta\s+name=["']generator["']\s+content=["']Ghost\s+([0-9.]+)/i, group: 1 }
    ]
  },
  { 
    name: 'Joomla',         
    cat: 'cms',       
    pattern: /joomla/i,                          
    src: 'meta',
    versionPatterns: [
      { regex: /<meta\s+name=["']generator["']\s+content=["']Joomla!\s+-\s+Open\s+Source\s+Content\s+Management\s+-\s+([0-9.]+)/i, group: 1 }
    ]
  },
  { name: 'Drupal',         cat: 'cms',       pattern: /Drupal/i,                          src: 'meta' },
  { name: 'Hugo',           cat: 'cms',       pattern: /Hugo/i,                            src: 'meta' },
  { name: 'Wix',            cat: 'cms',       pattern: /wix\.com/i,                        src: 'html' },
  { name: 'Shopify',        cat: 'cms',       pattern: /shopify/i,                         src: 'html' },

  // Frontend Frameworks
  { name: 'Next.js',        cat: 'framework', pattern: /_next\/static/i,                   src: 'html' },
  { name: 'React',          cat: 'framework', pattern: /react|react-dom/i,                 src: 'html' },
  { name: 'Vue.js',         cat: 'framework', pattern: /vue/i,                             src: 'html' },
  { name: 'Angular',        cat: 'framework', pattern: /ng-version|angular/i,              src: 'html' },
  { name: 'Nuxt.js',        cat: 'framework', pattern: /__NUXT__/i,                        src: 'html' },
  { name: 'Svelte',         cat: 'framework', pattern: /svelte/i,                          src: 'html' },

  // UI Libraries
  { name: 'Tailwind CSS',   cat: 'ui',        pattern: /tailwind/i,                        src: 'html' },
  { name: 'Bootstrap',      cat: 'ui',        pattern: /bootstrap/i,                       src: 'html' },
  { name: 'Material UI',    cat: 'ui',        pattern: /Mui|material-ui/i,                 src: 'html' },
  { name: 'Bulma',          cat: 'ui',        pattern: /bulma/i,                           src: 'html' },
  { name: 'Font Awesome',   cat: 'ui',        pattern: /font-awesome|fa-/i,                src: 'html' },

  // Analytics & Marketing
  { name: 'Google Analytics', cat: 'analytics', pattern: /googletagmanager|ga\.js|gtag/i, src: 'html' },
  { name: 'Meta Pixel',       cat: 'analytics', pattern: /fbevents\.js/i,                  src: 'html' },
  { name: 'Hotjar',           cat: 'analytics', pattern: /hotjar/i,                         src: 'html' },
  { name: 'HubSpot',          cat: 'analytics', pattern: /js\.hs-scripts\.com/i,           src: 'html' },

  // Infrastructure & CDN
  { name: 'Cloudflare',     cat: 'infra',     pattern: /cloudflare/i,                      src: 'header', key: 'server' },
  { name: 'Vercel',         cat: 'infra',     pattern: /vercel/i,                          src: 'header', key: 'server' },
  { name: 'Netlify',        cat: 'infra',     pattern: /netlify/i,                         src: 'header', key: 'server' },
  { name: 'Nginx',          cat: 'infra',     pattern: /nginx/i,                           src: 'header', key: 'server' },
  { name: 'Apache',         cat: 'infra',     pattern: /apache/i,                          src: 'header', key: 'server' },

  // Security
  { name: 'Incapsula',      cat: 'security',  pattern: /incapsula/i,                       src: 'header', key: 'x-cdn' },
  { name: 'Akamai',         cat: 'security',  pattern: /akamai/i,                          src: 'header', key: 'server' },
];

// ── Main Runner ──────────────────────────────────────────────────────────────
export async function run({ target, opts = {}, hooks = {} }) {
  // Debug config and options
  // console.log(`[DEBUG] config.proxy: ${config.proxy}`);
  // Use a longer timeout if a proxy is active, as Tor can be slow
  const defaultTimeout = config.proxy ? 60000 : 15000;
  const timeout = opts.timeout || defaultTimeout;
  
  const urlObj = new URL(target);
  const baseUrl = `${urlObj.protocol}//${urlObj.hostname}${urlObj.port ? ':' + urlObj.port : ''}`;

  hooks.onPhase?.('fetching', `Extrayendo contenido de ${target}...`);

  // Fetch main page, robots.txt and sitemap.xml in parallel
  let pageRes, robotsRes, sitemapRes;
  try {
    [pageRes, robotsRes, sitemapRes] = await Promise.all([
      httpClient.get(target, { timeout }),
      httpClient.get(`${baseUrl}/robots.txt`, { timeout }).catch(() => ({ status: 0, body: '' })),
      httpClient.get(`${baseUrl}/sitemap.xml`, { timeout }).catch(() => ({ status: 0, body: '' })),
    ]);
  } catch (err) {
    throw new Error(`Error de conexión: ${err.message}`);
  }

  if (!pageRes || pageRes.status === 0) {
    throw new Error('No se pudo conectar con el objetivo principal (status 0).');
  }

  if (pageRes.status >= 400 && pageRes.status !== 403) {
    throw new Error(`El servidor respondió con un error HTTP ${pageRes.status}`);
  }

  hooks.onPhase?.('analyzing', 'Analizando tecnologías y activos...');

  const { body, headers } = pageRes;
  const detected = [];
  const metaTags = extractMeta(body);

  for (const fp of FINGERPRINTS) {
    let match = false;
    let version = null;

    if (fp.src === 'html' && fp.pattern.test(body)) {
      match = true;
    } else if (fp.src === 'header' && headers[fp.key] && fp.pattern.test(headers[fp.key])) {
      match = true;
    } else if (fp.src === 'meta' && metaTags.some(m => fp.pattern.test(m.content) || fp.pattern.test(m.name))) {
      match = true;
    }

    if (match) {
      // Try version detection
      if (fp.versionPatterns) {
        for (const vp of fp.versionPatterns) {
          const vMatch = vp.regex.exec(body);
          if (vMatch && vMatch[vp.group]) {
            version = vMatch[vp.group];
            break;
          }
        }
      }
      detected.push({ name: fp.name, category: fp.cat, version });
    }
  }

  // Recon Assets analysis
  const reconAssets = {
    robots: {
      found: robotsRes.status === 200,
      size: robotsRes.body.length,
      sitemaps: (robotsRes.body.match(/Sitemap:\s*(.+)/gi) || []).map(s => s.replace(/Sitemap:\s*/i, '').trim()),
      disallowCount: (robotsRes.body.match(/Disallow:\s*(.+)/gi) || []).length,
    },
    sitemap: {
      found: sitemapRes.status === 200,
      size: sitemapRes.body.length,
      isIndex: sitemapRes.body.includes('<sitemapindex'),
    }
  };

  // Group by category, including version if present
  const grouped = detected.reduce((acc, curr) => {
    if (!acc[curr.category]) acc[curr.category] = [];
    const entry = curr.version ? `${curr.name} (${curr.version})` : curr.name;
    if (!acc[curr.category].includes(entry)) {
      acc[curr.category].push(entry);
    }
    return acc;
  }, {});

  return {
    target,
    status: pageRes.status,
    timestamp: new Date().toISOString(),
    technologies: grouped,
    reconAssets,
    raw: {
      headers,
      metaCount: metaTags.length,
      bodySize: body.length,
    }
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function fetchFull(url, timeout) {
  return httpClient.get(url, { timeout }).catch(() => ({ status: 0, headers: {}, body: '' }));
}

function extractMeta(html) {
  const metaTags = [];
  const metaRegex = /<meta\s+([^>]+)>/gi;
  let match;
  while ((match = metaRegex.exec(html)) !== null) {
    const content = match[1];
    const nameMatch = /name=["']([^"']+)["']/i.exec(content);
    const contentMatch = /content=["']([^"']+)["']/i.exec(content);
    if (nameMatch || contentMatch) {
      metaTags.push({
        name: nameMatch ? nameMatch[1] : '',
        content: contentMatch ? contentMatch[1] : '',
      });
    }
  }
  return metaTags;
}
