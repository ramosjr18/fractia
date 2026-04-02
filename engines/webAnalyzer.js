/**
 * Web Analyzer Engine
 * Identifica el stack tecnológico de un sitio web.
 */
import http from 'http';
import https from 'https';
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
  const timeout = opts.timeout || 10000;
  const urlObj = new URL(target);
  const baseUrl = `${urlObj.protocol}//${urlObj.hostname}${urlObj.port ? ':' + urlObj.port : ''}`;

  hooks.onPhase?.('fetching', `Extrayendo contenido de ${target}...`);

  // Fetch main page, robots.txt and sitemap.xml in parallel
  const [pageRes, robotsRes, sitemapRes] = await Promise.all([
    fetchFull(target, timeout),
    fetchFull(`${baseUrl}/robots.txt`, timeout),
    fetchFull(`${baseUrl}/sitemap.xml`, timeout),
  ]);

  if (pageRes.status === 0) {
    throw new Error('No se pudo conectar con el objetivo principal.');
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
  return new Promise(resolve => {
    try {
      const parsed = new URL(url);
      const mod = parsed.protocol === 'https:' ? https : http;
      const options = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        },
        rejectUnauthorized: false,
        timeout,
      };

      const req = mod.request(options, res => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
      });

      req.on('error', () => resolve({ status: 0, headers: {}, body: '' }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {}, body: '' }); });
      req.end();
    } catch {
      resolve({ status: 0, headers: {}, body: '' });
    }
  });
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
