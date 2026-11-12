'use strict';

const dns = require('node:dns');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const tls = require('node:tls');
const { URL } = require('node:url');

const config = require('./config');

/* ------------------------------------------------------------------ */
/* Utilities                                                          */
/* ------------------------------------------------------------------ */

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`${label} timed out after ${ms}ms`)),
      ms,
    );
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function f(label, value) {
  return `<b>${esc(label)}:</b> <code>${esc(value ?? 'N/A')}</code>`;
}

function isIpLiteral(host) {
  return net.isIP(host) !== 0;
}

function formatDn(obj) {
  if (!obj) return 'N/A';
  if (typeof obj === 'string') return obj;
  return Object.entries(obj)
    .map(([k, v]) => `${k}=${v}`)
    .join(', ');
}

function decodeEntities(text) {
  return text
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ');
}

/* ------------------------------------------------------------------ */
/* IP / CIDR validation                                               */
/* ------------------------------------------------------------------ */

function ipv4ToInt(ip) {
  return ip
    .split('.')
    .reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0)
    >>> 0;
}

function ipv4InCidr(ip, cidr) {
  const [network, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(network) & mask);
}

function ipv6ToBigInt(ip) {
  let address = ip.toLowerCase();

  const [head, tail] = address.includes('::')
    ? address.split('::')
    : [address, ''];

  const headParts = head ? head.split(':') : [];
  const tailParts = tail ? tail.split(':') : [];
  const missing = 8 - (headParts.length + tailParts.length);

  const parts = [
    ...headParts,
    ...Array(Math.max(0, missing)).fill('0'),
    ...tailParts,
  ];

  return parts.reduce(
    (acc, part) => (acc << 16n) + BigInt(parseInt(part || '0', 16)),
    0n,
  );
}

function ipv6InCidr(ip, cidr) {
  const [network, bitsRaw] = cidr.split('/');
  const prefix = BigInt(bitsRaw);
  const max = (1n << 128n) - 1n;
  const mask =
    prefix === 0n ? 0n : max ^ ((1n << (128n - prefix)) - 1n);
  return (ipv6ToBigInt(ip) & mask) === (ipv6ToBigInt(network) & mask);
}

function extractMappedIpv4(ip) {
  const lower = ip.toLowerCase();
  if (!lower.startsWith('::ffff:')) return null;
  const rest = lower.slice(7);

  if (net.isIPv4(rest)) return rest;

  const parts = rest.split(':');
  if (parts.length === 2) {
    const hi = parseInt(parts[0], 16);
    const lo = parseInt(parts[1], 16);
    if (!Number.isFinite(hi) || !Number.isFinite(lo)) return null;
    return `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
  }

  return null;
}

function isPublicIp(ip) {
  if (net.isIPv4(ip)) {
    return !config.ssrf.blockedIpv4Cidrs.some((cidr) =>
      ipv4InCidr(ip, cidr),
    );
  }

  if (net.isIPv6(ip)) {
    const mapped = extractMappedIpv4(ip);
    if (mapped) return isPublicIp(mapped);

    return !config.ssrf.blockedIpv6Cidrs.some((cidr) =>
      ipv6InCidr(ip, cidr),
    );
  }

  return false;
}

/* ------------------------------------------------------------------ */
/* URL validation                                                     */
/* ------------------------------------------------------------------ */

function validateUrl(input) {
  if (typeof input !== 'string') return { error: 'URL must be a string.' };

  let raw = input.trim();
  if (!raw) return { error: 'URL is empty.' };
  if (raw.length > config.limits.maxUrlLength) {
    return { error: 'URL is too long.' };
  }

  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    raw = 'https://' + raw;
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    return { error: 'Invalid URL format.' };
  }

  if (!['http:', 'https:'].includes(url.protocol)) {
    return { error: 'Only HTTP and HTTPS are supported.' };
  }

  if (url.username || url.password) {
    return { error: 'URLs with credentials are not allowed.' };
  }

  if (!url.hostname) {
    return { error: 'URL must include a hostname.' };
  }

  const port = url.port
    ? Number(url.port)
    : url.protocol === 'https:'
      ? 443
      : 80;

  if (![80, 443, 8080, 8443].includes(port)) {
    return {
      error:
        'Only ports 80, 443, 8080 and 8443 are allowed for website reconnaissance.',
    };
  }

  if (
    config.ssrf.blockedHostnames.includes(url.hostname.toLowerCase())
  ) {
    return { error: 'Target hostname is blocked.' };
  }

  return { url };
}

/* ------------------------------------------------------------------ */
/* DNS                                                                */
/* ------------------------------------------------------------------ */

async function resolveTarget(hostname) {
  const started = Date.now();

  const resolver = new dns.promises.Resolver({
    timeout: config.limits.dnsTimeoutMs,
    tries: 2,
  });

  const query = (promise, label) =>
    withTimeout(promise, config.limits.dnsTimeoutMs, label).catch(
      () => null,
    );

  const [a, aaaa, mx, ns, txt, cname] = await Promise.all([
    query(resolver.resolve4(hostname), 'A'),
    query(resolver.resolve6(hostname), 'AAAA'),
    query(resolver.resolveMx(hostname), 'MX'),
    query(resolver.resolveNs(hostname), 'NS'),
    query(resolver.resolveTxt(hostname), 'TXT'),
    query(resolver.resolveCname(hostname), 'CNAME'),
  ]);

  const dnsTimeMs = Date.now() - started;

  const addresses = [];
  (a || []).forEach((ip) => addresses.push({ address: ip, family: 4 }));
  (aaaa || []).forEach((ip) =>
    addresses.push({ address: ip, family: 6 }),
  );

  if (!addresses.length) {
    throw new Error(
      `DNS resolution failed: no A or AAAA records for ${hostname}`,
    );
  }

  const publicAddresses = addresses.filter((x) => isPublicIp(x.address));

  if (publicAddresses.length !== addresses.length) {
    throw new Error(
      'Target resolves to private, loopback, link-local, or blocked addresses.',
    );
  }

  if (!publicAddresses.length) {
    throw new Error('Target resolves only to blocked addresses.');
  }

  const primary =
    publicAddresses.find((x) => x.family === 4) || publicAddresses[0];

  return {
    hostname,
    addresses,
    publicAddresses,
    primary,
    dnsTimeMs,
    records: {
      a: a || [],
      aaaa: aaaa || [],
      mx: mx || [],
      ns: ns || [],
      txt: txt || [],
      cname: cname || [],
    },
  };
}

/* ------------------------------------------------------------------ */
/* HTTP                                                               */
/* ------------------------------------------------------------------ */

function makePinnedLookup(address) {
  return (_hostname, options, callback) => {
    if (typeof options === 'function') {
      callback = options;
      options = {};
    }

    const family = address.family === 6 ? 6 : 4;

    if (options && options.all) {
      callback(null, [{ address: address.address, family }]);
      return;
    }

    callback(null, address.address, family);
  };
}

function httpRequest(urlObj, address) {
  return new Promise((resolve) => {
    const isHttps = urlObj.protocol === 'https:';
    const mod = isHttps ? https : http;
    const port = urlObj.port
      ? Number(urlObj.port)
      : isHttps
        ? 443
        : 80;

    const started = Date.now();
    let settled = false;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const requestOptions = {
      hostname: urlObj.hostname,
      port,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'User-Agent': config.http.userAgent,
        Accept: config.http.accept,
        'Accept-Language': config.http.acceptLanguage,
        Connection: 'close',
      },
      lookup: makePinnedLookup(address),
      timeout: config.limits.requestTimeoutMs,
      rejectUnauthorized: false,
      agent: false,
    };

    if (!isIpLiteral(urlObj.hostname)) {
      requestOptions.servername = urlObj.hostname;
    }

    const req = mod.request(requestOptions, (res) => {
      const chunks = [];
      let size = 0;
      let truncated = false;

      res.on('data', (chunk) => {
        size += chunk.length;

        if (size <= config.limits.maxResponseBytes) {
          chunks.push(chunk);
          return;
        }

        truncated = true;
        res.destroy();

        finish({
          statusCode: res.statusCode,
          statusMessage: res.statusMessage,
          httpVersion: res.httpVersion,
          headers: res.headers,
          rawHeaders: res.rawHeaders,
          body: Buffer.concat(chunks).toString('utf8'),
          truncated: true,
          responseTimeMs: Date.now() - started,
          remoteAddress: res.socket && res.socket.remoteAddress,
        });
      });

      res.on('end', () => {
        finish({
          statusCode: res.statusCode,
          statusMessage: res.statusMessage,
          httpVersion: res.httpVersion,
          headers: res.headers,
          rawHeaders: res.rawHeaders,
          body: Buffer.concat(chunks).toString('utf8'),
          truncated,
          responseTimeMs: Date.now() - started,
          remoteAddress: res.socket && res.socket.remoteAddress,
        });
      });

      res.on('error', (err) => {
        finish({
          error: err.message,
          responseTimeMs: Date.now() - started,
        });
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error('Request timed out'));
    });

    req.on('error', (err) => {
      finish({
        error: err.message,
        responseTimeMs: Date.now() - started,
      });
    });

    req.end();
  });
}

function probeHttp10(hostname, address, port, isHttps) {
  return new Promise((resolve) => {
    const started = Date.now();
    let settled = false;
    let socket;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      try {
        if (socket) socket.destroy();
      } catch {
        /* ignore */
      }
      resolve(result);
    };

    const connectOptions = {
      host: address,
      port,
      timeout: config.limits.requestTimeoutMs,
    };

    if (isHttps) {
      connectOptions.rejectUnauthorized = false;
      connectOptions.ALPNProtocols = ['http/1.1'];
      if (!isIpLiteral(hostname)) {
        connectOptions.servername = hostname;
      }
      socket = tls.connect(connectOptions, onConnect);
    } else {
      socket = net.connect(connectOptions, onConnect);
    }

    function onConnect() {
      const request =
        `GET / HTTP/1.0\r\n` +
        `Host: ${hostname}\r\n` +
        `User-Agent: ${config.http.userAgent}\r\n` +
        `Accept: */*\r\n` +
        `Connection: close\r\n\r\n`;

      socket.write(request);

      let data = '';

      socket.on('data', (chunk) => {
        data += chunk.toString('utf8');
        const firstLine = data.split('\r\n')[0];
        if (!firstLine) return;

        const match = firstLine.match(/^HTTP\/(\d\.\d)\s+(\d{3})/);

        if (match) {
          finish({
            supported: true,
            httpVersion: match[1],
            statusCode: Number(match[2]),
            responseTimeMs: Date.now() - started,
          });
        }
      });

      socket.on('end', () => {
        if (!settled) {
          finish({
            supported: false,
            error: 'No valid HTTP response',
          });
        }
      });

      socket.on('timeout', () => {
        finish({ supported: false, error: 'Timeout' });
      });

      socket.on('error', (err) => {
        finish({ supported: false, error: err.message });
      });
    }

    socket.once('error', (err) => {
      finish({ supported: false, error: err.message });
    });

    socket.once('timeout', () => {
      finish({ supported: false, error: 'Timeout' });
    });
  });
}

/* ------------------------------------------------------------------ */
/* TLS                                                                */
/* ------------------------------------------------------------------ */

function inspectTls(hostname, address, port) {
  return new Promise((resolve) => {
    let settled = false;
    let socket;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      try {
        if (socket) socket.destroy();
      } catch {
        /* ignore */
      }
      resolve(result);
    };

    const connectOptions = {
      host: address,
      port,
      rejectUnauthorized: false,
      ALPNProtocols: ['h2', 'http/1.1'],
      timeout: config.limits.tlsTimeoutMs,
    };

    if (!isIpLiteral(hostname)) {
      connectOptions.servername = hostname;
    }

    socket = tls.connect(connectOptions, () => {
      const cert = socket.getPeerX509Certificate();
      const detailed = socket.getPeerCertificate(true);

      const chain = [];
      const seen = new Set();
      let current = detailed;

      while (
        current &&
        current.subject &&
        chain.length < 10
      ) {
        const fp = current.fingerprint256 || current.fingerprint;
        if (fp && seen.has(fp)) break;
        if (fp) seen.add(fp);

        chain.push({
          subject: formatDn(current.subject),
          issuer: formatDn(current.issuer),
        });

        current = current.issuerCertificate;
      }

      let hostnameMatch = null;
      if (cert) {
        try {
          hostnameMatch = cert.checkHost(hostname) || false;
        } catch {
          hostnameMatch = false;
        }
      }

      let daysRemaining = null;
      if (cert && cert.validTo) {
        const validTo = new Date(cert.validTo);
        if (!Number.isNaN(validTo.getTime())) {
          daysRemaining = Math.ceil(
            (validTo.getTime() - Date.now()) / 86400000,
          );
        }
      }

      const issues = [];

      if (!cert) {
        issues.push('No peer certificate was returned.');
      } else {
        if (
          daysRemaining !== null &&
          daysRemaining < 0
        ) {
          issues.push('Certificate has expired.');
        } else if (
          daysRemaining !== null &&
          daysRemaining < 30
        ) {
          issues.push(
            `Certificate expires in ${daysRemaining} days.`,
          );
        }

        if (socket.authorized === false) {
          issues.push(
            `Certificate is not trusted: ${
              socket.authorizationError || 'unknown reason'
            }.`,
          );
        }

        if (hostnameMatch === false) {
          issues.push(
            'Certificate does not match the target hostname.',
          );
        }

        if (chain.length <= 1) {
          issues.push(
            'Certificate chain appears incomplete or self-signed.',
          );
        }
      }

      finish({
        protocol: socket.getProtocol(),
        alpnProtocol: socket.alpnProtocol,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError || null,
        cipher: socket.getCipher(),
        certificate: cert
          ? {
              subject: formatDn(cert.subject),
              issuer: formatDn(cert.issuer),
              validFrom: cert.validFrom,
              validTo: cert.validTo,
              serialNumber: cert.serialNumber,
              fingerprint256: cert.fingerprint256,
              subjectAltName: cert.subjectAltName,
            }
          : null,
        daysRemaining,
        hostnameMatch,
        chainLength: chain.length,
        issues,
      });
    });

    socket.once('error', (err) => {
      finish({ error: err.message });
    });

    socket.once('timeout', () => {
      finish({ error: 'TLS connection timed out' });
    });
  });
}

/* ------------------------------------------------------------------ */
/* HTML parsing                                                       */
/* ------------------------------------------------------------------ */

function extractHtmlInfo(body) {
  const safeBody = body.slice(0, 1024 * 1024);

  const titleMatch = safeBody.match(
    /<title[^>]*>([\s\S]*?)<\/title>/i,
  );

  const title = titleMatch
    ? decodeEntities(
        titleMatch[1].replace(/\s+/g, ' ').trim(),
      ).slice(0, 200)
    : null;

  const meta = {};
  const metaRegex = /<meta\s+([^>]+?)\/?>/gi;
  let match;

  while ((match = metaRegex.exec(safeBody)) !== null) {
    const attrs = match[1];
    const nameMatch = attrs.match(
      /(?:name|property)\s*=\s*["']([^"']+)["']/i,
    );
    const contentMatch = attrs.match(
      /content\s*=\s*["']([^"']*)["']/i,
    );

    if (nameMatch && contentMatch) {
      const key = nameMatch[1].toLowerCase();
      if (!meta[key]) {
        meta[key] = contentMatch[1].slice(0, 500);
      }
    }
  }

  const scripts = [];
  const scriptRegex =
    /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;

  while (
    (match = scriptRegex.exec(safeBody)) !== null &&
    scripts.length < 100
  ) {
    scripts.push(match[1].slice(0, 500));
  }

  const links = [];
  const linkRegex = /<link[^>]+href\s*=\s*["']([^"']+)["']/gi;

  while (
    (match = linkRegex.exec(safeBody)) !== null &&
    links.length < 100
  ) {
    links.push(match[1].slice(0, 500));
  }

  return { title, meta, scripts, links };
}

function parseCookies(headers) {
  const raw = headers['set-cookie'];
  const list = Array.isArray(raw) ? raw : raw ? [raw] : [];

  return list.map((item) => {
    const pair = item.split(';')[0];
    const index = pair.indexOf('=');
    if (index === -1) return { name: pair.trim(), value: '', raw: item };
    return {
      name: pair.slice(0, index).trim(),
      value: pair.slice(index + 1).trim(),
      raw: item,
    };
  });
}

/* ------------------------------------------------------------------ */
/* Technology detection                                               */
/* ------------------------------------------------------------------ */

const TECH_SIGNATURES = [
  {
    name: 'PHP',
    category: 'Backend',
    test: ({ headers, cookies, html }) => {
      const evidence = [];
      const powered = (headers['x-powered-by'] || '').toLowerCase();
      if (powered.includes('php')) {
        evidence.push('X-Powered-By header contains PHP');
      }
      if (cookies.some((c) => c.name.toUpperCase() === 'PHPSESSID')) {
        evidence.push('PHPSESSID cookie');
      }
      if (/\.php(?:[?"'#]|$)/i.test(html)) {
        evidence.push('.php URL pattern in HTML');
      }
      return evidence;
    },
  },
  {
    name: 'Node.js',
    category: 'Backend',
    test: ({ headers }) => {
      const evidence = [];
      const powered = (headers['x-powered-by'] || '').toLowerCase();
      const server = (headers.server || '').toLowerCase();
      if (powered.includes('node') || server.includes('node')) {
        evidence.push('Header contains Node.js');
      }
      if (powered.includes('express')) {
        evidence.push('Express.js implies Node.js runtime');
      }
      return evidence;
    },
  },
  {
    name: 'Express.js',
    category: 'Backend',
    test: ({ headers }) => {
      const powered = (headers['x-powered-by'] || '').toLowerCase();
      return powered.includes('express')
        ? ['X-Powered-By: Express']
        : [];
    },
  },
  {
    name: 'Python',
    category: 'Backend',
    test: ({ headers }) => {
      const evidence = [];
      const server = (headers.server || '').toLowerCase();
      const powered = (headers['x-powered-by'] || '').toLowerCase();
      if (server.includes('gunicorn')) evidence.push('Server: Gunicorn');
      if (server.includes('uwsgi')) evidence.push('Server: uWSGI');
      if (powered.includes('python')) {
        evidence.push('X-Powered-By contains Python');
      }
      if (powered.includes('flask')) {
        evidence.push('X-Powered-By: Flask');
      }
      if (powered.includes('django')) {
        evidence.push('X-Powered-By: Django');
      }
      return evidence;
    },
  },
  {
    name: 'Laravel',
    category: 'Backend',
    test: ({ cookies, html }) => {
      const evidence = [];
      if (cookies.some((c) => c.name === 'laravel_session')) {
        evidence.push('laravel_session cookie');
      }
      if (/laravel/i.test(html)) {
        evidence.push('Laravel reference in HTML');
      }
      return evidence;
    },
  },
  {
    name: 'Django',
    category: 'Backend',
    test: ({ cookies, html }) => {
      const evidence = [];
      if (cookies.some((c) => c.name === 'csrftoken')) {
        evidence.push('csrftoken cookie');
      }
      if (/csrfmiddlewaretoken/i.test(html)) {
        evidence.push('csrfmiddlewaretoken in HTML');
      }
      return evidence;
    },
  },
  {
    name: 'WordPress',
    category: 'CMS',
    test: ({ html, meta, links, scripts }) => {
      const evidence = [];
      if (/wp-content|wp-includes|wp-json/i.test(html)) {
        evidence.push('wp-content / wp-includes / wp-json references');
      }
      if ((meta.generator || '').toLowerCase().includes('wordpress')) {
        evidence.push('Generator meta tag: WordPress');
      }
      if (
        links.some((l) => /wp-content|wp-includes/i.test(l))
      ) {
        evidence.push('WordPress asset links');
      }
      if (
        scripts.some((s) => /wp-includes/i.test(s))
      ) {
        evidence.push('WordPress script references');
      }
      return evidence;
    },
  },
  {
    name: 'Joomla',
    category: 'CMS',
    test: ({ html, meta }) => {
      const evidence = [];
      if (/\/components\/com_/i.test(html)) {
        evidence.push('/components/com_ URL pattern');
      }
      if ((meta.generator || '').toLowerCase().includes('joomla')) {
        evidence.push('Generator meta tag: Joomla');
      }
      return evidence;
    },
  },
  {
    name: 'Drupal',
    category: 'CMS',
    test: ({ html, meta }) => {
      const evidence = [];
      if (
        /Drupal\.settings|drupalSettings|\/sites\/default\/files/i.test(
          html,
        )
      ) {
        evidence.push('Drupal-specific HTML/JS patterns');
      }
      if ((meta.generator || '').toLowerCase().includes('drupal')) {
        evidence.push('Generator meta tag: Drupal');
      }
      return evidence;
    },
  },
  {
    name: 'React',
    category: 'Frontend',
    test: ({ html, scripts }) => {
      const evidence = [];
      if (
        /data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__|react-dom/i.test(
          html,
        )
      ) {
        evidence.push('React markers in HTML');
      }
      if (
        scripts.some((s) =>
          /react(?:\.min)?\.js|react-dom/i.test(s),
        )
      ) {
        evidence.push('React script references');
      }
      return evidence;
    },
  },
  {
    name: 'Next.js',
    category: 'Frontend',
    test: ({ html, scripts, headers }) => {
      const evidence = [];
      if (/__NEXT_DATA__|_next\//i.test(html)) {
        evidence.push('__NEXT_DATA__ / _next/ markers');
      }
      if (scripts.some((s) => /_next\//i.test(s))) {
        evidence.push('Next.js script references');
      }
      if (
        (headers['x-powered-by'] || '')
          .toLowerCase()
          .includes('next.js')
      ) {
        evidence.push('X-Powered-By: Next.js');
      }
      return evidence;
    },
  },
  {
    name: 'Vue.js',
    category: 'Frontend',
    test: ({ html, scripts }) => {
      const evidence = [];
      if (
        /data-v-[a-f0-9]|vue\.js|vue\.min\.js|Vue\.config/i.test(
          html,
        )
      ) {
        evidence.push('Vue.js markers in HTML');
      }
      if (scripts.some((s) => /vue(?:\.min)?\.js/i.test(s))) {
        evidence.push('Vue.js script references');
      }
      return evidence;
    },
  },
  {
    name: 'Angular',
    category: 'Frontend',
    test: ({ html, scripts }) => {
      const evidence = [];
      if (/ng-version|ng-app|angular\.min\.js/i.test(html)) {
        evidence.push('Angular markers in HTML');
      }
      if (
        scripts.some((s) => /angular(?:\.min)?\.js/i.test(s))
      ) {
        evidence.push('Angular script references');
      }
      return evidence;
    },
  },
  {
    name: 'Nuxt.js',
    category: 'Frontend',
    test: ({ html, scripts }) => {
      const evidence = [];
      if (/__NUXT__|_nuxt\//i.test(html)) {
        evidence.push('__NUXT__ / _nuxt/ markers');
      }
      if (scripts.some((s) => /_nuxt\//i.test(s))) {
        evidence.push('Nuxt.js script references');
      }
      return evidence;
    },
  },
  {
    name: 'Bootstrap',
    category: 'Frontend',
    test: ({ html, links, scripts }) => {
      const evidence = [];
      if (/bootstrap(?:\.min)?\.(?:css|js)/i.test(html)) {
        evidence.push('Bootstrap asset references');
      }
      if (
        links.some((l) =>
          /bootstrap(?:\.min)?\.css/i.test(l),
        )
      ) {
        evidence.push('Bootstrap CSS link');
      }
      if (
        scripts.some((s) =>
          /bootstrap(?:\.min)?\.js/i.test(s),
        )
      ) {
        evidence.push('Bootstrap JS script');
      }
      return evidence;
    },
  },
  {
    name: 'Tailwind CSS',
    category: 'Frontend',
    test: ({ html, links }) => {
      const evidence = [];
      if (/tailwind/i.test(html)) {
        evidence.push('Tailwind reference in HTML');
      }
      if (links.some((l) => /tailwind/i.test(l))) {
        evidence.push('Tailwind CSS link');
      }
      if (/--tw-/i.test(html)) {
        evidence.push('Tailwind CSS custom properties');
      }
      return evidence;
    },
  },
  {
    name: 'jQuery',
    category: 'Frontend',
    test: ({ html, scripts }) => {
      const evidence = [];
      if (/jquery(?:\.min)?\.js|window\.jQuery|jQuery\(/i.test(html)) {
        evidence.push('jQuery markers in HTML');
      }
      if (scripts.some((s) => /jquery/i.test(s))) {
        evidence.push('jQuery script references');
      }
      return evidence;
    },
  },
];

function detectTechnologies(headers, cookies, html, scripts, links, meta) {
  const context = { headers, cookies, html, scripts, links, meta };
  const detected = [];

  for (const signature of TECH_SIGNATURES) {
    let evidence = [];
    try {
      evidence = signature.test(context) || [];
    } catch {
      evidence = [];
    }

    if (evidence.length) {
      detected.push({
        name: signature.name,
        category: signature.category,
        evidence: [...new Set(evidence)].slice(0, 3),
      });
    }
  }

  return detected;
}

/* ------------------------------------------------------------------ */
/* CDN / WAF detection                                                */
/* ------------------------------------------------------------------ */

function detectCdnWaf(headers, cookies, html) {
  const h = (name) => headers[name.toLowerCase()];
  const cookieNames = new Set(
    cookies.map((c) => c.name.toLowerCase()),
  );

  const cdn = [];
  const waf = [];

  const add = (arr, name, evidence) => {
    const existing = arr.find((x) => x.name === name);
    if (existing) {
      for (const item of evidence) {
        if (
          !existing.evidence.includes(item) &&
          existing.evidence.length < 3
        ) {
          existing.evidence.push(item);
        }
      }
      return;
    }
    arr.push({
      name,
      evidence: [...new Set(evidence)].slice(0, 3),
    });
  };

  const cloudflare = [];
  if (h('cf-ray')) cloudflare.push('CF-RAY header');
  if ((h('server') || '').toLowerCase().includes('cloudflare')) {
    cloudflare.push('Server: cloudflare');
  }
  if (cookieNames.has('__cfduid')) cloudflare.push('__cfduid cookie');
  if (cookieNames.has('cf_clearance')) {
    cloudflare.push('cf_clearance cookie');
  }
  if (cloudflare.length) add(cdn, 'Cloudflare', cloudflare);

  if (
    h('cf-mitigated') ||
    (h('cf-ray') &&
      html &&
      /cf-challenge|challenge-platform/i.test(html))
  ) {
    add(waf, 'Cloudflare WAF', [
      'Challenge page or CF-Mitigated header',
    ]);
  }

  const cloudfront = [];
  if (h('x-amz-cf-id')) cloudfront.push('X-Amz-Cf-Id header');
  if (h('x-amz-cf-pop')) cloudfront.push('X-Amz-Cf-Pop header');
  if ((h('via') || '').toLowerCase().includes('cloudfront')) {
    cloudfront.push('Via header contains CloudFront');
  }
  if (cloudfront.length) add(cdn, 'AWS CloudFront', cloudfront);

  const fastly = [];
  if (h('x-fastly-request-id')) {
    fastly.push('X-Fastly-Request-ID header');
  }
  if ((h('x-served-by') || '').toLowerCase().includes('fastly')) {
    fastly.push('X-Served-By contains Fastly');
  }
  if ((h('via') || '').toLowerCase().includes('fastly')) {
    fastly.push('Via header contains Fastly');
  }
  if (fastly.length) add(cdn, 'Fastly', fastly);

  const akamai = [];
  if (h('x-akamai-transformed')) {
    akamai.push('X-Akamai-Transformed header');
  }
  if (h('akamai-grn')) akamai.push('Akamai-GRN header');
  if ((h('server') || '').toLowerCase().includes('akamaighost')) {
    akamai.push('Server: AkamaiGHost');
  }
  if (akamai.length) add(cdn, 'Akamai', akamai);

  const imperva = [];
  if ((h('x-cdn') || '').toLowerCase().includes('imperva')) {
    imperva.push('X-CDN: Imperva');
  }
  if (h('x-iinfo')) imperva.push('X-Iinfo header');
  if (cookieNames.has('incap_ses')) imperva.push('incap_ses cookie');
  if (cookieNames.has('visid_incap')) {
    imperva.push('visid_incap cookie');
  }
  if (imperva.length) {
    add(cdn, 'Imperva', imperva);
    add(waf, 'Imperva WAF', imperva);
  }

  const sucuri = [];
  if (h('x-sucuri-id')) sucuri.push('X-Sucuri-ID header');
  if (h('x-sucuri-cache')) sucuri.push('X-Sucuri-Cache header');
  if ((h('server') || '').toLowerCase().includes('sucuri')) {
    sucuri.push('Server: Sucuri');
  }
  if (sucuri.length) {
    add(cdn, 'Sucuri', sucuri);
    add(waf, 'Sucuri WAF', sucuri);
  }

  if (h('x-vercel-id')) {
    add(cdn, 'Vercel Edge Network', ['X-Vercel-Id header']);
  }
  if (h('x-nf-request-id')) {
    add(cdn, 'Netlify CDN', ['X-Nf-Request-Id header']);
  }
  if (h('x-azure-ref')) {
    add(cdn, 'Azure Front Door', ['X-Azure-Ref header']);
  }

  if (h('x-amzn-waf-action')) {
    add(waf, 'AWS WAF', ['X-Amzn-Waf-Action header']);
  }
  if (h('x-wa-info')) {
    add(waf, 'F5 Advanced WAF', ['X-Wa-Info header']);
  }
  if (cookieNames.has('barra_counter_session')) {
    add(waf, 'Barracuda WAF', ['barra_counter_session cookie']);
  }
  if ((h('server') || '').toLowerCase().includes('modsecurity')) {
    add(waf, 'ModSecurity', ['Server: ModSecurity']);
  }

  return { cdn, waf };
}

/* ------------------------------------------------------------------ */
/* Security headers                                                   */
/* ------------------------------------------------------------------ */

const SECURITY_HEADER_DEFS = [
  {
    key: 'strict-transport-security',
    label: 'Strict-Transport-Security',
    impact:
      'Enforces HTTPS and mitigates protocol downgrade and cookie-hijacking attacks.',
  },
  {
    key: 'content-security-policy',
    label: 'Content-Security-Policy',
    impact:
      'Restricts sources of executable content and mitigates XSS and data injection.',
  },
  {
    key: 'x-frame-options',
    label: 'X-Frame-Options',
    impact:
      'Mitigates clickjacking by controlling whether the page can be framed.',
  },
  {
    key: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    impact:
      'Prevents MIME-type sniffing, reducing drive-by download and content-confusion risks.',
  },
  {
    key: 'referrer-policy',
    label: 'Referrer-Policy',
    impact:
      'Controls how much referrer information is sent to other origins.',
  },
  {
    key: 'permissions-policy',
    label: 'Permissions-Policy',
    impact:
      'Restricts access to browser features such as camera, microphone, and geolocation.',
  },
  {
    key: 'cross-origin-opener-policy',
    label: 'Cross-Origin-Opener-Policy',
    impact:
      'Isolates browsing contexts and mitigates cross-window attacks.',
  },
  {
    key: 'cross-origin-resource-policy',
    label: 'Cross-Origin-Resource-Policy',
    impact:
      'Controls which origins may load the resource cross-origin.',
  },
  {
    key: 'cross-origin-embedder-policy',
    label: 'Cross-Origin-Embedder-Policy',
    impact:
      'Controls embedding of cross-origin resources and enables cross-origin isolation.',
  },
];

function analyzeSecurityHeaders(headers) {
  return SECURITY_HEADER_DEFS.map((def) => ({
    ...def,
    present: Boolean(headers[def.key]),
    value: headers[def.key] || null,
  }));
}

/* ------------------------------------------------------------------ */
/* DDoS defensive analysis                                            */
/* ------------------------------------------------------------------ */

function analyzeDdosProtection({
  headers,
  cdnWaf,
  finalResponse,
  http10Probe,
  securityHeaders,
  requestError,
}) {
  const layer34 = { confirmed: [], potential: [], unknown: [] };
  const layer7 = { confirmed: [], potential: [], unknown: [] };
  const additional = { confirmed: [], potential: [], unknown: [] };

  const cdnNames = cdnWaf.cdn.map((x) => x.name);
  const wafNames = cdnWaf.waf.map((x) => x.name);

  if (cdnNames.length) {
    layer34.confirmed.push(
      `CDN edge detected: ${cdnNames.join(', ')}. This indicates traffic absorption at the network edge, but specific L3/L4 flood protections are not externally verifiable.`,
    );
  } else {
    layer34.unknown.push(
      'No CDN detected. Network-level DDoS protection (SYN flood, UDP flood, network filtering) cannot be verified externally.',
    );
  }

  const rateLimitHeaders = Object.keys(headers).filter((name) =>
    /^x-ratelimit-|^ratelimit-|^retry-after$/i.test(name),
  );

  if (rateLimitHeaders.length) {
    layer7.confirmed.push(
      `Rate-limit headers observed: ${rateLimitHeaders.join(', ')}.`,
    );
  } else {
    layer7.unknown.push(
      'No rate-limit headers observed. Rate limiting configuration is unknown.',
    );
  }

  if (finalResponse && finalResponse.statusCode === 429) {
    layer7.confirmed.push(
      'HTTP 429 Too Many Requests returned for a single low-volume request, indicating active rate limiting.',
    );
  }

  if (headers['retry-after']) {
    layer7.confirmed.push(
      `Retry-After header present: ${headers['retry-after']}.`,
    );
  }

  if (wafNames.length) {
    layer7.confirmed.push(`WAF detected: ${wafNames.join(', ')}.`);
  } else {
    layer7.unknown.push(
      'No WAF detected. Application-layer filtering cannot be verified externally.',
    );
  }

  if (requestError && /timed?\s?out/i.test(requestError)) {
    layer7.potential.push(
      'Request timeout observed. This may indicate request timeout enforcement, but could also be network latency.',
    );
  }

  if (http10Probe && http10Probe.supported) {
    additional.confirmed.push(
      'The server accepted a low-volume HTTP/1.0 probe request.',
    );
  } else {
    additional.unknown.push(
      'HTTP/1.0 behavior could not be confirmed, so legacy protocol handling remains unverified.',
    );
  }

  const presentHeaders = securityHeaders.filter((h) => h.present);
  const missingHeaders = securityHeaders.filter((h) => !h.present);

  if (presentHeaders.length) {
    additional.confirmed.push(
      `Security headers present: ${presentHeaders.map((h) => h.label).join(', ')}.`,
    );
  }

  if (missingHeaders.length) {
    additional.potential.push(
      `Missing security headers: ${missingHeaders.map((h) => h.label).join(', ')}.`,
    );
  }

  additional.unknown.push(
    'Slowloris and resource-exhaustion configurations cannot be verified externally without intrusive testing.',
  );
  additional.unknown.push(
    'Request size restrictions and connection-timeout tuning cannot be verified without sending large or slow requests.',
  );

  return { layer34, layer7, additional };
}

/* ------------------------------------------------------------------ */
/* Main scan                                                          */
/* ------------------------------------------------------------------ */

async function scanWebsite(input, options = {}) {
  const {
    isCancelled = () => false,
    onProgress = async () => {},
  } = options;

  const progress = async (message) => {
    if (isCancelled()) throw new Error('Scan cancelled by user.');
    await onProgress(message);
  };

  await progress('🕷 Validating target...');

  const validation = validateUrl(input);
  if (validation.error) throw new Error(validation.error);

  const startUrl = validation.url;
  const hostname = startUrl.hostname;

  await progress(`🌐 Resolving DNS for ${hostname}...`);

  const resolution = await resolveTarget(hostname);

  await progress('🔐 Inspecting TLS configuration...');

  let tlsInfo = null;

  if (startUrl.protocol === 'https:') {
    tlsInfo = await inspectTls(
      hostname,
      resolution.primary.address,
      startUrl.port ? Number(startUrl.port) : 443,
    );
  }

  await progress(
    '📡 Fetching HTTP response and following redirects...',
  );

  const redirectChain = [];

  let currentUrl = startUrl;
  let currentResolution = resolution;

  let finalResponse = null;
  let finalUrl = startUrl;
  let finalResolution = resolution;

  for (let i = 0; i <= config.limits.maxRedirects; i += 1) {
    if (isCancelled()) throw new Error('Scan cancelled by user.');

    const response = await httpRequest(
      currentUrl,
      currentResolution.primary,
    );

    if (response.error) throw new Error(response.error);

    const isRedirect =
      [301, 302, 303, 307, 308].includes(response.statusCode) &&
      response.headers.location;

    if (isRedirect) {
      let nextUrl;
      try {
        nextUrl = new URL(response.headers.location, currentUrl);
      } catch {
        throw new Error('Invalid redirect location.');
      }

      const nextValidation = validateUrl(nextUrl.href);
      if (nextValidation.error) {
        throw new Error(`Redirect blocked: ${nextValidation.error}`);
      }

      redirectChain.push({
        from: currentUrl.href,
        to: nextUrl.href,
        status: response.statusCode,
      });

      currentUrl = nextValidation.url;

      if (i === config.limits.maxRedirects) {
        throw new Error('Too many redirects.');
      }

      if (currentUrl.hostname !== currentResolution.hostname) {
        currentResolution = await resolveTarget(currentUrl.hostname);
      }

      continue;
    }

    finalResponse = response;
    finalUrl = currentUrl;
    finalResolution = currentResolution;
    break;
  }

  if (!finalResponse) {
    throw new Error('No final HTTP response received.');
  }

  if (
    startUrl.protocol !== 'https:' &&
    finalUrl.protocol === 'https:' &&
    !tlsInfo
  ) {
    tlsInfo = await inspectTls(
      finalUrl.hostname,
      finalResolution.primary.address,
      finalUrl.port ? Number(finalUrl.port) : 443,
    );
  }

  await progress('🧪 Probing HTTP/1.0 support...');

  const http10Probe = await probeHttp10(
    finalUrl.hostname,
    finalResolution.primary.address,
    finalUrl.port
      ? Number(finalUrl.port)
      : finalUrl.protocol === 'https:'
        ? 443
        : 80,
    finalUrl.protocol === 'https:',
  );

  await progress(
    '⚙️ Analyzing technologies and protection mechanisms...',
  );

  const headers = finalResponse.headers || {};
  const cookies = parseCookies(headers);
  const html = finalResponse.body || '';
  const htmlInfo = extractHtmlInfo(html);

  const technologies = detectTechnologies(
    headers,
    cookies,
    html,
    htmlInfo.scripts,
    htmlInfo.links,
    htmlInfo.meta,
  );

  const cdnWaf = detectCdnWaf(headers, cookies, html);
  const securityHeaders = analyzeSecurityHeaders(headers);

  const ddos = analyzeDdosProtection({
    headers,
    cdnWaf,
    finalResponse,
    http10Probe,
    securityHeaders,
    requestError: null,
  });

  return {
    input,
    url: startUrl.href,
    finalUrl: finalUrl.href,
    hostname: finalUrl.hostname,
    protocol: finalUrl.protocol,
    availability: true,
    statusCode: finalResponse.statusCode,
    statusMessage: finalResponse.statusMessage,
    redirectChain,
    responseTimeMs: finalResponse.responseTimeMs,
    headers,
    rawHeaders: finalResponse.rawHeaders,
    title: htmlInfo.title,
    meta: htmlInfo.meta,
    dns: resolution,
    tls: tlsInfo,
    http10Probe,
    technologies,
    cdnWaf,
    securityHeaders,
    ddos,
    httpVersion: finalResponse.httpVersion,
    truncated: finalResponse.truncated,
    error: null,
  };
}

/* ------------------------------------------------------------------ */
/* Report                                                             */
/* ------------------------------------------------------------------ */

function detectReverseProxy(headers) {
  const indicators = [];

  if (headers.via) indicators.push(`Via: ${headers.via}`);
  if (headers['x-forwarded-for']) {
    indicators.push('X-Forwarded-For present');
  }
  if (headers['x-real-ip']) {
    indicators.push('X-Real-IP present');
  }
  if (headers['x-forwarded-proto']) {
    indicators.push('X-Forwarded-Proto present');
  }
  if (headers.forwarded) {
    indicators.push('Forwarded header present');
  }
  if (
    headers.server &&
    /nginx|apache|litespeed|openresty|caddy|iis/i.test(
      headers.server,
    )
  ) {
    indicators.push(`Server: ${headers.server}`);
  }

  return indicators.length
    ? `Detected (${indicators.join('; ')})`
    : 'No reverse-proxy indicators observed';
}

function buildReport(scan, mode = 'full', lang = 'en') {
  const lines = [];
  const sep = '━━━━━━━━━━━━━━━━━━';

  const push = (...items) => lines.push(...items);
  const blank = () => push('');

  push(`🕷 <b>${config.brand.name}</b>`);
  if (lang === 'fa') {
    push('🇮🇷 گزارش فنی به زبان انگلیسی ارائه شده است.');
  }
  push(sep);

  /* TARGET ---------------------------------------------------------- */

  if (
    mode === 'full' ||
    mode === 'network' ||
    mode === 'server' ||
    mode === 'security'
  ) {
    push('🌐 <b>TARGET INFORMATION</b>');
    blank();

    push(f('Input', scan.input));
    push(f('Final URL', scan.finalUrl));
    push(f('Domain', scan.hostname));
    push(
      f(
        'Protocol',
        scan.protocol.replace(':', '').toUpperCase(),
      ),
    );
    push(
      f(
        'Status',
        `${scan.statusCode} ${scan.statusMessage || ''}`.trim(),
      ),
    );
    push(
      f(
        'Availability',
        scan.availability ? 'Reachable' : 'Unreachable',
      ),
    );
    push(f('Response Time', `${scan.responseTimeMs}ms`));

    if (scan.title) push(f('Page Title', scan.title));

    if (scan.redirectChain.length) {
      push('<b>Redirect Chain:</b>');
      scan.redirectChain.forEach((item, index) => {
        push(
          `  ${index + 1}. ${esc(item.from)} → ${esc(item.to)} (HTTP ${item.status})`,
        );
      });
    } else {
      push(f('Redirect Chain', 'None'));
    }

    if (scan.truncated) {
      push(
        f(
          'Note',
          'Response body was truncated at the configured size limit.',
        ),
      );
    }

    push(sep);
  }

  /* NETWORK --------------------------------------------------------- */

  if (
    mode === 'full' ||
    mode === 'network' ||
    mode === 'server'
  ) {
    push('🌐 <b>NETWORK INFORMATION</b>');
    blank();

    const dns = scan.dns;

    push(
      f(
        'IPv4',
        dns.records.a.length
          ? dns.records.a.join(', ')
          : 'Not detected',
      ),
    );
    push(
      f(
        'IPv6',
        dns.records.aaaa.length
          ? dns.records.aaaa.join(', ')
          : 'Not detected',
      ),
    );
    push(f('DNS Resolution', `${dns.dnsTimeMs}ms`));
    push(
      f(
        'DNS A',
        dns.records.a.length ? dns.records.a.join(', ') : 'None',
      ),
    );
    push(
      f(
        'DNS AAAA',
        dns.records.aaaa.length
          ? dns.records.aaaa.join(', ')
          : 'None',
      ),
    );
    push(
      f(
        'DNS MX',
        dns.records.mx.length
          ? dns.records.mx
              .map((m) => `${m.exchange} (${m.priority})`)
              .join(', ')
          : 'None',
      ),
    );
    push(
      f(
        'DNS NS',
        dns.records.ns.length
          ? dns.records.ns.join(', ')
          : 'None',
      ),
    );
    push(
      f(
        'DNS TXT',
        dns.records.txt.length
          ? dns.records.txt
              .map((t) => t.join(' '))
              .join(' | ')
          : 'None',
      ),
    );
    push(
      f(
        'DNS CNAME',
        dns.records.cname.length
          ? dns.records.cname.join(', ')
          : 'None',
      ),
    );

    blank();
    push('<b>HTTP Protocol Support:</b>');
    push(
      `  HTTP/1.0: ${
        scan.http10Probe.supported
          ? 'Supported (probe response)'
          : 'Unverified'
      }`,
    );
    push(
      `  HTTP/1.1: ${
        scan.httpVersion === '1.1' ||
        scan.http10Probe.httpVersion === '1.1'
          ? 'Supported'
          : 'Unverified'
      }`,
    );
    push(
      `  HTTP/2: ${
        scan.tls && scan.tls.alpnProtocol === 'h2'
          ? 'Supported (ALPN h2)'
          : 'Not detected'
      }`,
    );
    push(
      `  HTTP/3: ${
        scan.headers['alt-svc'] &&
        /h3/i.test(scan.headers['alt-svc'])
          ? 'Advertised via Alt-Svc (h3)'
          : 'Not detected'
      }`,
    );

    push(sep);
  }

  /* TLS ------------------------------------------------------------- */

  if (mode === 'full' || mode === 'security') {
    push('🔐 <b>SSL/TLS</b>');
    blank();

    if (scan.tls && !scan.tls.error) {
      const cert = scan.tls.certificate;

      push(
        f(
          'Certificate',
          cert
            ? scan.tls.authorized
              ? 'Valid and trusted'
              : `Present but not trusted (${scan.tls.authorizationError || 'unknown error'})`
            : 'Not available',
        ),
      );
      push(f('Issuer', cert ? cert.issuer : 'N/A'));
      push(f('Subject', cert ? cert.subject : 'N/A'));
      push(f('Expiration', cert ? cert.validTo : 'N/A'));
      push(
        f(
          'Days Remaining',
          scan.tls.daysRemaining !== null
            ? `${scan.tls.daysRemaining} days`
            : 'N/A',
        ),
      );
      push(f('TLS Version', scan.tls.protocol || 'Unknown'));
      push(
        f(
          'ALPN Protocol',
          scan.tls.alpnProtocol || 'None',
        ),
      );
      push(
        f(
          'Cipher',
          scan.tls.cipher
            ? `${scan.tls.cipher.name} (${scan.tls.cipher.version})`
            : 'Unknown',
        ),
      );
      push(
        f(
          'Hostname Match',
          scan.tls.hostnameMatch
            ? `Matched: ${scan.tls.hostnameMatch}`
            : 'No match or not verifiable',
        ),
      );
      push(
        f(
          'Certificate Chain',
          scan.tls.chainLength
            ? `${scan.tls.chainLength} certificate(s)`
            : 'Not available',
        ),
      );

      if (scan.tls.issues.length) {
        push('<b>TLS Issues:</b>');
        scan.tls.issues.forEach((issue) => {
          push(`  • ${esc(issue)}`);
        });
      }
    } else if (scan.tls && scan.tls.error) {
      push(
        f('TLS Inspection', `Failed: ${scan.tls.error}`),
      );
    } else {
      push(
        f('TLS Inspection', 'Not applicable (HTTP target)'),
      );
    }

    push(sep);
  }

  /* SERVER ---------------------------------------------------------- */

  if (mode === 'full' || mode === 'server') {
    push('🖥 <b>SERVER INFORMATION</b>');
    blank();

    push(f('Web Server', scan.headers.server || 'Not disclosed'));
    push(f('Reverse Proxy', detectReverseProxy(scan.headers)));

    push(
      f(
        'CDN',
        scan.cdnWaf.cdn.length
          ? scan.cdnWaf.cdn.map((x) => x.name).join(', ')
          : 'Not detected',
      ),
    );
    push(
      f(
        'WAF',
        scan.cdnWaf.waf.length
          ? scan.cdnWaf.waf.map((x) => x.name).join(', ')
          : 'Not detected',
      ),
    );

    push(sep);
  }

  /* TECHNOLOGIES ---------------------------------------------------- */

  if (mode === 'full' || mode === 'server') {
    push('⚙️ <b>TECHNOLOGIES</b>');
    blank();

    if (scan.technologies.length) {
      const byCategory = {};

      for (const tech of scan.technologies) {
        if (!byCategory[tech.category]) {
          byCategory[tech.category] = [];
        }
        byCategory[tech.category].push(tech);
      }

      for (const [category, items] of Object.entries(byCategory)) {
        push(`<b>${esc(category)}:</b>`);
        for (const tech of items) {
          push(
            `  • <b>${esc(tech.name)}</b> — ${esc(
              tech.evidence.join('; '),
            )}`,
          );
        }
      }
    } else {
      push(
        'No technologies detected from publicly observable HTML, headers, or cookies.',
      );
    }

    push(sep);
  }

  /* SECURITY / DDOS ------------------------------------------------- */

  if (mode === 'full' || mode === 'security') {
    push('🛡 <b>PROTECTION ANALYSIS</b>');
    blank();

    push(
      f(
        'CDN Protection',
        scan.cdnWaf.cdn.length ? 'Detected' : 'Not detected',
      ),
    );
    push(
      f(
        'WAF',
        scan.cdnWaf.waf.length ? 'Detected' : 'Not detected',
      ),
    );
    push(
      f(
        'Rate Limiting',
        scan.ddos.layer7.confirmed.some((x) =>
          /rate/i.test(x),
        )
          ? 'Confirmed indicators'
          : 'Not verified',
      ),
    );

    const present = scan.securityHeaders.filter((h) => h.present);
    const missing = scan.securityHeaders.filter((h) => !h.present);

    push(
      f(
        'Security Headers',
        present.length === 0
          ? 'None observed'
          : `${present.length} present, ${missing.length} missing`,
      ),
    );

    push(sep);

    push('⚠️ <b>DDOS SECURITY ANALYSIS</b>');
    blank();

    push('<b>Layer 3/4:</b>');
    for (const item of scan.ddos.layer34.confirmed) {
      push(`  ✅ ${esc(item)}`);
    }
    for (const item of scan.ddos.layer34.potential) {
      push(`  ⚠️ ${esc(item)}`);
    }
    for (const item of scan.ddos.layer34.unknown) {
      push(`  ❓ ${esc(item)}`);
    }

    blank();
    push('<b>Layer 7:</b>');
    for (const item of scan.ddos.layer7.confirmed) {
      push(`  ✅ ${esc(item)}`);
    }
    for (const item of scan.ddos.layer7.potential) {
      push(`  ⚠️ ${esc(item)}`);
    }
    for (const item of scan.ddos.layer7.unknown) {
      push(`  ❓ ${esc(item)}`);
    }

    blank();
    push('<b>Additional Checks:</b>');
    for (const item of scan.ddos.additional.confirmed) {
      push(`  ✅ ${esc(item)}`);
    }
    for (const item of scan.ddos.additional.potential) {
      push(`  ⚠️ ${esc(item)}`);
    }
    for (const item of scan.ddos.additional.unknown) {
      push(`  ❓ ${esc(item)}`);
    }

    push(sep);

    push('🔎 <b>SECURITY HEADERS DETAIL</b>');
    blank();

    for (const header of scan.securityHeaders) {
      push(
        `${header.present ? '✅' : '❌'} <b>${esc(
          header.label,
        )}</b> — ${header.present ? 'Present' : 'Missing'}`,
      );
      push(`   ${esc(header.impact)}`);
    }

    push(sep);

    push('📋 <b>POTENTIAL SECURITY FINDINGS</b>');
    blank();

    const findings = [];

    if (!scan.finalUrl.startsWith('https://')) {
      findings.push(
        'The final URL uses HTTP, not HTTPS. Traffic may be transmitted without transport encryption.',
      );
    }

    if (
      scan.tls &&
      scan.tls.certificate &&
      !scan.tls.authorized
    ) {
      findings.push(
        `The TLS certificate is not trusted: ${
          scan.tls.authorizationError || 'unknown reason'
        }.`,
      );
    }

    if (
      scan.tls &&
      scan.tls.daysRemaining !== null &&
      scan.tls.daysRemaining < 0
    ) {
      findings.push('The TLS certificate has expired.');
    } else if (
      scan.tls &&
      scan.tls.daysRemaining !== null &&
      scan.tls.daysRemaining < 30
    ) {
      findings.push(
        `The TLS certificate expires in ${scan.tls.daysRemaining} days.`,
      );
    }

    if (scan.tls && scan.tls.hostnameMatch === false) {
      findings.push(
        'The TLS certificate does not match the target hostname.',
      );
    }

    if (!scan.cdnWaf.cdn.length) {
      findings.push(
        'No CDN detected; network-level DDoS absorption cannot be verified externally.',
      );
    }

    if (!scan.cdnWaf.waf.length) {
      findings.push(
        'No WAF detected; application-layer filtering cannot be verified externally.',
      );
    }

    if (
      !scan.ddos.layer7.confirmed.some((x) =>
        /rate/i.test(x),
      )
    ) {
      findings.push(
        'Rate limiting configuration is not confirmed by response headers or status codes.',
      );
    }

    for (const header of scan.securityHeaders.filter(
      (h) => !h.present,
    )) {
      findings.push(
        `Missing security header: ${header.label}. ${header.impact}`,
      );
    }

    if (scan.headers['x-powered-by']) {
      findings.push(
        `Technology disclosure via X-Powered-By: ${scan.headers['x-powered-by']}.`,
      );
    }

    if (
      scan.headers.server &&
      /\d+\.\d+/.test(scan.headers.server)
    ) {
      findings.push(
        `Server version disclosed in Server header: ${scan.headers.server}.`,
      );
    }

    if (scan.truncated) {
      findings.push(
        'The response body exceeded the configured limit and was truncated; analysis may be incomplete.',
      );
    }

    if (scan.http10Probe && !scan.http10Probe.supported) {
      findings.push(
        `HTTP/1.0 probe did not receive a valid response (${
          scan.http10Probe.error || 'unknown'
        }).`,
      );
    }

    if (!findings.length) {
      findings.push(
        'No potential security findings were identified from passively observable data.',
      );
    }

    findings.forEach((finding) => {
      push(`  • ${esc(finding)}`);
    });

    push(sep);
  }

  push('🕷 <b>SPIDER WEB ANALYZER</b>');
  push(config.brand.company);

  return lines.join('\n');
}

module.exports = {
  validateUrl,
  scanWebsite,
  buildReport,
  isPublicIp,
  esc,
};