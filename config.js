'use strict';

const fs = require('node:fs');
const path = require('node:path');

const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  try {
    process.loadEnvFile(envPath);
  } catch (err) {
    console.warn('Could not load .env:', err.message);
  }
}

const ADMIN_IDS = (process.env.ADMIN_IDS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
  .map(Number)
  .filter((n) => Number.isFinite(n));

module.exports = {
  bot: {
    token: process.env.BOT_TOKEN || '',
    admins: ADMIN_IDS,
  },

  brand: {
    name: 'SPIDER WEB ANALYZER',
    company: 'SPIDER SECURITY TOOLS',
    spider: '🕷',
  },

  limits: {
    requestTimeoutMs: 15000,
    dnsTimeoutMs: 5000,
    tlsTimeoutMs: 10000,
    maxResponseBytes: 512 * 1024,
    maxRedirects: 5,
    maxConcurrentGlobal: 4,
    maxScansPerUserPerWindow: 5,
    userWindowMs: 60 * 1000,
    maxUrlLength: 2048,
    progressEditIntervalMs: 1500,
  },

  http: {
    userAgent:
      'Mozilla/5.0 (compatible; SpiderWebAnalyzer/1.0; +https://example.invalid/bot)',
    accept:
      'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    acceptLanguage: 'en-US,en;q=0.9',
  },

  ssrf: {
    blockedHostnames: [
      'localhost',
      'metadata.google.internal',
      'metadata',
      'instance-data',
    ],

    blockedIpv4Cidrs: [
      '0.0.0.0/8',
      '10.0.0.0/8',
      '100.64.0.0/10',
      '127.0.0.0/8',
      '169.254.0.0/16',
      '172.16.0.0/12',
      '192.0.0.0/24',
      '192.0.2.0/24',
      '192.168.0.0/16',
      '198.18.0.0/15',
      '198.51.100.0/24',
      '203.0.113.0/24',
      '224.0.0.0/4',
      '240.0.0.0/4',
      '255.255.255.255/32',
    ],

    blockedIpv6Cidrs: [
      '::/128',
      '::1/128',
      '::ffff:0:0/96',
      '64:ff9b::/96',
      '100::/64',
      '2001:db8::/32',
      'fc00::/7',
      'fe80::/10',
      'ff00::/8',
    ],
  },
};