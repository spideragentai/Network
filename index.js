'use strict';

const { Telegraf, Markup } = require('telegraf');

const config = require('./config');
const {
  validateUrl,
  scanWebsite,
  buildReport,
  esc,
} = require('./scanner');

/* ------------------------------------------------------------------ */
/* Startup guard                                                      */
/* ------------------------------------------------------------------ */

if (!config.bot.token) {
  console.error(
    'BOT_TOKEN is not set. Create a .env file or export BOT_TOKEN before starting.',
  );
  process.exit(1);
}

const bot = new Telegraf(config.bot.token);

/* ------------------------------------------------------------------ */
/* State                                                              */
/* ------------------------------------------------------------------ */

const sessions = new Map();
const activeScans = new Set();
let totalScans = 0;

function createSemaphore(max) {
  let active = 0;
  const queue = [];

  return {
    acquire(timeoutMs = 30000) {
      return new Promise((resolve, reject) => {
        if (active < max) {
          active += 1;
          resolve();
          return;
        }

        let settled = false;

        const timer = setTimeout(() => {
          if (settled) return;
          settled = true;
          const index = queue.indexOf(onReady);
          if (index !== -1) queue.splice(index, 1);
          reject(
            new Error(
              'Server is busy. Please try again in a few seconds.',
            ),
          );
        }, timeoutMs);

        function onReady() {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          active += 1;
          resolve();
        }

        queue.push(onReady);
      });
    },

    release() {
      active -= 1;
      if (queue.length) {
        const next = queue.shift();
        next();
      }
    },
  };
}

const globalSemaphore = createSemaphore(
  config.limits.maxConcurrentGlobal,
);

/* ------------------------------------------------------------------ */
/* i18n                                                               */
/* ------------------------------------------------------------------ */

const T = {
  en: {
    welcome:
      `🕷 <b>SPIDER WEB ANALYZER</b>\n` +
      `SPIDER SECURITY TOOLS\n\n` +
      `Professional website reconnaissance and defensive DDoS security analysis.\n\n` +
      `Send a website URL or choose an option below. All scans use passive inspection and safe, low-volume requests only.`,
    help:
      `🕷 <b>SPIDER WEB ANALYZER — HELP</b>\n\n` +
      `<b>Commands</b>\n` +
      `/start — Main menu\n` +
      `/scan — Scan a website\n` +
      `/help — This help message\n` +
      `/about — About the bot\n` +
      `/cancel — Cancel an active scan\n\n` +
      `<b>What is analyzed</b>\n` +
      `• DNS records, IPv4/IPv6, resolution time\n` +
      `• HTTP status, redirects, response headers, page title\n` +
      `• HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3 indicators\n` +
      `• TLS certificate, issuer, expiration, hostname match, chain\n` +
      `• Server fingerprinting, CDN, WAF, reverse proxy\n` +
      `• Backend, CMS, frontend technologies with evidence\n` +
      `• Security headers and defensive DDoS indicators\n\n` +
      `<b>Security restrictions</b>\n` +
      `This bot is defensive only. It does not flood, flood-test, slowloris-test, bypass WAFs, or generate high-volume traffic. Private and blocked IP ranges are rejected by SSRF protection.`,
    about:
      `🕷 <b>SPIDER WEB ANALYZER</b>\n` +
      `SPIDER SECURITY TOOLS\n\n` +
      `A lightweight Telegram-based website reconnaissance and defensive security analysis system built with Node.js 22 and Telegraf.\n\n` +
      `It performs passive inspection and a small number of safe, low-volume requests. It never executes website content or downloaded JavaScript.`,
    promptUrl:
      '🔗 Send the website URL you want to analyze (for example: <code>https://example.com</code>).',
    startingScan: '🕷 Starting scan...',
    sendUrlHint:
      'Send a website URL or use the menu below to start a scan.',
    rateLimit:
      '⏳ Rate limit reached. Please wait about a minute before scanning again.',
    alreadyScanning:
      '⏳ A scan is already in progress. Use /cancel to stop it.',
    cancelled: '🛑 Scan cancelled.',
    noActiveScan:
      'No active scan to cancel. Use /scan to start one.',
    adminOnly:
      '⛔ This command is for administrators only.',
    invalidInput:
      '❌ That does not look like a valid URL. Send a public HTTP or HTTPS URL.',
    busy:
      '⏳ The scanner is busy. Please try again in a few seconds.',
    scanFailed:
      '❌ The scan could not be completed.',
  },

  fa: {
    welcome:
      `🕷 <b>تحلیلگر وب اسپایدر</b>\n` +
      `ابزارهای امنیتی اسپایدر\n\n` +
      `شناسایی حرفه‌ای وب‌سایت و تحلیل دفاعی امنیت DDoS.\n\n` +
      `یک URL ارسال کنید یا یکی از گزینه‌های زیر را انتخاب کنید. همه اسکن‌ها از بررسی غیرفعال و درخواست‌های ایمن و کم‌حجم استفاده می‌کنند.`,
    help:
      `🕷 <b>تحلیلگر وب اسپایدر — راهنما</b>\n\n` +
      `<b>دستورات</b>\n` +
      `/start — منوی اصلی\n` +
      `/scan — اسکن وب‌سایت\n` +
      `/help — این راهنما\n` +
      `/about — درباره ربات\n` +
      `/cancel — لغو اسکن فعال\n\n` +
      `<b>موارد تحلیل‌شده</b>\n` +
      `• رکوردهای DNS، IPv4/IPv6، زمان resolve\n` +
      `• وضعیت HTTP، ریدایرکت‌ها، هدرهای پاسخ، عنوان صفحه\n` +
      `• نشانه‌های HTTP/1.0، HTTP/1.1، HTTP/2، HTTP/3\n` +
      `• گواهی TLS، صادرکننده، انقضا، تطابق نام میزبان، زنجیره\n` +
      `• شناسایی سرور، CDN، WAF، پروکسی معکوس\n` +
      `• تکنولوژی‌های بک‌اند، CMS و فرانت‌اند با شواهد\n` +
      `• هدرهای امنیتی و نشانه‌های دفاعی DDoS\n\n` +
      `<b>محدودیت‌های امنیتی</b>\n` +
      `این ربات فقط دفاعی است. حملات flooding، slowloris، دور زدن WAF یا ترافیک پرحجم انجام نمی‌دهد. آدرس‌های خصوصی و مسدود توسط محافظت SSRF رد می‌شوند.`,
    about:
      `🕷 <b>تحلیلگر وب اسپایدر</b>\n` +
      `ابزارهای امنیتی اسپایدر\n\n` +
      `یک سیستم سبک تلگرامی برای شناسایی وب‌سایت و تحلیل دفاعی امنیت، ساخته‌شده با Node.js 22 و Telegraf.\n\n` +
      `این ربات بررسی غیرفعال و تعداد کمی درخواست ایمن و کم‌حجم انجام می‌دهد. هرگز محتوای وب‌سایت یا JavaScript دانلودشده را اجرا نمی‌کند.`,
    promptUrl:
      '🔗 URL وب‌سایتی را که می‌خواهید تحلیل شود ارسال کنید (مثلاً: <code>https://example.com</code>).',
    startingScan: '🕷 شروع اسکن...',
    sendUrlHint:
      'یک URL ارسال کنید یا از منوی زیر برای شروع اسکن استفاده کنید.',
    rateLimit:
      '⏳ محدودیت درخواست فعال شد. لطفاً حدود یک دقیقه صبر کنید.',
    alreadyScanning:
      '⏳ یک اسکن در حال انجام است. برای توقف از /cancel استفاده کنید.',
    cancelled: '🛑 اسکن لغو شد.',
    noActiveScan:
      'اسکن فعالی برای لغو وجود ندارد. برای شروع از /scan استفاده کنید.',
    adminOnly: '⛔ این دستور فقط برای مدیران است.',
    invalidInput:
      '❌ ورودی شبیه URL معتبر نیست. یک URL عمومی HTTP یا HTTPS ارسال کنید.',
    busy:
      '⏳ اسکنر مشغول است. لطفاً چند ثانیه دیگر دوباره تلاش کنید.',
    scanFailed: '❌ اسکن کامل نشد.',
  },
};

function detectLang(ctx) {
  const code = (ctx.from && ctx.from.language_code) || 'en';
  return code.startsWith('fa') ? 'fa' : 'en';
}

function getSession(userId) {
  if (!sessions.has(userId)) {
    sessions.set(userId, {
      awaitingUrl: false,
      mode: 'full',
      scanning: false,
      cancelRequested: false,
      progressMsgId: null,
      lang: 'en',
      scanTimestamps: [],
      lastProgressEdit: 0,
      lastProgressText: '',
    });
  }
  return sessions.get(userId);
}

function checkRateLimit(session) {
  const now = Date.now();
  session.scanTimestamps = session.scanTimestamps.filter(
    (t) => now - t < config.limits.userWindowMs,
  );

  if (
    session.scanTimestamps.length >=
    config.limits.maxScansPerUserPerWindow
  ) {
    return false;
  }

  session.scanTimestamps.push(now);
  return true;
}

/* ------------------------------------------------------------------ */
/* Keyboards                                                          */
/* ------------------------------------------------------------------ */

function mainMenu(lang) {
  const fa = lang === 'fa';

  return Markup.inlineKeyboard([
    [
      Markup.button.callback(
        fa ? '🔍 اسکن وب‌سایت' : '🔍 Scan Website',
        'menu:scan',
      ),
    ],
    [
      Markup.button.callback(
        fa ? '🌐 اطلاعات سرور' : '🌐 Server Information',
        'menu:server',
      ),
    ],
    [
      Markup.button.callback(
        fa ? '🛡 تحلیل امنیتی' : '🛡 Security Analysis',
        'menu:security',
      ),
    ],
    [
      Markup.button.callback(
        fa
          ? '📋 گزارش فنی کامل'
          : '📋 Full Technical Report',
        'menu:full',
      ),
    ],
    [
      Markup.button.callback(
        fa ? 'ℹ️ راهنما' : 'ℹ️ Help',
        'menu:help',
      ),
    ],
  ]);
}

function cancelKeyboard(lang) {
  const fa = lang === 'fa';
  return Markup.inlineKeyboard([
    [
      Markup.button.callback(
        fa ? '🛑 لغو' : '🛑 Cancel',
        'menu:cancel',
      ),
    ],
  ]);
}

function backKeyboard(lang) {
  const fa = lang === 'fa';
  return Markup.inlineKeyboard([
    [
      Markup.button.callback(
        fa ? '🔙 بازگشت' : '🔙 Back',
        'menu:back',
      ),
    ],
  ]);
}

/* ------------------------------------------------------------------ */
/* Error formatting                                                   */
/* ------------------------------------------------------------------ */

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function formatError(message, lang = 'en') {
  const fa = lang === 'fa';
  const text = String(message || '');

  const rules = [
    [
      /invalid url|only http|hostname|credentials|ports/i,
      fa
        ? '❌ آدرس نامعتبر است. فقط آدرس‌های HTTP/HTTPS عمومی با پورت‌های 80، 443، 8080 یا 8443 مجاز هستند.'
        : '❌ Invalid URL. Only public HTTP/HTTPS URLs on ports 80, 443, 8080, or 8443 are allowed.',
    ],
    [
      /dns resolution failed|no a or aaaa/i,
      fa
        ? '❌ خطا در resolve دامنه. دامنه وجود ندارد یا رکورد A/AAAA ندارد.'
        : '❌ DNS resolution failed. The domain does not exist or has no A/AAAA records.',
    ],
    [
      /private|loopback|link-local|blocked addresses/i,
      fa
        ? '❌ هدف به آدرس‌های خصوصی، loopback یا مسدود resolve شده است. اسکن مجاز نیست.'
        : '❌ Target resolves to private, loopback, link-local, or blocked addresses. Scanning is not allowed.',
    ],
    [
      /timed out|timeout/i,
      fa
        ? '⏱ زمان اتصال یا پاسخ به پایان رسید.'
        : '⏱ Connection or response timed out.',
    ],
    [
      /too many redirects/i,
      fa
        ? '🔁 تعداد ریدایرکت‌ها بیش از حد مجاز است.'
        : '🔁 Too many redirects.',
    ],
    [
      /cancel/i,
      fa ? '🛑 اسکن لغو شد.' : '🛑 Scan cancelled.',
    ],
    [
      /connection refused|econnrefused/i,
      fa
        ? '🔌 اتصال به سرور رد شد.'
        : '🔌 Connection refused by the target server.',
    ],
    [
      /certificate|tls|ssl/i,
      fa
        ? '🔐 خطا در بررسی گواهی TLS.'
        : '🔐 TLS/SSL inspection error.',
    ],
    [
      /enotfound|eai_again/i,
      fa
        ? '🌐 خطای شبکه یا DNS.'
        : '🌐 Network or DNS error.',
    ],
  ];

  for (const [regex, translated] of rules) {
    if (regex.test(text)) return translated;
  }

  return fa
    ? `❌ خطای غیرمنتظره: ${escapeHtml(text.slice(0, 300))}`
    : `❌ Unexpected error: ${escapeHtml(text.slice(0, 300))}`;
}

/* ------------------------------------------------------------------ */
/* Message splitting                                                  */
/* ------------------------------------------------------------------ */

function splitMessage(text, maxLen = 4000) {
  const parts = [];
  let current = '';

  const pushCurrent = () => {
    if (current) {
      parts.push(current);
      current = '';
    }
  };

  for (const line of text.split('\n')) {
    if (line.length > maxLen) {
      pushCurrent();
      for (let i = 0; i < line.length; i += maxLen) {
        parts.push(line.slice(i, i + maxLen));
      }
      continue;
    }

    if ((current + '\n' + line).length > maxLen) {
      pushCurrent();
      current = line;
    } else {
      current = current ? current + '\n' + line : line;
    }
  }

  pushCurrent();
  return parts.length ? parts : [''];
}

/* ------------------------------------------------------------------ */
/* Commands                                                           */
/* ------------------------------------------------------------------ */

bot.start((ctx) => {
  const session = getSession(ctx.from.id);
  session.lang = detectLang(ctx);

  return ctx.reply(T[session.lang].welcome, {
    parse_mode: 'HTML',
    ...mainMenu(session.lang),
  });
});

bot.help((ctx) => {
  const session = getSession(ctx.from.id);
  session.lang = detectLang(ctx);

  return ctx.reply(T[session.lang].help, {
    parse_mode: 'HTML',
    ...backKeyboard(session.lang),
  });
});

bot.command('about', (ctx) => {
  const session = getSession(ctx.from.id);
  session.lang = detectLang(ctx);

  return ctx.reply(T[session.lang].about, {
    parse_mode: 'HTML',
    ...backKeyboard(session.lang),
  });
});

bot.command('scan', (ctx) => {
  const session = getSession(ctx.from.id);
  session.lang = detectLang(ctx);
  session.mode = 'full';
  session.awaitingUrl = true;

  return ctx.reply(T[session.lang].promptUrl, {
    parse_mode: 'HTML',
    ...cancelKeyboard(session.lang),
  });
});

bot.command('cancel', (ctx) => {
  const session = getSession(ctx.from.id);
  session.lang = detectLang(ctx);

  if (session.scanning) {
    session.cancelRequested = true;
    return ctx.reply(T[session.lang].cancelled);
  }

  session.awaitingUrl = false;
  return ctx.reply(T[session.lang].noActiveScan, {
    ...mainMenu(session.lang),
  });
});

bot.command('stats', (ctx) => {
  if (!config.bot.admins.includes(ctx.from.id)) {
    return ctx.reply(T[detectLang(ctx)].adminOnly);
  }

  return ctx.reply(
    `🕷 <b>SPIDER STATS</b>\n` +
      `Users: ${sessions.size}\n` +
      `Active scans: ${activeScans.size}\n` +
      `Total scans: ${totalScans}`,
    { parse_mode: 'HTML' },
  );
});

/* ------------------------------------------------------------------ */
/* Menu callbacks                                                     */
/* ------------------------------------------------------------------ */

bot.action(/^menu:(.+)$/, async (ctx) => {
  const action = ctx.match[1];
  const session = getSession(ctx.from.id);
  session.lang = detectLang(ctx);

  await ctx.answerCbQuery();

  if (action === 'cancel') {
    session.awaitingUrl = false;
    session.cancelRequested = true;
    await ctx.editMessageText(T[session.lang].cancelled, {
      ...mainMenu(session.lang),
    });
    return;
  }

  if (action === 'help') {
    await ctx.editMessageText(T[session.lang].help, {
      parse_mode: 'HTML',
      ...backKeyboard(session.lang),
    });
    return;
  }

  if (action === 'back') {
    await ctx.editMessageText(T[session.lang].welcome, {
      parse_mode: 'HTML',
      ...mainMenu(session.lang),
    });
    return;
  }

  const modeMap = {
    scan: 'full',
    server: 'server',
    security: 'security',
    full: 'full',
  };

  session.mode = modeMap[action] || 'full';
  session.awaitingUrl = true;

  await ctx.editMessageText(T[session.lang].promptUrl, {
    parse_mode: 'HTML',
    ...cancelKeyboard(session.lang),
  });
});

/* ------------------------------------------------------------------ */
/* Text input                                                         */
/* ------------------------------------------------------------------ */

bot.on('text', async (ctx) => {
  const session = getSession(ctx.from.id);
  session.lang = detectLang(ctx);

  if (!session.awaitingUrl) {
    return ctx.reply(T[session.lang].sendUrlHint, {
      ...mainMenu(session.lang),
    });
  }

  const input = ctx.message.text.trim();

  if (!input || input.startsWith('/')) {
    return ctx.reply(T[session.lang].invalidInput, {
      ...mainMenu(session.lang),
    });
  }

  return handleScan(ctx, session, input);
});

/* ------------------------------------------------------------------ */
/* Scan handler                                                       */
/* ------------------------------------------------------------------ */

async function handleScan(ctx, session, input) {
  if (session.scanning) {
    return ctx.reply(T[session.lang].alreadyScanning);
  }

  const validation = validateUrl(input);
  if (validation.error) {
    return ctx.reply(T[session.lang].invalidInput, {
      ...mainMenu(session.lang),
    });
  }

  if (!checkRateLimit(session)) {
    return ctx.reply(T[session.lang].rateLimit);
  }

  session.scanning = true;
  session.cancelRequested = false;
  session.awaitingUrl = false;
  session.lastProgressEdit = 0;
  session.lastProgressText = '';

  const mode = session.mode || 'full';
  const lang = session.lang;

  let acquired = false;

  try {
    await globalSemaphore.acquire(30000);
    acquired = true;

    activeScans.add(ctx.from.id);

    const progressMessage = await ctx.reply(
      T[lang].startingScan,
      { parse_mode: 'HTML' },
    );

    session.progressMsgId = progressMessage.message_id;

    const onProgress = async (text) => {
      if (session.cancelRequested) {
        throw new Error('Scan cancelled by user.');
      }

      const now = Date.now();

      if (
        now - session.lastProgressEdit <
        config.limits.progressEditIntervalMs
      ) {
        return;
      }

      if (text === session.lastProgressText) return;

      session.lastProgressEdit = now;
      session.lastProgressText = text;

      try {
        await ctx.telegram.editMessageText(
          ctx.chat.id,
          session.progressMsgId,
          undefined,
          text,
          { parse_mode: 'HTML' },
        );
      } catch {
        /* Ignore edit throttling errors. */
      }
    };

    const scan = await scanWebsite(input, {
      isCancelled: () => session.cancelRequested,
      onProgress,
    });

    totalScans += 1;

    const report = buildReport(scan, mode, lang);
    const parts = splitMessage(report);

    try {
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        session.progressMsgId,
        undefined,
        parts[0],
        {
          parse_mode: 'HTML',
          disable_web_page_preview: true,
        },
      );
    } catch {
      await ctx.reply(parts[0], {
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      });
    }

    for (let i = 1; i < parts.length; i += 1) {
      await ctx.reply(parts[i], {
        parse_mode: 'HTML',
        disable_web_page_preview: true,
      });
    }
  } catch (error) {
    const message = formatError(
      (error && error.message) || String(error),
      lang,
    );

    if (session.progressMsgId) {
      try {
        await ctx.telegram.editMessageText(
          ctx.chat.id,
          session.progressMsgId,
          undefined,
          message,
          { parse_mode: 'HTML' },
        );
      } catch {
        await ctx.reply(message, { parse_mode: 'HTML' });
      }
    } else {
      await ctx.reply(message, { parse_mode: 'HTML' });
    }
  } finally {
    if (acquired) globalSemaphore.release();
    activeScans.delete(ctx.from.id);

    session.scanning = false;
    session.cancelRequested = false;
    session.progressMsgId = null;
    session.lastProgressEdit = 0;
    session.lastProgressText = '';
  }
}

/* ------------------------------------------------------------------ */
/* Global error handling                                              */
/* ------------------------------------------------------------------ */

bot.catch((error, ctx) => {
  console.error('Telegram bot error:', error);

  if (ctx && ctx.reply) {
    ctx
      .reply(
        '❌ An unexpected error occurred. The bot is still running.',
      )
      .catch(() => {});
  }
});

/* ------------------------------------------------------------------ */
/* Launch                                                             */
/* ------------------------------------------------------------------ */

bot.telegram
  .setMyCommands([
    { command: 'start', description: 'Start the bot' },
    { command: 'scan', description: 'Scan a website' },
    { command: 'help', description: 'Show help' },
    { command: 'about', description: 'About the bot' },
    { command: 'cancel', description: 'Cancel active scan' },
  ])
  .catch(() => {});

bot
  .launch()
  .then(() => {
    console.log('🕷 SPIDER WEB ANALYZER is running.');
  })
  .catch((error) => {
    console.error('Failed to launch bot:', error);
    process.exit(1);
  });

process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));