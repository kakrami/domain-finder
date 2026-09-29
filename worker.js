import page from './index.html';

// Domain Finder 1.0.0. Only these two read-only Registrar operations are exposed.
// Runtime secrets: CF_ACCOUNT_ID and CF_API_TOKEN. Never put values in this file.
const VERSION = '1.0.0';
const LIMIT = 20;
const HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

class AppError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status, headers: { ...HEADERS, 'Content-Type': 'application/json; charset=utf-8' },
  });
}

function settings(env) {
  const account = String(env.CF_ACCOUNT_ID || '').trim();
  const token = String(env.CF_API_TOKEN || '').trim();
  const problems = [];
  if (!account) problems.push('Add the CF_ACCOUNT_ID secret.');
  else if (!/^[a-f0-9]{32}$/i.test(account)) {
    problems.push('CF_ACCOUNT_ID must be the 32-character Cloudflare account ID, not a Worker name or address.');
  }
  if (!token) problems.push('Add the CF_API_TOKEN secret.');
  else if (/\s/.test(token)) problems.push('CF_API_TOKEN must contain only the token value, without "Bearer" or spaces.');
  return { account, token, problems };
}

function domainName(input) {
  if (typeof input !== 'string') throw new AppError('Each domain must be text.');
  let raw = input.trim().toLowerCase();
  if (/^https?:\/\//.test(raw)) {
    try { raw = new URL(raw).hostname; }
    catch { throw new AppError('Enter a valid domain, such as example.com.'); }
  }
  raw = raw.replace(/\.$/, '');
  if (!raw || !/^[\p{L}\p{N}.-]+$/u.test(raw)) {
    throw new AppError('Use full domain names, such as example.com. Separate multiple domains with commas.');
  }
  let name;
  try { name = new URL('https://' + raw).hostname; }
  catch { throw new AppError('One of the domain names is invalid.'); }
  const labels = name.split('.');
  if (name.length > 253 || labels.length < 2 || /^\d+$/.test(labels.at(-1)) ||
      labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new AppError('Enter a valid full domain, such as example.com.');
  }
  return name;
}

async function readBody(request) {
  if (!request.headers.get('content-type')?.toLowerCase().includes('application/json')) {
    throw new AppError('Send a JSON request.', 415);
  }
  if (Number(request.headers.get('content-length')) > 8192) throw new AppError('Request is too large.', 413);
  const reader = request.body?.getReader();
  if (!reader) throw new AppError('Enter a search first.');
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 8192) { await reader.cancel(); throw new AppError('Request is too large.', 413); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  try {
    const body = JSON.parse(new TextDecoder().decode(bytes));
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error();
    return body;
  } catch { throw new AppError('The request is not valid JSON.'); }
}

function cleanRows(rows) {
  if (!Array.isArray(rows) || rows.length > 50) throw new AppError('Cloudflare returned an unexpected result format.', 502);
  const seen = new Set();
  return rows.map(row => {
    if (!row || typeof row.name !== 'string' || typeof row.registrable !== 'boolean') {
      throw new AppError('Cloudflare returned an incomplete result. No availability was assumed.', 502);
    }
    let name;
    try { name = domainName(row.name); }
    catch { throw new AppError('Cloudflare returned an invalid domain name.', 502); }
    const out = { name, registrable: row.registrable };
    if (typeof row.reason === 'string') out.reason = row.reason.slice(0, 120);
    if (typeof row.tier === 'string') out.tier = row.tier.slice(0, 30);
    const price = row.pricing;
    if (price && typeof price.currency === 'string' && /^[A-Z]{3}$/.test(price.currency)) {
      out.pricing = { currency: price.currency };
      for (const key of ['registration_cost', 'renewal_cost']) {
        if (typeof price[key] === 'string' && /^\d+(\.\d+)?$/.test(price[key])) out.pricing[key] = price[key];
      }
    }
    return out;
  }).filter(row => {
    if (seen.has(row.name)) return false;
    seen.add(row.name);
    return true;
  });
}

async function registrar(config, operation, data) {
  const url = new URL(`https://api.cloudflare.com/client/v4/accounts/${config.account}/registrar/${operation}`);
  const options = {
    method: operation === 'domain-search' ? 'GET' : 'POST',
    headers: { Authorization: 'Bearer ' + config.token, Accept: 'application/json' },
    redirect: 'error',
  };
  if (operation === 'domain-search') {
    url.searchParams.set('q', data.q);
    url.searchParams.set('limit', String(LIMIT));
  } else {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify({ domains: data.domains });
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  options.signal = controller.signal;
  try {
    const response = await fetch(url, options);
    let body;
    try { body = await response.json(); }
    catch {
      if (response.status === 429) throw new AppError('Cloudflare is rate-limiting requests. Wait a moment, then search again.', 429);
      throw new AppError(`Cloudflare returned HTTP ${response.status} without a JSON result. Try again later.`, 502);
    }
    if (!response.ok || body?.success !== true) {
      const detail = Array.isArray(body?.errors)
        ? body.errors.map(e => String(e?.message || '')).filter(Boolean).join('; ').slice(0, 500)
        : '';
      // Never send a credential back, even if an upstream diagnostic echoes it.
      const safeDetail = detail.split(config.token).join('[redacted]').split(config.account).join('[account]');
      let message = 'Cloudflare could not complete this search.';
      if (response.status === 401 || response.status === 403) {
        message = 'Cloudflare rejected access. Check CF_ACCOUNT_ID, the token, and its Registrar permissions for this account.';
      } else if (response.status === 404) {
        message = 'Cloudflare did not find this Registrar API resource. Check the account ID and Registrar API access.';
      } else if (response.status === 429) {
        message = 'Cloudflare is rate-limiting requests. Wait a moment, then search again.';
      }
      throw new AppError(message + (safeDetail ? ' ' + safeDetail : ` (HTTP ${response.status})`), response.status === 429 ? 429 : 502);
    }
    return cleanRows(body.result?.domains);
  } catch (error) {
    if (error instanceof AppError) throw error;
    if (controller.signal.aborted) throw new AppError('Cloudflare took too long to respond. Please retry the search.', 504);
    throw new AppError('The Worker could not reach Cloudflare Registrar. Please retry.', 502);
  } finally { clearTimeout(timeout); }
}

async function check(config, domains) {
  if (!Array.isArray(domains) || !domains.length || domains.length > LIMIT) {
    throw new AppError(`Check between 1 and ${LIMIT} domains at a time.`);
  }
  const names = [...new Set(domains.map(domainName))];
  const rows = await registrar(config, 'domain-check', { domains: names });
  const byName = new Map(rows.map(row => [row.name, row]));
  // Missing records are unknown, never "available" or "taken".
  return names.map(name => byName.has(name)
    ? { ...byName.get(name), checked: true }
    : { name, registrable: null, checked: false, reason: 'not_returned' });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if ((url.pathname === '/' || url.pathname === '/index.html') && ['GET', 'HEAD'].includes(request.method)) {
      const nonce = crypto.randomUUID().replaceAll('-', '');
      return new Response(request.method === 'HEAD' ? null : page.replaceAll('__CSP_NONCE__', nonce), {
        headers: {
          ...HEADERS,
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
          'X-Frame-Options': 'DENY',
        },
      });
    }
    if (url.pathname === '/favicon.ico') return new Response(null, { status: 204, headers: HEADERS });
    if (url.pathname === '/robots.txt') return new Response('User-agent: *\nDisallow: /\n', { headers: { ...HEADERS, 'Content-Type': 'text/plain' } });
    if (url.pathname === '/api/status' && request.method === 'GET') {
      const config = settings(env);
      return json({ version: VERSION, configured: config.problems.length === 0, problems: config.problems });
    }
    if (!['/api/search', '/api/check'].includes(url.pathname)) return json({ error: 'Not found.' }, 404);
    if (request.method !== 'POST') return json({ error: 'Use POST for searches.' }, 405);
    // No cross-origin credentialed proxy. Only fixed search/check routes exist.
    const origin = request.headers.get('origin');
    if ((origin && origin !== url.origin) || request.headers.get('sec-fetch-site') === 'cross-site') {
      return json({ error: 'Search from this website, not another origin.' }, 403);
    }
    try {
      const config = settings(env);
      if (config.problems.length) throw new AppError('Setup needed: ' + config.problems.join(' '), 503);
      const body = await readBody(request);
      if (url.pathname === '/api/check') {
        return json({ mode: 'check', domains: await check(config, body.domains), checkedAt: new Date().toISOString() });
      }
      if (typeof body.q !== 'string' || !body.q.trim()) throw new AppError('Enter a name, phrase, or full domain.');
      const q = body.q.trim();
      if (q.length > 2000 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(q)) throw new AppError('The search is too long or contains invalid characters.');
      const parts = q.split(/[,;\n]+/).map(x => x.trim()).filter(Boolean);
      const isExact = parts.length > 1 || /^https?:\/\//i.test(q) || (q.includes('.') && !/\s/.test(q));
      if (isExact) {
        return json({ mode: 'check', domains: await check(config, parts), checkedAt: new Date().toISOString() });
      }
      if (q.length > 100) throw new AppError('Keep a keyword or phrase search to 100 characters or fewer.');
      const rows = await registrar(config, 'domain-search', { q });
      return json({ mode: 'suggestions', domains: rows.slice(0, LIMIT).map(row => ({ ...row, checked: false })) });
    } catch (error) {
      return json({ error: error instanceof AppError ? error.message : 'An unexpected error occurred. Please retry.' }, error instanceof AppError ? error.status : 500);
    }
  },
};
