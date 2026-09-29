import { DurableObject } from 'cloudflare:workers';
import page from './index.html';

// Domain Finder 1.3.0. Only search, check, and extension-list Registrar operations are exposed.
// Runtime secrets: CF_ACCOUNT_ID and CF_API_TOKEN. Never put values in this file.
const VERSION = '1.3.0';
const LIMIT = 20; // Cloudflare domain-check request limit.
const SEARCH_LIMIT = 50;
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

function extensionName(value) {
  if (typeof value !== 'string') throw new AppError('Each ending must be text.');
  const name = value.trim().toLowerCase().replace(/^\./, '');
  if (!name || name.length > 253 || !/[a-z]/.test(name) ||
      name.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new AppError('Use endings such as .com, .app, or .co.uk.');
  }
  return name;
}

function selectedExtensions(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 50) throw new AppError('Choose up to 50 endings.');
  return [...new Set(value.map(extensionName))];
}

function extensionPage(body) {
  if (!Array.isArray(body.result) || body.result.length > 50) {
    throw new AppError('Cloudflare returned an unexpected ending list.', 502);
  }
  let extensions;
  try { extensions = [...new Set(body.result.map(item => extensionName(item?.metadata?.name)))]; }
  catch { throw new AppError('Cloudflare returned an invalid ending list.', 502); }
  const cursor = body.result_info?.cursor ?? '';
  if (typeof cursor !== 'string' || cursor.length > 256 || /[\u0000-\u001f\u007f]/.test(cursor)) {
    throw new AppError('Cloudflare returned an invalid ending-list cursor.', 502);
  }
  return { extensions, cursor };
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

// Redact before truncating so a long error cannot expose part of a secret.
function safeDetail(value, config) {
  let text = String(value || '');
  for (const secret of [config.token, config.account]) {
    if (!secret) continue;
    for (const variant of new Set([secret, encodeURIComponent(secret)])) {
      text = text.split(variant).join('[redacted]');
    }
  }
  return text.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 600);
}

async function registrar(config, operation, data) {
  const url = new URL(`https://api.cloudflare.com/client/v4/accounts/${config.account}/registrar/${operation}`);
  const options = {
    method: operation === 'domain-check' ? 'POST' : 'GET',
    headers: { Authorization: 'Bearer ' + config.token, Accept: 'application/json' },
    // Workers supports manual redirect handling. Never forward the API token.
    redirect: 'manual',
  };
  if (operation === 'domain-search') {
    url.searchParams.set('q', data.q);
    url.searchParams.set('limit', String(SEARCH_LIMIT));
    // Repeated keys match Cloudflare's official SDK query serialization.
    for (const extension of data.extensions || []) url.searchParams.append('extensions', extension);
  } else if (operation === 'extensions') {
    url.searchParams.set('per_page', '50');
    if (data.cursor) url.searchParams.set('cursor', data.cursor);
  } else {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify({ domains: data.domains });
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  options.signal = controller.signal;
  try {
    const response = await fetch(url, options);
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      throw new AppError(`Cloudflare Registrar returned an unexpected HTTP ${response.status} redirect. The request was not forwarded to protect your API token.`, 502);
    }
    let body;
    try { body = await response.json(); }
    catch {
      if (controller.signal.aborted) throw new AppError('Cloudflare took too long to respond. Please retry the search.', 504);
      if (response.status === 429) throw new AppError('Cloudflare is rate-limiting requests. Wait a moment, then search again.', 429);
      throw new AppError(`Cloudflare returned HTTP ${response.status} without a JSON result. Try again later.`, 502);
    }
    if (!response.ok || body?.success !== true) {
      const detail = safeDetail(Array.isArray(body?.errors)
        ? body.errors.map(e => String(e?.message || '')).filter(Boolean).join('; ')
        : '', config);
      let message = 'Cloudflare could not complete this search.';
      if (response.status === 401 || response.status === 403) {
        message = 'Cloudflare rejected access. Check CF_ACCOUNT_ID, the token, and its Registrar permissions for this account.';
      } else if (response.status === 404) {
        message = 'Cloudflare did not find this Registrar API resource. Check the account ID and Registrar API access.';
      } else if (response.status === 429) {
        message = 'Cloudflare is rate-limiting requests. Wait a moment, then search again.';
      }
      throw new AppError(`${message} (HTTP ${response.status})` + (detail ? ' ' + detail : ''), response.status === 429 ? 429 : 502);
    }
    return body;
  } catch (error) {
    if (error instanceof AppError) throw error;
    if (controller.signal.aborted) throw new AppError('Cloudflare took too long to respond. Please retry the search.', 504);
    const detail = safeDetail(error instanceof Error ? `${error.name}: ${error.message}` : error, config);
    throw new AppError('Cloudflare request failed.' + (detail ? ' ' + detail : ' No response was received.'), 502);
  } finally { clearTimeout(timeout); }
}

async function check(config, domains) {
  if (!Array.isArray(domains) || !domains.length || domains.length > LIMIT) {
    throw new AppError(`Check between 1 and ${LIMIT} domains at a time.`);
  }
  const names = [...new Set(domains.map(domainName))];
  const rows = cleanRows((await registrar(config, 'domain-check', { domains: names })).result?.domains);
  const byName = new Map(rows.map(row => [row.name, row]));
  // Missing records are unknown, never "available" or "taken".
  return names.map(name => byName.has(name)
    ? { ...byName.get(name), checked: true }
    : { name, registrable: null, checked: false, reason: 'not_returned' });
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(catalogStub(env).fetch(new Request('https://catalog/ensure')));
  },
  async fetch(request, env) {
    const url = new URL(request.url);
    if ((url.pathname === '/' || url.pathname === '/index.html') && ['GET', 'HEAD'].includes(request.method)) {
      const nonce = crypto.randomUUID().replaceAll('-', '');
      return new Response(request.method === 'HEAD' ? null : page.replaceAll('__CSP_NONCE__', nonce), {
        headers: {
          ...HEADERS,
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; worker-src blob:; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
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
    if (url.pathname.startsWith('/api/catalog/')) {
      const origin = request.headers.get('origin');
      if ((origin && origin !== url.origin) || request.headers.get('sec-fetch-site') === 'cross-site') return json({ error: 'Use the Catalog tab on this website.' }, 403);
      const path = url.pathname.slice('/api/catalog'.length);
      if (!['/status','/list','/control'].includes(path)) return json({ error: 'Not found.' }, 404);
      if (request.method !== (path === '/control' ? 'POST' : 'GET')) return json({ error: 'Invalid method.' }, 405);
      try {
        return await catalogStub(env).fetch(new Request('https://catalog' + path + url.search, request));
      } catch { return json({ error: 'Catalog could not connect to storage. Deploy the updated wrangler.jsonc and worker.js together.' }, 503); }
    }
    const isExtensions = url.pathname === '/api/extensions';
    if (!['/api/search', '/api/check', '/api/extensions'].includes(url.pathname)) return json({ error: 'Not found.' }, 404);
    if (request.method !== (isExtensions ? 'GET' : 'POST')) {
      return json({ error: isExtensions ? 'Use GET for endings.' : 'Use POST for searches.' }, 405);
    }
    // No cross-origin credentialed proxy. Only fixed read-only routes exist.
    const origin = request.headers.get('origin');
    if ((origin && origin !== url.origin) || request.headers.get('sec-fetch-site') === 'cross-site') {
      return json({ error: 'Search from this website, not another origin.' }, 403);
    }
    try {
      const config = settings(env);
      if (config.problems.length) throw new AppError('Setup needed: ' + config.problems.join(' '), 503);
      if (isExtensions) {
        const cursor = url.searchParams.get('cursor') || '';
        if (cursor.length > 256 || /[\u0000-\u001f\u007f]/.test(cursor)) throw new AppError('Invalid ending-list cursor.');
        return json(extensionPage(await registrar(config, 'extensions', { cursor })));
      }
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
      const extensions = selectedExtensions(body.extensions);
      const rows = cleanRows((await registrar(config, 'domain-search', { q, extensions })).result?.domains);
      return json({ mode: 'suggestions', domains: rows.slice(0, SEARCH_LIMIT).map(row => ({ ...row, checked: false })) });
    } catch (error) {
      return json({ error: error instanceof AppError ? error.message : 'An unexpected error occurred. Please retry.' }, error instanceof AppError ? error.status : 500);
    }
  },
};

const CATALOG_TOTAL = 26 ** 3;
function shortName(index) {
  return String.fromCharCode(97 + Math.floor(index / 676), 97 + Math.floor(index / 26) % 26, 97 + index % 26);
}
function catalogStub(env) {
  if (!env.CATALOG) throw new AppError('Upload the updated wrangler.jsonc with the Catalog binding, then deploy.', 503);
  return env.CATALOG.get(env.CATALOG.idFromName('three-letter-catalog'));
}
export class DomainCatalog extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx; this.env = env;
    this.sql = ctx.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS jobs (ending TEXT PRIMARY KEY, cursor INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'running', sequence INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, retry_at INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '', updated INTEGER NOT NULL DEFAULT 0, cached INTEGER NOT NULL DEFAULT 0, checked INTEGER NOT NULL DEFAULT 0, available INTEGER NOT NULL DEFAULT 0, unknown INTEGER NOT NULL DEFAULT 0)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS domains (ending TEXT NOT NULL, ordinal INTEGER NOT NULL, checked INTEGER NOT NULL, available INTEGER, data TEXT NOT NULL, sequence INTEGER NOT NULL, PRIMARY KEY (ending, ordinal))`);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS domain_changes ON domains(ending, sequence)`);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS domain_status ON domains(ending, checked, available)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS retries (ending TEXT NOT NULL, ordinal INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, due INTEGER NOT NULL, PRIMARY KEY(ending, ordinal))`);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS retry_due ON retries(ending, due)`);
  }
  job(ending) { return this.sql.exec('SELECT * FROM jobs WHERE ending = ?', ending).toArray()[0]; }
  async ensure() {
    this.sql.exec("INSERT OR IGNORE INTO jobs(ending, updated) VALUES('com', ?)", Date.now());
    await this.wake();
  }
  async wake() {
    const jobs = this.sql.exec("SELECT * FROM jobs WHERE state IN ('running','retrying')").toArray();
    if (!jobs.length) { await this.ctx.storage.deleteAlarm(); return; }
    let next = Infinity;
    for (const job of jobs) {
      if (job.cursor < CATALOG_TOTAL) next = Math.min(next, Math.max(Date.now() + 1000, job.retry_at));
      else {
        const due = this.sql.exec('SELECT MIN(due) AS due FROM retries WHERE ending = ?', job.ending).toArray()[0]?.due;
        if (due !== null && due !== undefined) next = Math.min(next, Math.max(Date.now() + 1000, job.retry_at, due));
      }
    }
    if (Number.isFinite(next)) {
      const alarm = await this.ctx.storage.getAlarm();
      if (!alarm || alarm > next) await this.ctx.storage.setAlarm(next);
    }
  }
  status() {
    const jobs = this.sql.exec('SELECT * FROM jobs ORDER BY ending').toArray().map(job => {
      return { ...job, total: CATALOG_TOTAL };
    });
    return { length: 3, characters: 'a-z', jobs };
  }
  async fetch(request) {
    return this.ctx.blockConcurrencyWhile(async () => {
      try {
        const url = new URL(request.url);
        await this.ensure();
        if (url.pathname === '/ensure') return json(this.status());
        if (request.method === 'GET' && url.pathname === '/status') return json(this.status());
        if (request.method === 'GET' && url.pathname === '/list') {
          const ending = extensionName(url.searchParams.get('ending') || 'com');
          const after = Number(url.searchParams.get('after') || 0);
          if (!Number.isSafeInteger(after) || after < 0) throw new AppError('Invalid catalog cursor.');
          const data = this.sql.exec('SELECT data, sequence FROM domains WHERE ending = ? AND sequence > ? ORDER BY sequence LIMIT 1001', ending, after).toArray();
          const rows = data.slice(0, 1000);
          return json({ domains: rows.map(row => JSON.parse(row.data)), after: rows.at(-1)?.sequence || after, hasMore: data.length > 1000 });
        }
        if (request.method === 'POST' && url.pathname === '/control') {
          const body = await readBody(request);
          const ending = extensionName(body.ending);
          if (!['start','pause','resume'].includes(body.action)) throw new AppError('Invalid catalog action.');
          if (body.action === 'start' && !this.job(ending)) {
            if (this.sql.exec('SELECT COUNT(*) AS count FROM jobs').toArray()[0].count >= 50) throw new AppError('The catalog supports up to 50 endings.');
            // Validate the ending with one real check before creating a job.
            const config = settings(this.env);
            if (config.problems.length) throw new AppError(config.problems.join(' '), 503);
            const first = await check(config, ['aaa.' + ending]);
            if (first[0]?.reason === 'extension_disallows_registration') throw new AppError('This ending is not supported by the Registrar API.');
            this.sql.exec('INSERT INTO jobs(ending, updated) VALUES(?, ?)', ending, Date.now());
          }
          const job = this.job(ending);
          if (!job) throw new AppError('Start this ending first.');
          if (body.action === 'pause') this.sql.exec("UPDATE jobs SET state='paused', updated=? WHERE ending=?", Date.now(), ending);
          else if (job.cursor < CATALOG_TOTAL || job.state === 'paused' || job.state === 'complete_with_unknown') {
            this.ctx.storage.transactionSync(() => {
              if (job.cursor >= CATALOG_TOTAL) {
                this.sql.exec('INSERT OR IGNORE INTO retries(ending, ordinal, attempts, due) SELECT ending, ordinal, 0, ? FROM domains WHERE ending=? AND checked=0', Date.now(), ending);
                this.sql.exec('UPDATE retries SET attempts=0, due=? WHERE ending=?', Date.now(), ending);
              }
              this.sql.exec("UPDATE jobs SET state='running', attempts=0, retry_at=0, error='', updated=? WHERE ending=?", Date.now(), ending);
            });
          }
          if (this.job(ending).cursor >= CATALOG_TOTAL && !this.job(ending).unknown) this.sql.exec("UPDATE jobs SET state='complete' WHERE ending=?", ending);
          await this.wake();
          return json(this.status());
        }
        throw new AppError('Not found.', 404);
      } catch (error) { return json({ error: error instanceof AppError ? error.message : 'Catalog storage is unavailable. Retry after checking the deployment.' }, error instanceof AppError ? error.status : 503); }
    });
  }
  async alarm() {
    return this.ctx.blockConcurrencyWhile(async () => {
      const now = Date.now();
      const jobs = this.sql.exec("SELECT * FROM jobs WHERE state IN ('running','retrying') AND retry_at <= ? ORDER BY updated, ending", now).toArray();
      let job, indices, isRetry;
      for (const candidate of jobs) {
        if (candidate.cursor < CATALOG_TOTAL) {
          job = candidate; indices = Array.from({ length: Math.min(20, CATALOG_TOTAL - candidate.cursor) }, (_, i) => candidate.cursor + i); isRetry = false; break;
        }
        const pending = this.sql.exec('SELECT ordinal FROM retries WHERE ending=? AND due<=? ORDER BY due, ordinal LIMIT 20', candidate.ending, now).toArray();
        if (pending.length) { job = candidate; indices = pending.map(row => row.ordinal); isRetry = true; break; }
      }
      if (!job) { await this.wake(); return; }
      try {
        const config = settings(this.env);
        if (config.problems.length) throw new AppError(config.problems.join(' '), 503);
        const results = await check(config, indices.map(i => shortName(i) + '.' + job.ending));
        const checkedAt = new Date().toISOString();
        this.ctx.storage.transactionSync(() => {
          let sequence = job.sequence;
          let cached = job.cached, checkedCount = job.checked, available = job.available, unknown = job.unknown;
          results.forEach((row, i) => {
            const ordinal = indices[i];
            const data = { ...row, checkedAt };
            const previousRow = this.sql.exec('SELECT checked, available FROM domains WHERE ending=? AND ordinal=?', job.ending, ordinal).toArray()[0];
            if (!previousRow) cached++;
            checkedCount += (row.checked ? 1 : 0) - (previousRow?.checked || 0);
            available += (row.checked && row.registrable === true ? 1 : 0) - (previousRow?.checked && previousRow.available === 1 ? 1 : 0);
            unknown = cached - checkedCount;
            this.sql.exec('INSERT INTO domains(ending,ordinal,checked,available,data,sequence) VALUES(?,?,?,?,?,?) ON CONFLICT(ending,ordinal) DO UPDATE SET checked=excluded.checked, available=excluded.available, data=excluded.data, sequence=excluded.sequence', job.ending, ordinal, row.checked ? 1 : 0, row.registrable === true ? 1 : row.registrable === false ? 0 : null, JSON.stringify(data), ++sequence);
            if (row.checked) this.sql.exec('DELETE FROM retries WHERE ending=? AND ordinal=?', job.ending, ordinal);
            else {
              const previous = this.sql.exec('SELECT attempts FROM retries WHERE ending=? AND ordinal=?', job.ending, ordinal).toArray()[0]?.attempts || 0;
              if (previous >= 6) this.sql.exec('DELETE FROM retries WHERE ending=? AND ordinal=?', job.ending, ordinal);
              else this.sql.exec('INSERT INTO retries(ending,ordinal,attempts,due) VALUES(?,?,?,?) ON CONFLICT(ending,ordinal) DO UPDATE SET attempts=excluded.attempts,due=excluded.due', job.ending, ordinal, previous + 1, now + Math.min(900000, 60000 * 2 ** previous));
            }
          });
          const cursor = isRetry ? job.cursor : job.cursor + indices.length;
          const pending = this.sql.exec('SELECT COUNT(*) AS count FROM retries WHERE ending=?', job.ending).toArray()[0].count;
          const state = cursor < CATALOG_TOTAL ? 'running' : pending ? 'retrying' : unknown ? 'complete_with_unknown' : 'complete';
          this.sql.exec('UPDATE jobs SET cursor=?,sequence=?,state=?,attempts=0,retry_at=?,error=\'\',updated=?,cached=?,checked=?,available=?,unknown=? WHERE ending=?', cursor, sequence, state, now + 10000, now, cached, checkedCount, available, unknown, job.ending);
        });
      } catch (error) {
        const attempts = job.attempts + 1;
        const message = error instanceof AppError ? error.message : 'Catalog check failed. It will retry automatically.';
        this.sql.exec("UPDATE jobs SET state='retrying',attempts=?,retry_at=?,error=?,updated=? WHERE ending=?", attempts, now + Math.min(900000, 10000 * 2 ** Math.min(attempts, 7)), message, now, job.ending);
      }
      await this.wake();
    });
  }
}
