// CurlSec — zero-dependency local server (Node 18+)
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, 'public');
const MAX_BYTES = 15 * 1024 * 1024;
const DEFAULT_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';

const ASSETS = path.join(__dirname, 'assets');
const MIME = {
  '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml',
  '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime', '.png': 'image/png', '.jpg': 'image/jpeg', '.webp': 'image/webp',
};

function sendJson(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 20 * 1024 * 1024) reject(new Error('Request too large'));
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function isTextType(ct) {
  return !ct || /text|json|xml|javascript|ecmascript|html|css|svg|csv|yaml|x-www-form-urlencoded/i.test(ct);
}

async function doCurl(opts) {
  let url = String(opts.url || '').trim();
  if (!url) throw new Error('URL is required');
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  new URL(url); // validate

  const method = (opts.method || 'GET').toUpperCase();
  const headers = { 'User-Agent': DEFAULT_UA, Accept: '*/*', ...(opts.headers || {}) };
  const follow = opts.followRedirects !== false;
  const redirects = [];
  const start = performance.now();

  let current = url;
  let res;
  for (let hop = 0; hop < 10; hop++) {
    res = await fetch(current, {
      method,
      headers,
      body: ['GET', 'HEAD'].includes(method) ? undefined : opts.body || undefined,
      redirect: 'manual',
      signal: AbortSignal.timeout(25000),
    });
    const loc = res.headers.get('location');
    if (follow && res.status >= 300 && res.status < 400 && loc) {
      const next = new URL(loc, current).href;
      redirects.push({ status: res.status, from: current, to: next });
      current = next;
      continue;
    }
    break;
  }
  const ttfb = performance.now() - start;

  const buf = Buffer.from(await res.arrayBuffer());
  const total = performance.now() - start;
  const ct = res.headers.get('content-type') || '';
  const text = isTextType(ct);
  const truncated = buf.length > MAX_BYTES;
  const slice = truncated ? buf.subarray(0, MAX_BYTES) : buf;

  return {
    ok: true,
    url,
    finalUrl: current,
    method,
    status: res.status,
    statusText: res.statusText,
    headers: Object.fromEntries(res.headers.entries()),
    setCookies: res.headers.getSetCookie ? res.headers.getSetCookie() : [],
    requestHeaders: headers,
    contentType: ct,
    isText: text,
    body: text ? slice.toString('utf8') : slice.toString('base64'),
    size: buf.length,
    truncated,
    redirects,
    timing: { ttfb: Math.round(ttfb), total: Math.round(total) },
  };
}

/* ---------------- AI analysis proxy (streams NDJSON back to the browser) ---------------- */

// Parse a Server-Sent Events body into its `data:` payloads.
async function* sseData(body) {
  const dec = new TextDecoder();
  let buf = '';
  const flush = function* (block) {
    const data = block.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
    if (data) yield data;
  };
  for await (const chunk of body) {
    buf += dec.decode(chunk, { stream: true });
    let m;
    while ((m = /\r?\n\r?\n/.exec(buf))) {
      yield* flush(buf.slice(0, m.index));
      buf = buf.slice(m.index + m[0].length);
    }
  }
  if (buf.trim()) yield* flush(buf);
}

function buildProviderRequest({ provider, apiKey, model, baseUrl, system, prompt }) {
  if (provider === 'anthropic') {
    const headers = { 'content-type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' };
    const body = { model, max_tokens: 32000, stream: true, system, messages: [{ role: 'user', content: prompt }] };
    if (/^claude-(opus|fable|mythos)|^claude-sonnet-(4-6|5)/.test(model)) body.output_config = { effort: 'high' };
    // Re-run a declined request on Anthropic's recommended fallback model instead of returning a refusal.
    if (/^claude-(opus-5|fable-5-1|sonnet-5-5)/.test(model)) {
      body.fallbacks = 'default';
      headers['anthropic-beta'] = 'server-side-fallback-2026-07-01';
    }
    return { url: 'https://api.anthropic.com/v1/messages', headers, body };
  }
  if (provider === 'gemini') {
    return {
      url: `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:streamGenerateContent?alt=sse`,
      headers: { 'content-type': 'application/json', 'x-goog-api-key': apiKey },
      body: {
        systemInstruction: { parts: [{ text: system }] },
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: { responseMimeType: 'application/json', maxOutputTokens: 32768 },
      },
    };
  }
  // OpenAI and every OpenAI-compatible API (OpenRouter, Groq, DeepSeek, xAI, Ollama, custom)
  const base = String(baseUrl || OPENAI_BASES[provider] || OPENAI_BASES.openai).replace(/\/+$/, '');
  const headers = { 'content-type': 'application/json', 'X-Title': 'CurlSec' };
  if (apiKey) headers.authorization = 'Bearer ' + apiKey;
  const body = { model, stream: true, messages: [{ role: 'system', content: system }, { role: 'user', content: prompt }] };
  if (['openai', 'groq', 'deepseek', 'xai', 'ollama'].includes(provider)) body.response_format = { type: 'json_object' };
  // Groq's free tier counts the reserved output against a small tokens-per-minute limit, so keep it modest.
  if (provider === 'groq') body.max_completion_tokens = 6000;
  return { url: base + '/chat/completions', headers, body };
}

/* ---------------- One-step key connect: detect provider, validate key, pick a model ---------------- */

const OPENAI_BASES = {
  openai: 'https://api.openai.com/v1',
  groq: 'https://api.groq.com/openai/v1',
  deepseek: 'https://api.deepseek.com/v1',
  openrouter: 'https://openrouter.ai/api/v1',
  xai: 'https://api.x.ai/v1',
};
const MODEL_PREFS = {
  anthropic: [/^claude-opus-5-5$/, /^claude-sonnet-5-5$/, /^claude-opus/, /^claude-sonnet/, /^claude/],
  openai: [/^gpt-5(\.\d+)?$/, /^gpt-5(\.\d+)?-mini$/, /^gpt-4\.1$/, /^gpt-4o$/, /^gpt/],
  groq: [/gpt-oss-120b/, /llama-3\.3-70b-versatile/, /llama-4-maverick/, /kimi-k2/, /qwen/, /llama/],
  gemini: [/^gemini-\d+(\.\d+)?-pro$/, /^gemini-.*pro/, /^gemini-\d+(\.\d+)?-flash$/, /^gemini/],
  deepseek: [/^deepseek-chat$/, /deepseek/],
  xai: [/^grok-4$/, /^grok-4/, /^grok/],
  openrouter: [/^anthropic\/claude-opus-5/, /^anthropic\/claude-sonnet/, /^openai\/gpt-5$/, /^google\/gemini-.*-pro$/, /./],
};
const SKIP_MODELS = /whisper|tts|audio|guard|embed|image|dall-e|moderation|realtime|transcribe|playai|orpheus|compound|distil/i;

function detectProviders(key) {
  if (/^sk-ant-/.test(key)) return ['anthropic'];
  if (/^gsk_/.test(key)) return ['groq'];
  if (/^AIza/.test(key)) return ['gemini'];
  if (/^sk-or-/.test(key)) return ['openrouter'];
  if (/^xai-/.test(key)) return ['xai'];
  if (/^sk-/.test(key)) return ['openai', 'deepseek'];
  return ['openai', 'groq', 'openrouter', 'xai', 'deepseek', 'anthropic', 'gemini'];
}

function pickModel(provider, ids) {
  const usable = ids.filter((id) => !SKIP_MODELS.test(id));
  for (const re of MODEL_PREFS[provider] || []) {
    const hits = usable.filter((id) => re.test(id)).sort().reverse();
    if (hits.length) return hits[0];
  }
  return usable[0];
}

async function listModels(provider, key) {
  let url, headers;
  if (provider === 'anthropic') {
    url = 'https://api.anthropic.com/v1/models?limit=100';
    headers = { 'x-api-key': key, 'anthropic-version': '2023-06-01' };
  } else if (provider === 'gemini') {
    url = 'https://generativelanguage.googleapis.com/v1beta/models?pageSize=200';
    headers = { 'x-goog-api-key': key };
  } else {
    url = OPENAI_BASES[provider] + '/models';
    headers = { authorization: 'Bearer ' + key };
  }
  const get = async (u) => {
    const r = await fetch(u, { headers, signal: AbortSignal.timeout(15000) });
    if (!r.ok) { const e = new Error(`HTTP ${r.status}`); e.status = r.status; throw e; }
    return r.json();
  };
  // OpenRouter's model list is public, so check the key itself first.
  if (provider === 'openrouter') await get('https://openrouter.ai/api/v1/key');
  const j = await get(url);
  if (provider === 'gemini') {
    return (j.models || []).filter((m) => (m.supportedGenerationMethods || []).includes('generateContent')).map((m) => m.name.replace(/^models\//, ''));
  }
  return (j.data || []).map((m) => m.id);
}

async function connect(req, res) {
  const key = String(JSON.parse((await readBody(req)) || '{}').apiKey || '').trim();
  if (!key) return sendJson(res, 200, { ok: false, error: 'Paste an API key first.' });
  let lastErr;
  for (const provider of detectProviders(key)) {
    try {
      const ids = await listModels(provider, key);
      const model = pickModel(provider, ids);
      if (!model) throw new Error('This account has no chat models available.');
      return sendJson(res, 200, { ok: true, provider, model, models: ids.filter((id) => !SKIP_MODELS.test(id)).slice(0, 300) });
    } catch (e) {
      lastErr = e;
    }
  }
  const s = lastErr?.status;
  const error = [400, 401, 403].includes(s) ? 'This key was rejected. Make sure you copied the whole key (and that it has not been deleted).'
    : s === 429 ? 'The provider is rate-limiting this key — wait a minute and try again.'
    : lastErr?.cause ? `Could not reach the provider (${lastErr.cause.code || lastErr.cause.message}). Check your internet connection.`
    : lastErr?.message || 'Unknown error';
  sendJson(res, 200, { ok: false, error });
}

// Pull text / stop info out of one streamed event, per provider.
function parseEvent(provider, data) {
  if (data === '[DONE]') return {};
  const j = JSON.parse(data);
  if (j.error) return { error: j.error.message || JSON.stringify(j.error) };
  if (provider === 'anthropic') {
    if (j.type === 'content_block_delta' && j.delta?.type === 'text_delta') return { text: j.delta.text };
    if (j.type === 'message_delta' && j.delta?.stop_reason) return { stop: j.delta.stop_reason };
    return {};
  }
  if (provider === 'gemini') {
    const c = j.candidates?.[0];
    const text = (c?.content?.parts || []).filter((p) => !p.thought && p.text).map((p) => p.text).join('');
    return { text, stop: c?.finishReason };
  }
  const c = j.choices?.[0];
  return { text: c?.delta?.content || '', stop: c?.finish_reason };
}

async function analyze(req, res) {
  const opts = JSON.parse((await readBody(req)) || '{}');
  res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-cache' });
  const send = (o) => res.write(JSON.stringify(o) + '\n');
  const ac = new AbortController();
  res.on('close', () => { if (!res.writableEnded) ac.abort(); });

  try {
    if (!opts.model) throw new Error('No model selected — open AI Settings.');
    if (!opts.apiKey && opts.provider !== 'ollama' && opts.provider !== 'custom') throw new Error('No API key set — open AI Settings.');
    const r = buildProviderRequest(opts);
    const post = () => fetch(r.url, { method: 'POST', headers: r.headers, body: JSON.stringify(r.body), signal: ac.signal });
    let up = await post();
    // Some models don't support JSON mode — retry once without it.
    if (up.status === 400 && r.body.response_format) {
      const t = await up.text();
      if (/response_format|json/i.test(t)) { delete r.body.response_format; up = await post(); }
      else up = new Response(t, { status: 400, statusText: 'Bad Request' });
    }
    if (!up.ok) {
      const t = await up.text();
      let msg = t;
      try { const j = JSON.parse(t); msg = j.error?.message || j.message || (Array.isArray(j) && j[0]?.error?.message) || t; } catch {}
      throw new Error(`${up.status} ${up.statusText} — ${String(msg).slice(0, 500)}`);
    }
    send({ type: 'start' });
    let stop = null;
    for await (const data of sseData(up.body)) {
      let ev;
      try { ev = parseEvent(opts.provider, data); } catch { continue; }
      if (ev.error) throw new Error(ev.error);
      if (ev.text) send({ type: 'text', text: ev.text });
      if (ev.stop) stop = ev.stop;
    }
    if (stop === 'refusal' || stop === 'SAFETY') throw new Error('The model declined this request (' + stop + '). Try another model.');
    send({ type: 'done', stop });
  } catch (e) {
    if (e.name !== 'AbortError') {
      const net = e.cause && (e.cause.code || e.cause.message || e.cause.errors?.[0]?.code);
      send({ type: 'error', error: net ? `Could not reach the AI provider (${net}). Check the base URL / your connection.` : e.message });
    }
  }
  res.end();
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'POST' && req.url === '/api/analyze') return await analyze(req, res);
    if (req.method === 'POST' && req.url === '/api/connect') return await connect(req, res);
    if (req.method === 'POST' && req.url === '/api/curl') {
      const opts = JSON.parse((await readBody(req)) || '{}');
      try {
        sendJson(res, 200, await doCurl(opts));
      } catch (e) {
        const msg = e.name === 'TimeoutError' ? 'Request timed out (25s)' : e.cause?.message || e.message;
        sendJson(res, 200, { ok: false, error: msg });
      }
      return;
    }
    let file = decodeURIComponent(req.url.split('?')[0]);
    if (file === '/') file = '/index.html';
    // /assets/* comes from the project's assets folder (splash video etc.), everything else from public/.
    const root = file.startsWith('/assets/') ? ASSETS : PUBLIC;
    const full = path.normalize(path.join(root, root === ASSETS ? file.slice('/assets'.length) : file));
    if (!full.startsWith(root) || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
      res.writeHead(404);
      return res.end('Not found');
    }
    const type = MIME[path.extname(full).toLowerCase()] || 'application/octet-stream';
    const size = fs.statSync(full).size;
    // Byte-range support so browsers can stream and seek video.
    const range = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
    if (range) {
      const start = range[1] ? +range[1] : size - +range[2];
      const end = range[1] && range[2] ? Math.min(+range[2], size - 1) : size - 1;
      if (start >= size || start > end) { res.writeHead(416, { 'Content-Range': `bytes */${size}` }); return res.end(); }
      res.writeHead(206, { 'Content-Type': type, 'Content-Length': end - start + 1, 'Content-Range': `bytes ${start}-${end}/${size}`, 'Accept-Ranges': 'bytes' });
      return fs.createReadStream(full, { start, end }).pipe(res);
    }
    res.writeHead(200, { 'Content-Type': type, 'Content-Length': size, 'Accept-Ranges': 'bytes' });
    fs.createReadStream(full).pipe(res);
  } catch (e) {
    sendJson(res, 500, { ok: false, error: e.message });
  }
});

// Bind to localhost only so nobody else on the network can use this as a proxy.
server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n  ⚡ CurlSec running at  http://localhost:${PORT}\n`);
});
