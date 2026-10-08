#!/usr/bin/env node
/**
 * SEOlity – Subscription AI runner (GitHub Actions)
 * ---------------------------------------------------------------
 * Runs SEOlity's AI requests with the AI account you already pay for, using the
 * vendors' OFFICIAL command-line tools in headless mode:
 *   - engine "claude": Claude Code  (`claude -p`)  + CLAUDE_CODE_OAUTH_TOKEN (Claude Pro/Max, from `claude setup-token`)
 *   - engine "codex" : OpenAI Codex (`codex exec`) + ChatGPT auth.json      (ChatGPT Plus/Pro)
 *
 * Queue (branch SEOLITY_JOBS_BRANCH, default "seolity-jobs"):
 *   jobs/<id>.json     written by WordPress  – AES-256-GCM encrypted request
 *   results/<id>.json  written by this runner – AES-256-GCM encrypted answer
 * Results are also POSTed (HMAC-signed) to SEOLITY_RELAY_URL (the site owner's
 * Cloudflare worker mailbox, which forwards them or keeps them until WordPress
 * pulls) and/or to SEOLITY_CALLBACK_URL when the site is reachable. Without
 * either, SEOlity simply collects the results from GitHub.
 *
 * Node 18+ – no npm dependencies.
 */
import { spawn } from 'node:child_process';
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile, appendFile, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const E = process.env;
const SECRET = E.SEOLITY_SHARED_SECRET || '';
const CALLBACK = /^https?:\/\//.test((E.SEOLITY_CALLBACK_URL || '').trim()) ? E.SEOLITY_CALLBACK_URL.trim() : '';
const RELAY = /^https:\/\//.test((E.SEOLITY_RELAY_URL || '').trim()) ? E.SEOLITY_RELAY_URL.trim().replace(/\/+$/, '') : '';
const BRANCH = /^[A-Za-z0-9._\/-]{1,100}$/.test(E.SEOLITY_JOBS_BRANCH || '') ? E.SEOLITY_JOBS_BRANCH : 'seolity-jobs';
const ENGINES = (E.SEOLITY_ENGINES || 'claude').split(',').map((s) => s.trim()).filter((s) => s === 'claude' || s === 'codex');
const BUDGET_MS = Math.min(Math.max(Number(E.SEOLITY_BUDGET_MIN || 40), 5), 55) * 60000;
const IDLE_MS = Math.min(Math.max(Number(E.SEOLITY_IDLE_SEC || 120), 0), 600) * 1000;
const ENGINE_TIMEOUT = Math.min(Math.max(Number(E.SEOLITY_ENGINE_TIMEOUT || 900), 60), 1800) * 1000;
const RESULT_TTL_MS = 24 * 3600 * 1000;
const CLAUDE_BIN = E.CLAUDE_BIN || 'claude';
const CODEX_BIN = E.CODEX_BIN || 'codex';
const WORK = join(process.cwd(), '.seolity-queue');

const log = (...a) => console.log('[seolity]', ...a);
const summary = [];

/* ------------------------------ crypto (must match SubscriptionRunner.php) ------------------------------ */
const encKey = () => createHash('sha256').update('enc|' + SECRET).digest();
const macKey = () => createHash('sha256').update('mac|' + SECRET).digest('hex');

export function encrypt(obj) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', encKey(), iv);
  const data = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return { v: 1, iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64') };
}

export function decrypt(env) {
  if (!env || env.v !== 1) throw new Error('unknown envelope');
  const d = createDecipheriv('aes-256-gcm', encKey(), Buffer.from(env.iv, 'base64'));
  d.setAuthTag(Buffer.from(env.tag, 'base64'));
  const plain = Buffer.concat([d.update(Buffer.from(env.data, 'base64')), d.final()]).toString('utf8');
  return JSON.parse(plain);
}

async function post(url, body, ts, sig, label) {
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'SEOlity-Runner/1.1', 'X-SEOlity-Timestamp': ts, 'X-SEOlity-Signature': sig },
      body,
      signal: AbortSignal.timeout(30000),
    });
    log(`${label} → HTTP ${res.status}`);
    return res.ok;
  } catch (e) {
    log(`${label} skipped:`, e.message);
    return false;
  }
}

async function callback(results) {
  if (!results.length || (!CALLBACK && !RELAY)) return;
  const body = JSON.stringify({ results });
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = createHmac('sha256', macKey()).update(`${ts}.${body}`).digest('hex');
  // Cloudflare mailbox first: it forwards to the site or keeps the result until WordPress pulls it.
  if (RELAY && (await post(`${RELAY}/mailbox`, body, ts, sig, 'relay'))) return;
  if (CALLBACK && (await post(CALLBACK, body, ts, sig, 'callback'))) return;
  log('site not reachable – it will collect results from GitHub');
}

/* ------------------------------ process helper ------------------------------ */
function run(bin, args, input, env, timeoutMs = ENGINE_TIMEOUT, cwd) {
  return new Promise((resolve) => {
    let out = '';
    let err = '';
    let killed = false;
    const child = spawn(bin, args, { env, cwd, stdio: ['pipe', 'pipe', 'pipe'] });
    const timer = setTimeout(() => { killed = true; child.kill('SIGKILL'); }, timeoutMs);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => { clearTimeout(timer); resolve({ code: -1, out, err: String(e.message), killed }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, out, err, killed }); });
    if (input) child.stdin.write(input);
    child.stdin.end();
  });
}
const git = async (args, cwd = WORK) => {
  const r = await run('git', args, '', E, 300000, cwd);
  if (r.code !== 0) throw new Error(`git ${args[0]}: ${(r.err || r.out).slice(0, 400)}`);
  return r.out;
};

/* ------------------------------ engines ------------------------------ */
let tmp = '';
let codexHome = '';
let codexAuthBefore = '';
let codexError = '';

async function prepare() {
  tmp = await mkdtemp(join(tmpdir(), 'seolity-'));
  if (ENGINES.includes('codex') && E.CODEX_AUTH_JSON) {
    // A bad credential must not stop the run: each codex job then reports the error to the site.
    try { JSON.parse(E.CODEX_AUTH_JSON); } catch (_) { codexError = 'Secret CODEX_AUTH_JSON is not valid JSON. Paste the whole ~/.codex/auth.json in SEOlity → Settings → Subscription AI.'; return; }
    codexHome = join(tmp, 'codex');
    await mkdir(codexHome, { recursive: true });
    codexAuthBefore = E.CODEX_AUTH_JSON;
    await writeFile(join(codexHome, 'auth.json'), E.CODEX_AUTH_JSON, { mode: 0o600 });
    await writeFile(join(codexHome, 'config.toml'), 'cli_auth_credentials_store = "file"\n');
  }
}

async function refreshedCodexAuth() {
  if (!codexHome) return null;
  try {
    const now = await readFile(join(codexHome, 'auth.json'), 'utf8');
    if (now && now !== codexAuthBefore) { codexAuthBefore = now; return now; }
  } catch (_) { /* ignore */ }
  return null;
}

const isQuota = (m) => /limit|quota|usage|rate/i.test(m);

async function askClaude(job) {
  if (!E.CLAUDE_CODE_OAUTH_TOKEN) throw new Error('Secret CLAUDE_CODE_OAUTH_TOKEN is missing. Paste your `claude setup-token` token in SEOlity → Settings → AI.');
  const sysFile = join(tmp, `sys-${job.id}.txt`);
  await writeFile(sysFile, job.system || 'You are a helpful assistant.', 'utf8');
  const args = ['-p', '--output-format', 'json', '--model', job.model || 'sonnet', '--tools', '', '--max-turns', '2', '--no-session-persistence', '--system-prompt-file', sysFile];
  const env = { ...E, DISABLE_AUTOUPDATER: '1' };
  delete env.ANTHROPIC_API_KEY; // never bill the API – use the subscription token
  delete env.ANTHROPIC_AUTH_TOKEN;
  delete env.SEOLITY_SHARED_SECRET;
  delete env.CODEX_AUTH_JSON;
  const r = await run(CLAUDE_BIN, args, job.prompt, env);
  if (r.killed) throw new Error('Claude Code timeout');
  let data = null;
  try { data = JSON.parse(r.out.trim().split('\n').filter(Boolean).pop() || ''); } catch (_) { /* ignore */ }
  if (!data) throw new Error('Claude Code: ' + (r.err || r.out || 'no output').slice(0, 500));
  if (data.is_error || (data.subtype && data.subtype !== 'success')) {
    const msg = String(data.result || data.subtype || 'error').slice(0, 500);
    throw Object.assign(new Error('Claude Code: ' + msg), { quota: isQuota(msg) });
  }
  const u = data.usage || {};
  return {
    text: String(data.result || ''),
    usage: { input: (u.input_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0), output: u.output_tokens || 0 },
    model: job.model || 'sonnet',
  };
}

async function askCodex(job) {
  if (codexError) throw new Error(codexError);
  if (!codexHome) throw new Error('Secret CODEX_AUTH_JSON is missing. Paste your ChatGPT auth.json in SEOlity → Settings → AI.');
  const outFile = join(tmp, `out-${job.id}.txt`);
  const input = (job.system ? `# Instructions\n${job.system}\n\n# Task\n` : '') + job.prompt + '\n\nReturn only the requested output. Do not run commands or edit files.';
  const args = ['exec', '--skip-git-repo-check', '--sandbox', 'read-only', '--ephemeral', '--json', '-o', outFile];
  if (job.model) args.push('-m', job.model);
  args.push('-');
  const env = { ...E, CODEX_HOME: codexHome };
  delete env.OPENAI_API_KEY; // never bill the API – use the ChatGPT plan
  delete env.CODEX_API_KEY;
  delete env.SEOLITY_SHARED_SECRET;
  delete env.CLAUDE_CODE_OAUTH_TOKEN;
  const r = await run(CODEX_BIN, args, input, env, ENGINE_TIMEOUT, tmp);
  if (r.killed) throw new Error('Codex timeout');
  const text = existsSync(outFile) ? (await readFile(outFile, 'utf8')).trim() : '';
  let usage = { input: 0, output: 0 };
  let errorMsg = '';
  for (const line of r.out.split('\n')) {
    if (!line.trim().startsWith('{')) continue;
    try {
      const ev = JSON.parse(line);
      const u = ev.usage || (ev.msg && ev.msg.usage) || (ev.info && ev.info.total_token_usage);
      if (u) usage = { input: u.input_tokens || usage.input, output: u.output_tokens || usage.output };
      if (ev.type === 'error' || ev.type === 'turn.failed') errorMsg = ev.message || (ev.error && ev.error.message) || errorMsg;
    } catch (_) { /* ignore */ }
  }
  if (!text) {
    const msg = (errorMsg || r.err || 'no output').slice(0, 500);
    throw Object.assign(new Error('Codex: ' + msg), { quota: isQuota(msg) });
  }
  return { text, usage, model: job.model || 'codex-default' };
}

/* ------------------------------ queue ------------------------------ */
async function sync() {
  await git(['fetch', '--quiet', 'origin', BRANCH]);
  await git(['reset', '--quiet', '--hard', `origin/${BRANCH}`]);
}

async function push(message) {
  await git(['add', '-A', 'jobs', 'results']).catch(() => git(['add', '-A']));
  const status = await git(['status', '--porcelain']);
  if (!status.trim()) return;
  await git(['commit', '--quiet', '-m', message]);
  for (let i = 0; i < 4; i++) {
    try {
      await git(['push', '--quiet', 'origin', `HEAD:${BRANCH}`]);
      return;
    } catch (e) {
      log('push rejected, rebasing:', e.message);
      await git(['pull', '--quiet', '--rebase', 'origin', BRANCH]);
    }
  }
  throw new Error('Could not push results after 4 attempts.');
}

async function pendingJobs() {
  const dir = join(WORK, 'jobs');
  if (!existsSync(dir)) return [];
  const names = (await readdir(dir)).filter((n) => /^[a-f0-9]{32}\.json$/.test(n)).sort();
  const out = [];
  for (const n of names) {
    const file = join(dir, n);
    try {
      const job = decrypt(JSON.parse(await readFile(file, 'utf8')));
      if (!ENGINES.includes(job.engine)) continue; // Another run (with that CLI installed) handles it.
      out.push({ file, job });
    } catch (e) {
      log(`cannot read ${n}: ${e.message} (wrong SEOLITY_SHARED_SECRET?)`);
    }
  }
  return out;
}

async function cleanupResults() {
  const dir = join(WORK, 'results');
  if (!existsSync(dir)) return 0;
  let removed = 0;
  for (const n of await readdir(dir)) {
    try {
      const r = decrypt(JSON.parse(await readFile(join(dir, n), 'utf8')));
      if (Date.now() - Date.parse(r.finished || 0) > RESULT_TTL_MS) { await unlink(join(dir, n)); removed++; }
    } catch (_) { await unlink(join(dir, n)).catch(() => {}); removed++; }
  }
  return removed;
}

async function processOne({ file, job }) {
  const t0 = Date.now();
  let result;
  try {
    const r = job.engine === 'codex' ? await askCodex(job) : await askClaude(job);
    result = { id: job.id, ok: true, text: r.text, usage: r.usage, model: r.model, ms: Date.now() - t0 };
    summary.push(`- ✅ ${job.task || 'task'} (${job.engine}, ${Math.round(result.ms / 1000)}s)`);
  } catch (e) {
    result = { id: job.id, ok: false, error: e.message, quota: !!e.quota, ms: Date.now() - t0 };
    summary.push(`- ❌ ${job.task || 'task'} (${job.engine}): ${e.message.slice(0, 160)}`);
  }
  result.finished = new Date().toISOString();
  const auth = await refreshedCodexAuth();
  if (auth) result.codex_auth = auth; // WordPress stores the refreshed ChatGPT login and updates the secret.
  const env = encrypt(result);
  await mkdir(join(WORK, 'results'), { recursive: true });
  await writeFile(join(WORK, 'results', `${job.id}.json`), JSON.stringify(env));
  await unlink(file).catch(() => {});
  return env;
}

/* ------------------------------ main ------------------------------ */
async function main() {
  if (!SECRET) throw new Error('Secret SEOLITY_SHARED_SECRET is missing. Run "Set up GitHub runner" again in SEOlity.');
  await prepare();
  await rm(WORK, { recursive: true, force: true });
  await git(['worktree', 'add', '--quiet', '-B', `seolity-work-${Date.now()}`, WORK, `origin/${BRANCH}`], process.cwd())
    .catch(async () => { await git(['fetch', '--quiet', 'origin', BRANCH], process.cwd()); await git(['worktree', 'add', '--quiet', '-B', `seolity-work-${Date.now()}`, WORK, `origin/${BRANCH}`], process.cwd()); });
  await git(['config', 'user.name', 'seolity-runner[bot]']);
  await git(['config', 'user.email', 'seolity-runner@users.noreply.github.com']);

  const started = Date.now();
  let idleSince = 0;
  let done = 0;
  log(`engines=${ENGINES.join(',')} branch=${BRANCH}`);
  while (Date.now() - started < BUDGET_MS) {
    await sync();
    const jobs = await pendingJobs();
    if (!jobs.length) {
      if (!idleSince) idleSince = Date.now();
      if (Date.now() - idleSince >= IDLE_MS) break;
      await new Promise((r) => setTimeout(r, 10000)); // Wait briefly for follow-up requests (e.g. a second AI step).
      continue;
    }
    idleSince = 0;
    for (const j of jobs) {
      if (Date.now() - started >= BUDGET_MS) break;
      const env = await processOne(j);
      done++;
      await push(`SEOlity: result ${j.job.id}`);
      await callback([env]);
    }
  }
  await sync();
  if (await cleanupResults()) await push('SEOlity: remove old results');
  summary.unshift(`### SEOlity subscription AI: ${done} request(s) processed`);
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  main()
    .catch((e) => {
      console.error('[seolity] ERROR:', e.message);
      summary.push('### Error: ' + e.message);
      process.exitCode = 1;
    })
    .finally(async () => {
      if (E.GITHUB_STEP_SUMMARY && summary.length) {
        try { await appendFile(E.GITHUB_STEP_SUMMARY, summary.join('\n') + '\n'); } catch (_) { /* ignore */ }
      }
      if (tmp) await rm(tmp, { recursive: true, force: true }).catch(() => {});
    });
}
