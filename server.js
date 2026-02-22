#!/usr/bin/env node
'use strict';

const WebSocket = require('ws');
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

const CONFIG_PATH = process.env.SHELL_RELAY_CONFIG || path.join(__dirname, 'config.json');
const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));

const PORT = parseInt(process.env.SHELL_RELAY_PORT || config.port || 8765, 10);
const HOST = process.env.SHELL_RELAY_HOST || config.host || '127.0.0.1';
const TOKEN = process.env.SHELL_RELAY_TOKEN || config.token;
const SHELL = process.env.SHELL_RELAY_SHELL || config.shell || '/bin/zsh';
const MAX_SESSIONS = config.maxSessions || 10;
const IDLE_TIMEOUT = config.idleTimeoutMs || 300000;
const WS_MAX_PAYLOAD = config.maxPayloadBytes || 16 * 1024;
const PER_IP_MAX_CONNECTIONS = config.rateLimit?.perIpMaxConnections || 5;
const CMD_WINDOW_MS = config.rateLimit?.commandWindowMs || 10000;
const CMD_MAX_PER_WINDOW = config.rateLimit?.commandMaxPerWindow || 10;
const OUTPUT_CAP_STDOUT = config.outputCaps?.stdoutBytes || 256 * 1024;
const OUTPUT_CAP_STDERR = config.outputCaps?.stderrBytes || 128 * 1024;
const FAILED_AUTH_WINDOW_MS = config.authThrottle?.windowMs || 10 * 60 * 1000;
const FAILED_AUTH_MAX = config.authThrottle?.maxFailures || 6;
const FAILED_AUTH_BAN_MS = config.authThrottle?.banMs || 15 * 60 * 1000;

if (!TOKEN || TOKEN.length < 32) {
  console.error('FATAL: Missing or weak SHELL_RELAY token');
  process.exit(1);
}

if (!config.tls?.enabled) {
  console.error('FATAL: TLS must be enabled for shell relay');
  process.exit(1);
}

if (!config.tls?.cert || !config.tls?.key) {
  console.error('FATAL: TLS cert/key paths are required');
  process.exit(1);
}

const sessions = new Map();
const ipConnections = new Map();
const failedAuth = new Map();

function now() {
  return Date.now();
}

function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function sanitizeIp(raw) {
  if (!raw) return 'unknown';
  if (raw.startsWith('::ffff:')) return raw.slice(7);
  return raw;
}

function safeMeta(meta = {}) {
  const out = { ...meta };
  if (out.command) delete out.command;
  if (out.token) delete out.token;
  return out;
}

function log(level, message, meta = {}) {
  const entry = {
    ts: new Date().toISOString(),
    level,
    message,
    ...safeMeta(meta)
  };

  const line = JSON.stringify(entry);
  console.log(line);

  if (config.logging?.file) {
    try {
      fs.appendFileSync(config.logging.file, line + '\n');
    } catch (_) {}
  }
}

function constantTimeTokenEqual(a, b) {
  const ab = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function isBanned(ip) {
  const rec = failedAuth.get(ip);
  if (!rec) return false;
  if (rec.bannedUntil && rec.bannedUntil > now()) return true;
  if (rec.bannedUntil && rec.bannedUntil <= now()) {
    rec.bannedUntil = 0;
    rec.failures = [];
    failedAuth.set(ip, rec);
  }
  return false;
}

function registerAuthFailure(ip) {
  const t = now();
  const rec = failedAuth.get(ip) || { failures: [], bannedUntil: 0 };
  rec.failures = rec.failures.filter((x) => t - x < FAILED_AUTH_WINDOW_MS);
  rec.failures.push(t);
  if (rec.failures.length >= FAILED_AUTH_MAX) {
    rec.bannedUntil = t + FAILED_AUTH_BAN_MS;
    rec.failures = [];
  }
  failedAuth.set(ip, rec);
}

function registerAuthSuccess(ip) {
  failedAuth.delete(ip);
}

function commandAllowed(command) {
  const cmd = String(command || '').trim();
  if (!cmd) return { allowed: false, reason: 'Empty command' };

  if (Array.isArray(config.commandAllowlist) && config.commandAllowlist.length > 0) {
    let anyAllowed = false;
    for (const pattern of config.commandAllowlist) {
      const re = new RegExp(pattern);
      if (re.test(cmd)) {
        anyAllowed = true;
        break;
      }
    }
    if (!anyAllowed) return { allowed: false, reason: 'Not allowlisted' };
  }

  if (Array.isArray(config.commandBlocklist) && config.commandBlocklist.length > 0) {
    for (const pattern of config.commandBlocklist) {
      const re = new RegExp(pattern);
      if (re.test(cmd)) return { allowed: false, reason: 'Blocked by policy' };
    }
  }

  return { allowed: true };
}

function makeHealthPayload() {
  return {
    ok: true,
    service: 'shell-relay',
    uptimeSec: Math.floor(process.uptime()),
    sessions: sessions.size,
    ts: new Date().toISOString()
  };
}

class ShellSession {
  constructor(ws, sessionId, clientIp) {
    this.ws = ws;
    this.sessionId = sessionId;
    this.clientIp = clientIp;
    this.proc = null;
    this.authenticated = false;
    this.lastActivity = now();
    this.cmdTimestamps = [];
  }

  send(msg) {
    if (this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }

  authenticate(token) {
    if (isBanned(this.clientIp)) {
      this.send({ type: 'auth_fail', reason: 'Temporarily banned' });
      log('warn', 'Auth rejected due to ban', { sessionId: this.sessionId, clientIp: this.clientIp });
      return false;
    }

    if (constantTimeTokenEqual(token, TOKEN)) {
      this.authenticated = true;
      registerAuthSuccess(this.clientIp);
      this.send({ type: 'auth_ok', sessionId: this.sessionId });
      log('info', 'Authenticated', { sessionId: this.sessionId, clientIp: this.clientIp });
      return true;
    }

    registerAuthFailure(this.clientIp);
    this.send({ type: 'auth_fail', reason: 'Invalid credentials' });
    log('warn', 'Auth failed', { sessionId: this.sessionId, clientIp: this.clientIp });
    return false;
  }

  commandRateAllowed() {
    const t = now();
    this.cmdTimestamps = this.cmdTimestamps.filter((x) => t - x < CMD_WINDOW_MS);
    if (this.cmdTimestamps.length >= CMD_MAX_PER_WINDOW) {
      return false;
    }
    this.cmdTimestamps.push(t);
    return true;
  }

  exec(command, id) {
    this.lastActivity = now();
    const cmdId = id || crypto.randomUUID();
    const cmd = String(command || '');

    if (!this.commandRateAllowed()) {
      this.send({ type: 'error', message: 'Command rate limit exceeded', id: cmdId });
      this.send({ type: 'exit', code: 1, id: cmdId });
      log('warn', 'Command rate-limited', { sessionId: this.sessionId, clientIp: this.clientIp });
      return;
    }

    const policy = commandAllowed(cmd);
    if (!policy.allowed) {
      this.send({ type: 'error', message: policy.reason, id: cmdId });
      this.send({ type: 'exit', code: 1, id: cmdId });
      log('warn', 'Command blocked', {
        sessionId: this.sessionId,
        clientIp: this.clientIp,
        commandHash: sha256(cmd),
        reason: policy.reason
      });
      return;
    }

    if (this.proc) {
      try { this.proc.kill('SIGKILL'); } catch (_) {}
      this.proc = null;
    }

    log('info', 'Exec start', {
      sessionId: this.sessionId,
      clientIp: this.clientIp,
      id: cmdId,
      commandHash: sha256(cmd),
      commandLen: cmd.length
    });

    this.proc = spawn(SHELL, ['-l', '-c', cmd], {
      cwd: process.env.HOME || '/Users/ben',
      env: { ...process.env, TERM: 'xterm-256color', SHELL_RELAY_SESSION: this.sessionId },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdoutSent = 0;
    let stderrSent = 0;
    let stdoutCapped = false;
    let stderrCapped = false;

    this.proc.stdout.on('data', (chunk) => {
      this.lastActivity = now();
      if (stdoutCapped) return;
      const data = Buffer.from(chunk);
      const remaining = OUTPUT_CAP_STDOUT - stdoutSent;
      if (remaining <= 0) {
        stdoutCapped = true;
        this.send({ type: 'stderr', data: '\n[relay] stdout output capped\n', id: cmdId });
        return;
      }
      const sendBuf = data.length > remaining ? data.subarray(0, remaining) : data;
      stdoutSent += sendBuf.length;
      this.send({ type: 'stdout', data: sendBuf.toString('utf8'), id: cmdId });
      if (data.length > remaining) {
        stdoutCapped = true;
        this.send({ type: 'stderr', data: '\n[relay] stdout output capped\n', id: cmdId });
      }
    });

    this.proc.stderr.on('data', (chunk) => {
      this.lastActivity = now();
      if (stderrCapped) return;
      const data = Buffer.from(chunk);
      const remaining = OUTPUT_CAP_STDERR - stderrSent;
      if (remaining <= 0) {
        stderrCapped = true;
        this.send({ type: 'stderr', data: '\n[relay] stderr output capped\n', id: cmdId });
        return;
      }
      const sendBuf = data.length > remaining ? data.subarray(0, remaining) : data;
      stderrSent += sendBuf.length;
      this.send({ type: 'stderr', data: sendBuf.toString('utf8'), id: cmdId });
      if (data.length > remaining) {
        stderrCapped = true;
        this.send({ type: 'stderr', data: '\n[relay] stderr output capped\n', id: cmdId });
      }
    });

    this.proc.on('close', (code) => {
      this.send({ type: 'exit', code: code ?? 1, id: cmdId });
      log('info', 'Exec exit', { sessionId: this.sessionId, id: cmdId, code: code ?? 1 });
      this.proc = null;
    });

    this.proc.on('error', (err) => {
      this.send({ type: 'error', message: 'Execution error', id: cmdId });
      this.send({ type: 'exit', code: 1, id: cmdId });
      log('error', 'Exec process error', { sessionId: this.sessionId, id: cmdId, err: err.message });
      this.proc = null;
    });
  }

  stdin(data) {
    this.lastActivity = now();
    if (this.proc?.stdin?.writable) {
      this.proc.stdin.write(String(data || ''));
    }
  }

  close() {
    if (this.proc) {
      try { this.proc.kill('SIGKILL'); } catch (_) {}
      this.proc = null;
    }
  }
}

const server = config.tls?.enabled
  ? https.createServer({
      cert: fs.readFileSync(config.tls.cert),
      key: fs.readFileSync(config.tls.key)
    }, (req, res) => {
      if (req.url === '/healthz') {
        const body = JSON.stringify(makeHealthPayload());
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(body);
        return;
      }
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'not_found' }));
    })
  : http.createServer((req, res) => {
      if (req.url === '/healthz') {
        const body = JSON.stringify(makeHealthPayload());
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(body);
        return;
      }
      res.writeHead(426, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'upgrade_required' }));
    });

const wss = new WebSocket.Server({ server, maxPayload: WS_MAX_PAYLOAD });

wss.on('connection', (ws, req) => {
  const clientIp = sanitizeIp(req.socket.remoteAddress);
  const currentIpCount = ipConnections.get(clientIp) || 0;

  if (sessions.size >= MAX_SESSIONS) {
    ws.send(JSON.stringify({ type: 'error', message: 'Max sessions reached' }));
    ws.close();
    log('warn', 'Connection rejected: max sessions', { clientIp });
    return;
  }

  if (currentIpCount >= PER_IP_MAX_CONNECTIONS) {
    ws.send(JSON.stringify({ type: 'error', message: 'Too many connections from this IP' }));
    ws.close();
    log('warn', 'Connection rejected: per-ip limit', { clientIp });
    return;
  }

  const sessionId = crypto.randomUUID();
  const session = new ShellSession(ws, sessionId, clientIp);
  sessions.set(sessionId, session);
  ipConnections.set(clientIp, currentIpCount + 1);

  log('info', 'Connected', { sessionId, clientIp });

  const idleCheck = setInterval(() => {
    if (now() - session.lastActivity > IDLE_TIMEOUT) {
      session.send({ type: 'error', message: 'Idle timeout' });
      ws.close();
    }
  }, 30000);

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch (_) {
      session.send({ type: 'error', message: 'Invalid JSON' });
      return;
    }

    if (!session.authenticated) {
      if (msg.type === 'auth') {
        if (!session.authenticate(msg.token)) {
          ws.close();
        }
      } else {
        session.send({ type: 'error', message: 'Not authenticated' });
      }
      return;
    }

    switch (msg.type) {
      case 'exec':
        session.exec(msg.command, msg.id);
        break;
      case 'stdin':
        session.stdin(msg.data);
        break;
      case 'ping':
        session.send({ type: 'pong', ts: msg.ts });
        session.lastActivity = now();
        break;
      default:
        session.send({ type: 'error', message: `Unknown type: ${msg.type}` });
    }
  });

  ws.on('close', () => {
    clearInterval(idleCheck);
    session.close();
    sessions.delete(sessionId);
    const count = ipConnections.get(clientIp) || 1;
    if (count <= 1) ipConnections.delete(clientIp);
    else ipConnections.set(clientIp, count - 1);
    log('info', 'Disconnected', { sessionId, clientIp });
  });

  ws.on('error', (err) => {
    log('error', 'WebSocket error', { sessionId, clientIp, err: err.message });
  });
});

function shutdown(signal) {
  log('info', 'Shutting down', { signal });
  for (const [, s] of sessions) {
    s.send({ type: 'error', message: 'Server shutting down' });
    s.close();
  }
  wss.close(() => server.close(() => process.exit(0)));
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', (err) => {
  log('error', 'uncaughtException', { err: err?.message || String(err) });
});
process.on('unhandledRejection', (reason) => {
  log('error', 'unhandledRejection', { reason: reason?.message || String(reason) });
});

server.listen(PORT, HOST, () => {
  log('info', 'Shell relay listening', { url: `wss://${HOST}:${PORT}` });
});
