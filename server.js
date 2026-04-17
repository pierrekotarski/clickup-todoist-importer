#!/usr/bin/env node
'use strict';

require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const express                             = require('express');
const cookieSession                       = require('cookie-session');
const https                               = require('https');
const http                                = require('http');
const crypto                              = require('crypto');
const { URL }                             = require('url');
const { TodoistApi, TodoistRequestError } = require('@doist/todoist-sdk');

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

const PORT     = process.env.PORT     || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const IS_PROD  = BASE_URL.startsWith('https');

// Fail loudly in production if required env vars are missing
const missing = ['SESSION_SECRET','CLICKUP_CLIENT_ID','CLICKUP_CLIENT_SECRET','TODOIST_CLIENT_ID','TODOIST_CLIENT_SECRET']
  .filter(k => !process.env[k]);
if (IS_PROD && missing.length) {
  console.error(`\n✗ Missing required env vars for production:\n  ${missing.join('\n  ')}\n`);
  process.exit(1);
}

const CLICKUP = {
  clientId:     process.env.CLICKUP_CLIENT_ID     || '',
  clientSecret: process.env.CLICKUP_CLIENT_SECRET || '',
  // ClickUp strips paths from registered redirect URIs — use base URL only
  redirectUri:  `${BASE_URL}`,
};
const TODOIST = {
  clientId:     process.env.TODOIST_CLIENT_ID     || '',
  clientSecret: process.env.TODOIST_CLIENT_SECRET || '',
  redirectUri:  `${BASE_URL}/auth/todoist/callback`,
  scope:        'data:read_write',
};

const app = express();

// ── Security headers ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (IS_PROD) res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  next();
});

// Trust the platform's reverse proxy (Render, Railway, Fly, Heroku all set X-Forwarded-Proto)
if (IS_PROD) app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// cookie-session: signed, stateless — no database or Redis needed.
// Tokens are stored in a tamper-proof signed cookie on the user's browser.
app.use(cookieSession({
  name:   'cu2td',
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  maxAge: 8 * 60 * 60 * 1000, // 8 hours
  secure: IS_PROD,
  httpOnly: true,
  sameSite: 'lax',
}));

// ─────────────────────────────────────────────────────────────────────────────
// HTTP utilities
// ─────────────────────────────────────────────────────────────────────────────

function httpRequest(options, body) {
  return new Promise((resolve, reject) => {
    const mod = (options.protocol || 'https:') === 'http:' ? http : https;
    const req = mod.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    if (body) req.write(Buffer.isBuffer(body) ? body : Buffer.from(body));
    req.end();
  });
}

async function httpJSON(options, body) {
  const res = await httpRequest(options, body);
  let data;
  try { data = JSON.parse(res.body.toString('utf8')); } catch { data = null; }
  if (res.statusCode >= 400) {
    const msg = data?.error || data?.message || data?.err || res.body.toString('utf8').slice(0, 300);
    const e = new Error(`HTTP ${res.statusCode}: ${msg}`);
    e.statusCode  = res.statusCode;
    e.retryAfter  = res.headers['retry-after'] ? parseInt(res.headers['retry-after'], 10) : null;
    throw e;
  }
  return data;
}

async function fetchBinary(urlStr, headers = {}, _hops = 0) {
  if (_hops > 5) throw new Error('Too many redirects fetching attachment');
  const u = new URL(urlStr);
  // Only allow https: (and http: for localhost dev) — prevent SSRF to internal services
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && u.hostname === 'localhost')) {
    throw new Error(`Blocked download from disallowed protocol: ${u.protocol}`);
  }
  const res = await httpRequest({ hostname: u.hostname, path: u.pathname + u.search, method: 'GET', headers, protocol: u.protocol });
  if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
    // On redirect, drop auth headers — S3 pre-signed URLs don't want them
    return fetchBinary(res.headers.location, {}, _hops + 1);
  }
  if (res.statusCode >= 400) throw new Error(`Download failed: HTTP ${res.statusCode}`);
  return { data: res.body, contentType: res.headers['content-type'] || 'application/octet-stream' };
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─────────────────────────────────────────────────────────────────────────────
// ClickUp API  (base: https://api.clickup.com/api/v2)
// ─────────────────────────────────────────────────────────────────────────────

async function cuGet(path, token) {
  const u = new URL(`https://api.clickup.com/api/v2${path}`);
  return httpJSON({ hostname: u.hostname, path: u.pathname + u.search, method: 'GET', headers: { Authorization: token } });
}

// Token exchange — ClickUp uses query params, not body
async function cuExchangeCode(code) {
  const path = `/api/v2/oauth/token?client_id=${encodeURIComponent(CLICKUP.clientId)}&client_secret=${encodeURIComponent(CLICKUP.clientSecret)}&code=${encodeURIComponent(code)}`;
  return httpJSON({ hostname: 'api.clickup.com', path, method: 'POST', headers: { 'Content-Length': '0' } });
}

async function cuGetTeams(token)                    { return cuGet('/team', token); }
async function cuGetSpaces(token, teamId)            { return cuGet(`/team/${teamId}/space`, token); }
async function cuGetFolders(token, spaceId)          { return cuGet(`/space/${spaceId}/folder?archived=false`, token); }
async function cuGetFolderLists(token, folderId)     { return cuGet(`/folder/${folderId}/list?archived=false`, token); }
async function cuGetFolderlessLists(token, spaceId)  { return cuGet(`/space/${spaceId}/list?archived=false`, token); }

async function cuGetTasksPage(token, listId, page, includeClosed) {
  return cuGet(`/list/${listId}/task?subtasks=true&include_closed=${includeClosed}&page=${page}`, token);
}

async function cuGetTask(token, taskId) {
  return cuGet(`/task/${taskId}`, token);
}

async function cuGetAllTasks(token, listId, includeClosed = true) {
  const all = [];
  let page = 0;
  while (true) {
    const data = await cuGetTasksPage(token, listId, page, includeClosed);
    const tasks = data.tasks || [];
    all.push(...tasks);
    if (tasks.length < 100) break;
    page++;
    await sleep(200);
  }
  return all;
}

// Build a full list tree for a workspace
async function cuGetListTree(token, teamId) {
  const spacesData = await cuGetSpaces(token, teamId);
  const spaces = spacesData.spaces || [];
  const tree = [];
  for (const space of spaces) {
    const spaceNode = { id: space.id, name: space.name, folders: [], lists: [] };
    const [foldersData, listsData] = await Promise.all([
      cuGetFolders(token, space.id),
      cuGetFolderlessLists(token, space.id),
    ]);
    for (const folder of (foldersData.folders || [])) {
      const folderNode = { id: folder.id, name: folder.name, lists: [] };
      const flData = await cuGetFolderLists(token, folder.id);
      folderNode.lists = (flData.lists || []).map(l => ({ id: l.id, name: l.name, taskCount: l.task_count }));
      spaceNode.folders.push(folderNode);
    }
    spaceNode.lists = (listsData.lists || []).map(l => ({ id: l.id, name: l.name, taskCount: l.task_count }));
    tree.push(spaceNode);
    await sleep(100); // gentle throttle
  }
  return tree;
}

// ─────────────────────────────────────────────────────────────────────────────
// Todoist API  (base: https://api.todoist.com/api/v1)
// ─────────────────────────────────────────────────────────────────────────────

async function tdExchangeCode(code) {
  const payload = JSON.stringify({ client_id: TODOIST.clientId, client_secret: TODOIST.clientSecret, code });
  return httpJSON({
    hostname: 'api.todoist.com', path: '/oauth/access_token', method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
  }, payload);
}

// ── Todoist SDK helpers ───────────────────────────────────────────────────────

function getTdApi(token) {
  return new TodoistApi(token);
}

async function tdGetProjects(token) {
  const api = getTdApi(token);
  const all = [];
  let cursor = undefined;
  do {
    const { results, nextCursor } = await api.getProjects(cursor ? { cursor } : {});
    all.push(...results);
    cursor = nextCursor;
  } while (cursor);
  return all;
}

async function tdCreateProj(token, name) {
  return getTdApi(token).addProject({ name });
}

function tdCreateTask(token, args) {
  return getTdApi(token).addTask(args);
}

function tdCreateComment(token, args) {
  return getTdApi(token).addComment(args);
}

function tdUploadFile(token, fileName, _mimeType, fileData) {
  // The SDK handles multipart encoding internally; mimeType is inferred by Todoist from content
  return getTdApi(token).uploadFile({ file: fileData, fileName });
}

// ─────────────────────────────────────────────────────────────────────────────
// Priority mapping
// ClickUp: urgent=1, high=2, normal=3, low=4
// Todoist:  p1=4,   p2=3,   p3=2,   p4=1
// ─────────────────────────────────────────────────────────────────────────────

function mapPriority(cu) {
  return ({ '1': 4, '2': 3, '3': 2, '4': 1 })[String(cu?.id ?? cu?.priority ?? '3')] ?? 1;
}
function fmtDate(ms) {
  if (!ms) return null;
  return new Date(parseInt(ms, 10)).toISOString().split('T')[0];
}

// ─────────────────────────────────────────────────────────────────────────────
// Import core
// ─────────────────────────────────────────────────────────────────────────────

async function importList(listId, projectId, opts, tokens, emit, abortRef) {
  const tasks = await cuGetAllTasks(tokens.clickup, listId, opts.includeClosed);
  const topLevel = tasks.filter(t => !t.parent);
  emit({ type: 'list_start', listId, total: tasks.length });

  async function importTask(task, parentTodoistId) {
    if (abortRef.aborted) return;
    const params = {
      content:   task.name,
      projectId: projectId,
      priority:  mapPriority(task.priority),
      ...(fmtDate(task.due_date) ? { dueDate: fmtDate(task.due_date) } : {}),
      ...(task.description        ? { description: task.description }  : {}),
      ...(parentTodoistId         ? { parentId: parentTodoistId }      : {}),
    };

    let todoistId;
    if (opts.dryRun) {
      todoistId = `dry-${task.id}`;
      emit({ type: 'task', status: 'dry_run', name: task.name });
    } else {
      let attempt = 0;
      while (true) {
        try {
          const created = await tdCreateTask(tokens.todoist, params);
          todoistId = created.id;
          emit({ type: 'task', status: 'created', name: task.name });
          break;
        } catch (err) {
          if (err instanceof TodoistRequestError && err.httpStatusCode === 429 && attempt < 4) {
            const wait = Math.pow(2, attempt) * 1000;
            emit({ type: 'log', message: `Rate limited — waiting ${wait / 1000}s…` });
            await sleep(wait);
            attempt++;
          } else {
            console.error(`[importTask] failed projectId=${projectId}:`, err.message);
            emit({ type: 'task', status: 'error', name: task.name, error: err.message });
            return;
          }
        }
      }
      await sleep(130);
    }

    // Attachments — bulk list endpoint omits attachment data, fetch full task to get them
    if (opts.includeAttachments) {
      let fullTask = task;
      try {
        fullTask = await cuGetTask(tokens.clickup, task.id);
      } catch (err) {
        emit({ type: 'log', message: `Could not fetch full task for "${task.name}": ${err.message}` });
      }
      for (const att of (fullTask.attachments || [])) {
        if (abortRef.aborted) break;
        if (opts.dryRun) {
          emit({ type: 'attachment', status: 'dry_run', taskName: task.name, fileName: att.title });
          continue;
        }
        try {
          emit({ type: 'attachment', status: 'downloading', taskName: task.name, fileName: att.title });
          const { data, contentType } = await fetchBinary(att.url, { Authorization: tokens.clickup });
          emit({ type: 'attachment', status: 'uploading', taskName: task.name, fileName: att.title });
          const upload = await tdUploadFile(tokens.todoist, att.title, att.mimetype || contentType, data);
          await tdCreateComment(tokens.todoist, {
            taskId:  todoistId,
            content: `📎 ${att.title}`,
            attachment: {
              resourceType: upload.resourceType || 'file',
              fileUrl:      upload.fileUrl,
              fileType:     upload.fileType || att.mimetype || contentType,
              fileName:     upload.fileName || att.title,
            },
          });
          emit({ type: 'attachment', status: 'done', taskName: task.name, fileName: att.title });
          await sleep(150);
        } catch (err) {
          emit({ type: 'attachment', status: 'error', taskName: task.name, fileName: att.title, error: err.message });
        }
      }
    }

    // Subtasks (ClickUp returns them flat with parent field)
    for (const sub of tasks.filter(t => t.parent === task.id)) {
      await importTask(sub, todoistId);
    }
  }

  for (const task of topLevel) {
    if (abortRef.aborted) break;
    await importTask(task, null);
  }
}

async function runImport(config, tokens, emit) {
  const abortRef = { aborted: false };
  const stats = { tasks: 0, taskErrors: 0, attachments: 0, attachmentErrors: 0 };

  function track(event) {
    if (event.type === 'task'       && event.status === 'created') stats.tasks++;
    if (event.type === 'task'       && event.status === 'error')   stats.taskErrors++;
    if (event.type === 'attachment' && event.status === 'done')    stats.attachments++;
    if (event.type === 'attachment' && event.status === 'error')   stats.attachmentErrors++;
    emit(event);
  }

  const mode     = config.projectMode || 'existing';
  const listMap  = config.listMap || {};

  // Resolve a single shared project for 'existing' and 'new' modes
  let sharedProjectId = config.projectId;

  if (mode === 'new') {
    if (!config.dryRun) {
      const proj = await tdCreateProj(tokens.todoist, config.newProjectName);
      sharedProjectId = proj.id;
      emit({ type: 'log', message: `Created Todoist project "${config.newProjectName}"` });
    } else {
      sharedProjectId = 'dry-project';
      emit({ type: 'log', message: `[DRY RUN] Would create project "${config.newProjectName}"` });
    }
  }

  for (const listId of config.listIds) {
    if (abortRef.aborted) break;

    let projectId = sharedProjectId;

    if (mode === 'per-list') {
      const listName = listMap[listId] || `ClickUp List ${listId}`;
      if (!config.dryRun) {
        try {
          const proj = await tdCreateProj(tokens.todoist, listName);
          projectId = proj.id;
          emit({ type: 'log', message: `Created Todoist project "${listName}"` });
        } catch (err) {
          emit({ type: 'task', status: 'error', name: `[Project] ${listName}`, error: `Could not create project: ${err.message}` });
          continue;
        }
      } else {
        projectId = `dry-${listId}`;
        emit({ type: 'log', message: `[DRY RUN] Would create project "${listName}"` });
      }
      await sleep(150);
    }

    await importList(listId, projectId, config, tokens, track, abortRef);
  }

  emit({ type: 'done', stats, dryRun: config.dryRun });
  return abortRef;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML (single-page app, all views inline)
// ─────────────────────────────────────────────────────────────────────────────

function renderPage(status) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ClickUp → Todoist Importer</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f3f4f6;color:#111827;min-height:100vh}
header{background:#fff;border-bottom:1px solid #e5e7eb;padding:0 24px;height:56px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:10}
.logo{font-size:16px;font-weight:600;color:#111827;display:flex;align-items:center;gap:8px}
.logo-sep{color:#9ca3af;font-weight:300}
main{max-width:760px;margin:0 auto;padding:40px 24px 80px}
h1{font-size:24px;font-weight:700;margin-bottom:8px}
.subtitle{color:#6b7280;margin-bottom:32px;font-size:15px}
.view{display:none}.view.active{display:block}

/* Cards */
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:24px;margin-bottom:16px}
.card-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
@media(max-width:520px){.card-grid{grid-template-columns:1fr}}
.service-card{background:#fff;border:2px solid #e5e7eb;border-radius:12px;padding:24px;text-align:center;transition:border-color .15s}
.service-card.connected{border-color:#22c55e}
.service-icon{font-size:32px;margin-bottom:12px}
.service-card h2{font-size:16px;font-weight:600;margin-bottom:6px}
.status-badge{display:inline-flex;align-items:center;gap:6px;font-size:13px;padding:4px 10px;border-radius:20px;margin-bottom:16px;font-weight:500}
.status-badge.connected{background:#dcfce7;color:#16a34a}
.status-badge.disconnected{background:#f3f4f6;color:#6b7280}

/* Buttons */
btn,button{cursor:pointer;border:none;border-radius:8px;font-size:14px;font-weight:500;padding:10px 18px;transition:opacity .15s}
.btn{display:inline-block;cursor:pointer;border:none;border-radius:8px;font-size:14px;font-weight:500;padding:10px 18px;transition:opacity .15s;text-decoration:none}
.btn-primary{background:#db4035;color:#fff}.btn-primary:hover{opacity:.88}
.btn-clickup{background:#7c4dff;color:#fff}.btn-clickup:hover{opacity:.88}
.btn-todoist{background:#db4035;color:#fff}.btn-todoist:hover{opacity:.88}
.btn-ghost{background:transparent;color:#6b7280;border:1px solid #e5e7eb}.btn-ghost:hover{background:#f9fafb}
.btn-danger{background:transparent;color:#dc2626;border:1px solid #fecaca;font-size:12px;padding:6px 12px}.btn-danger:hover{background:#fef2f2}
.btn-lg{padding:13px 28px;font-size:15px;width:100%}
button:disabled,.btn:disabled{opacity:.4;cursor:not-allowed}

/* Forms */
.form-section{margin-bottom:28px}
.form-section h2{font-size:15px;font-weight:600;color:#374151;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #f3f4f6}
label{display:block;font-size:13px;font-weight:500;color:#374151;margin-bottom:6px}
select,input[type=text]{width:100%;padding:9px 12px;border:1px solid #d1d5db;border-radius:8px;font-size:14px;color:#111827;background:#fff;outline:none}
select:focus,input[type=text]:focus{border-color:#7c4dff;box-shadow:0 0 0 3px rgba(124,77,255,.1)}
.input-group{display:flex;gap:8px;margin-top:8px}
.input-group input{flex:1}
.checkbox-row{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #f3f4f6;cursor:pointer}
.checkbox-row:last-child{border-bottom:none}
.checkbox-row input[type=checkbox]{width:16px;height:16px;accent-color:#7c4dff;cursor:pointer;flex-shrink:0}
.checkbox-row .label-text{font-size:14px;color:#374151}
.checkbox-row .label-hint{font-size:12px;color:#9ca3af;margin-top:1px}

/* List tree */
#list-tree{margin-top:12px;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;max-height:320px;overflow-y:auto}
.tree-loading{padding:20px;text-align:center;color:#9ca3af;font-size:14px}
.tree-space{border-bottom:1px solid #f3f4f6}
.tree-space:last-child{border-bottom:none}
.tree-space-header{display:flex;align-items:center;gap:8px;padding:10px 14px;background:#f9fafb;cursor:pointer;font-size:13px;font-weight:600;color:#374151}
.tree-space-header input[type=checkbox]{accent-color:#7c4dff}
.tree-space-body{padding:4px 0}
.tree-folder{padding:0 0 4px}
.tree-folder-name{padding:6px 14px 4px 28px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:#9ca3af}
.tree-list{display:flex;align-items:center;gap:8px;padding:6px 14px 6px 40px;cursor:pointer;transition:background .1s}
.tree-list:hover{background:#f9fafb}
.tree-list input[type=checkbox]{accent-color:#7c4dff;flex-shrink:0}
.tree-list-name{font-size:13px;color:#374151;flex:1}
.tree-list-count{font-size:11px;color:#9ca3af}

/* Project selector */
.project-or{text-align:center;color:#9ca3af;font-size:13px;margin:12px 0;position:relative}
.project-or::before{content:'';position:absolute;left:0;top:50%;width:100%;height:1px;background:#e5e7eb}
.project-or span{background:#fff;padding:0 8px;position:relative}
.radio-options{display:flex;flex-direction:column;gap:2px;margin-bottom:14px}
.radio-row{display:flex;align-items:flex-start;gap:10px;padding:10px 12px;border:1.5px solid #e5e7eb;border-radius:8px;cursor:pointer;transition:border-color .15s,background .15s}
.radio-row:has(input:checked){border-color:#7c4dff;background:#faf7ff}
.radio-row input[type=radio]{width:16px;height:16px;accent-color:#7c4dff;cursor:pointer;flex-shrink:0;margin-top:2px}
.radio-row .label-text{font-size:14px;color:#374151;font-weight:500}
.radio-row .label-hint{font-size:12px;color:#9ca3af;margin-top:2px}
.project-sub{margin-top:12px}

/* Progress */
.progress-bar-wrap{background:#e5e7eb;border-radius:99px;height:8px;margin-bottom:24px;overflow:hidden}
.progress-bar-fill{height:100%;background:linear-gradient(90deg,#7c4dff,#db4035);border-radius:99px;transition:width .3s;width:0%}
#progress-log{border:1px solid #e5e7eb;border-radius:8px;background:#fff;max-height:420px;overflow-y:auto;font-size:13px;font-family:'SF Mono',Menlo,monospace}
.log-entry{display:flex;align-items:flex-start;gap:10px;padding:8px 14px;border-bottom:1px solid #f3f4f6;animation:fadeIn .15s}
.log-entry:last-child{border-bottom:none}
@keyframes fadeIn{from{opacity:0;transform:translateY(-2px)}to{opacity:1;transform:translateY(0)}}
.log-icon{flex-shrink:0;width:16px;text-align:center;margin-top:1px}
.log-text{flex:1;color:#374151;line-height:1.45}
.log-text .sub{color:#9ca3af;font-size:11px;margin-top:2px}
.log-icon.ok{color:#16a34a}.log-icon.err{color:#dc2626}.log-icon.spin{color:#7c4dff;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.log-icon.info{color:#6b7280}

/* Summary */
.summary-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:24px}
.summary-stat{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px 20px}
.summary-stat .n{font-size:28px;font-weight:700;color:#111827}
.summary-stat .label{font-size:13px;color:#6b7280;margin-top:2px}
.summary-stat.error-stat .n{color:#dc2626}
.alert{border-radius:8px;padding:12px 16px;font-size:14px;margin-bottom:16px}
.alert-warning{background:#fef3c7;color:#92400e;border:1px solid #fde68a}
.alert-info{background:#eff6ff;color:#1e40af;border:1px solid #bfdbfe}

/* Misc */
.back-link{display:inline-flex;align-items:center;gap:6px;font-size:14px;color:#6b7280;margin-bottom:24px;cursor:pointer;background:none;border:none;padding:0}
.back-link:hover{color:#374151}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid #e5e7eb;border-top-color:#7c4dff;border-radius:50%;animation:spin .7s linear infinite}
</style>
</head>
<body>

<header>
  <div class="logo">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="20" height="20"><path fill="#4ac9f9" d="M8,15.044l-1.622,1.392l1.814,2.115C8.069,17.398,8.002,16.229,8,15.044z"/><path fill="#ff2bbe" d="M10.675,21.444l1.564,1.823l0.775-0.665c0,0,0-0.001,0-0.002l1.696-1.455l9.407-8.07 c0-0.001,0-0.002,0-0.003l0.038-0.032l1.862,1.59l4.574,3.904l5.511,4.706l0.391-0.458l1.325-1.552l1.354-1.586c0,0,0,0-0.001,0 l2.774-3.25l-5.015-4.282l-1.527-1.304l-1.522-1.299l0,0l-1.523-1.3l-1.523-1.3c0,0,0,0,0,0.001l-1.523-1.3l-1.521-1.3l0,0 l-1.523-1.301l-1.523-1.3l-0.603-0.515l-3.407,2.923l-3.444,2.955l-2.704,2.32l-2.359,2.024l-2.179,1.87l-3.671,3.15L10.675,21.444z"/><path fill="#4ac9f9" d="M27.073,36.625C26.088,36.866,25.06,37,24,37c-0.319,0-0.635-0.013-0.948-0.036 c-1.394-0.101-2.724-0.425-3.96-0.931c-1.378-0.564-2.639-1.354-3.732-2.331v0.001c-1.044-0.932-1.937-2.031-2.637-3.253 l-0.927,0.697l-5.491,4.132c1.292,2.023,2.926,3.804,4.811,5.277C11.045,39.712,11,38.861,11,38c0,0.861,0.045,1.712,0.116,2.555 c1.347,1.053,2.824,1.943,4.405,2.645c1.423,0.632,2.925,1.115,4.494,1.418C21.305,44.867,22.637,45,24,45 c0.137,0,0.271-0.011,0.407-0.014c1.44-0.028,2.843-0.2,4.197-0.505c-0.764-1.46-1.295-3.071-1.504-4.804 C26.975,38.642,26.975,37.622,27.073,36.625z"/><path fill="#4ac9f9" d="M38.867,32.398l-3.3-2.483c-0.934,1.824-2.286,3.397-3.929,4.596 c-1.348,0.984-2.893,1.709-4.564,2.115c-0.097,0.997-0.098,2.017,0.027,3.052c0.209,1.733,0.74,3.344,1.504,4.804 c1.343-0.302,2.636-0.732,3.867-1.279C33.7,42.658,34.865,42,35.955,41.24c2.445-1.706,4.516-3.912,6.054-6.478L38.867,32.398z"/><path fill="#e20caa" d="M6.378,16.436l1.814,2.115C8.069,17.398,8.002,16.229,8,15.044L6.378,16.436z"/><path fill="#ff2bbe" d="M12,15c0-1.214,0.083-2.409,0.228-3.584l-2.179,1.87l-2.048,1.758 c0.002,1.185,0.068,2.354,0.192,3.507l2.482,2.893l1.564,1.823l0.775-0.665C12.357,20.178,12,17.631,12,15z"/><path fill="#ff3da8" d="M17.291,7.072l-2.704,2.32l-2.359,2.024C12.083,12.591,12,13.786,12,15 c0,2.631,0.357,5.178,1.013,7.601l1.697-1.456l1.73-1.484C16.155,18.15,16,16.593,16,15C16,12.228,16.458,9.564,17.291,7.072z"/><path fill="#ff5190" d="M24.745,1.709l-0.603-0.515l-3.407,2.923l-3.444,2.955C16.458,9.564,16,12.228,16,15 c0,1.593,0.155,3.15,0.44,4.66l1.778-1.525l1.859-1.595C20.041,16.029,20,15.52,20,15C20,9.956,21.781,5.33,24.745,1.709z"/><path fill="#ff6d6e" d="M26.268,3.009l-1.523-1.3C21.781,5.33,20,9.956,20,15c0,0.52,0.041,1.029,0.078,1.54l1.928-1.654 l2.111-1.811c0.373-3.301,1.688-6.314,3.674-8.765L26.268,3.009z"/><path fill="#ff884d" d="M30.835,6.909l-1.523-1.3l-1.523-1.3c-1.986,2.451-3.301,5.464-3.674,8.765l0.04-0.034l1.862,1.59 l2.057,1.756C28.028,15.931,28,15.469,28,15C28,11.939,29.065,9.13,30.835,6.909z"/><path fill="#ff943f" d="M32,15c0-2.07,0.706-3.971,1.881-5.492l-1.523-1.3l-1.523-1.3C29.065,9.13,28,11.939,28,15 c0,0.469,0.028,0.931,0.076,1.387l2.515,2.147l5.511,4.706l0.391-0.458C33.809,21.224,32,18.326,32,15z"/><path fill="#ffa32d" d="M36,15c0-1.079,0.349-2.071,0.93-2.888l-1.527-1.304l-1.523-1.3C32.706,11.029,32,12.93,32,15 c0,3.326,1.809,6.224,4.493,7.782l1.325-1.552l1.354-1.586C37.317,18.912,36,17.114,36,15z"/><path fill="#ffc208" d="M36.93,12.112C36.349,12.929,36,13.921,36,15c0,2.114,1.317,3.912,3.171,4.644l2.774-3.25 L36.93,12.112z"/><g><path fill="#8638fd" d="M11.796,31.147l-5.491,4.132c1.292,2.023,2.926,3.804,4.811,5.277C11.045,39.712,11,38.861,11,38 C11,35.641,11.281,33.349,11.796,31.147z"/><path fill="#7b52fc" d="M15,38c0-1.465,0.127-2.899,0.36-4.297c-1.044-0.932-1.937-2.031-2.637-3.253l-0.927,0.697 C11.281,33.349,11,35.641,11,38c0,0.861,0.045,1.712,0.116,2.555c1.347,1.053,2.824,1.943,4.405,2.645C15.18,41.52,15,39.781,15,38z"/><path fill="#5b4aff" d="M15.521,43.2c1.423,0.632,2.925,1.115,4.494,1.418C19.357,42.529,19,40.306,19,38 c0-0.663,0.035-1.318,0.092-1.967c-1.378-0.564-2.639-1.354-3.732-2.331C15.127,35.101,15,36.535,15,38 C15,39.781,15.18,41.52,15.521,43.2z"/><path fill="#775dfc" d="M24.407,44.986C23.502,42.838,23,40.478,23,38c0-0.35,0.033-0.691,0.052-1.036 c-1.394-0.101-2.724-0.425-3.96-0.931C19.035,36.682,19,37.337,19,38c0,2.306,0.357,4.529,1.015,6.618 C21.305,44.867,22.637,45,24,45C24.137,45,24.271,44.989,24.407,44.986z"/><path fill="#716bfb" d="M24.407,44.986c1.44-0.028,2.843-0.2,4.197-0.505c-0.764-1.46-1.295-3.071-1.504-4.804 c-0.125-1.035-0.125-2.055-0.027-3.052C26.088,36.866,25.06,37,24,37c-0.319,0-0.635-0.013-0.948-0.036 C23.033,37.309,23,37.65,23,38C23,40.478,23.502,42.838,24.407,44.986z"/><path fill="#6094fa" d="M31,38c0-1.229,0.232-2.401,0.638-3.489c-1.348,0.984-2.893,1.709-4.564,2.115 c-0.097,0.997-0.098,2.017,0.027,3.052c0.209,1.733,0.74,3.344,1.504,4.804c1.343-0.302,2.636-0.732,3.867-1.279 C31.544,41.686,31,39.909,31,38z"/><path fill="#58a8fa" d="M32.472,43.203C33.7,42.658,34.865,42,35.955,41.24C35.353,40.305,35,39.195,35,38 c0-2.561,1.608-4.741,3.867-5.602l-3.3-2.483c-0.934,1.824-2.286,3.397-3.929,4.596C31.232,35.599,31,36.771,31,38 C31,39.909,31.544,41.686,32.472,43.203z"/><path fill="#4ac9f9" d="M42.009,34.762l-3.142-2.364C36.608,33.259,35,35.439,35,38c0,1.195,0.353,2.305,0.955,3.24 C38.4,39.534,40.471,37.328,42.009,34.762z"/></g></svg>
    ClickUp
    <span class="logo-sep">→</span>
    <svg width="20" height="20" viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" fill-rule="evenodd" clip-rule="evenodd" stroke-linejoin="round" stroke-miterlimit="2"><path d="M68.5 6h375C477.875 6 506 34.125 506 68.5v375c0 34.374-28.125 62.5-62.5 62.5h-375C34.125 506 6 477.873 6 443.5v-83.97l.881.513c21.325 12.419 71.75 41.781 84.1 48.756 7.475 4.22 14.625 4.113 21.831-.037 4.313-2.488 51.594-29.7 99.375-57.194l.232-.131.95-.55c49.712-28.606 99.58-57.306 101.787-58.581 4.331-2.5 4.55-10.169-.3-12.938l-3.4-1.937-.025-.019c-4.944-2.813-11.337-6.45-14.062-8.05-3.488-2.031-9.763-3.163-15.588.187-2.412 1.394-164.081 94.35-169.481 97.425-6.469 3.675-14.475 3.725-20.919-.006-5.094-2.95-85.381-49.6-85.381-49.6v-42.087l.887.518c21.325 12.42 71.744 41.782 84.094 48.75 7.475 4.22 14.625 4.12 21.831-.037 4.32-2.488 51.663-29.731 99.475-57.25l.382-.219.293-.169.17-.1c49.787-28.65 99.812-57.443 102.024-58.712 4.331-2.5 4.55-10.175-.3-12.944l-3.4-1.937c-4.944-2.813-11.356-6.469-14.087-8.069-3.488-2.031-9.763-3.162-15.588.188-2.412 1.393-164.081 94.35-169.481 97.424-6.469 3.675-14.475 3.725-20.919-.006C86.287 279.774 6 233.118 6 233.118v-42.081l.875.513c21.319 12.412 71.756 41.78 84.106 48.756 7.475 4.219 14.625 4.119 21.831-.038l99.594-57.318.125-.07c49.988-28.768 100.406-57.787 102.625-59.062 4.331-2.506 4.55-10.175-.3-12.943l-3.4-1.938c-4.944-2.812-11.356-6.469-14.087-8.062-3.488-2.038-9.763-3.17-15.588.18-2.412 1.395-164.081 94.357-169.481 97.426-6.469 3.675-14.475 3.725-20.919-.006C86.287 195.53 6 148.875 6 148.875V68.5C6 34.125 34.125 6 68.5 6z" fill="#e44232"/><path d="M112.812 240.262c4.32-2.487 51.738-29.775 99.594-57.312l.125-.075c49.988-28.77 100.406-57.782 102.625-59.063 4.331-2.5 4.55-10.175-.3-12.937l-3.4-1.938c-4.944-2.819-11.356-6.469-14.087-8.069-3.488-2.037-9.763-3.168-15.582.188-2.418 1.394-164.087 94.35-169.487 97.419-6.469 3.68-14.475 3.725-20.919-.007C86.287 195.525 6 148.868 6 148.868v42.169l.875.506c21.319 12.413 71.756 41.788 84.106 48.757 7.475 4.225 14.625 4.118 21.831-.038z" fill="#fff" fill-rule="nonzero"/><path d="M112.812 324.512c4.32-2.488 51.663-29.738 99.475-57.25l.382-.219c49.943-28.743 100.268-57.706 102.487-58.987 4.331-2.5 4.55-10.169-.3-12.938l-3.4-1.937c-4.944-2.813-11.356-6.469-14.087-8.069-3.488-2.031-9.763-3.162-15.582.188-2.418 1.393-164.087 94.35-169.487 97.424-6.469 3.675-14.475 3.725-20.919-.006-5.094-2.95-85.381-49.6-85.381-49.6v42.163l.887.518c21.325 12.42 71.744 41.775 84.094 48.75 7.475 4.22 14.625 4.113 21.831-.037z" fill="#fff" fill-rule="nonzero"/><path d="M212.419 351.43a354703.563 354703.563 0 00-99.607 57.326c-7.206 4.15-14.356 4.256-21.83.037-12.35-6.975-62.776-36.337-84.1-48.756L6 359.524v-42.168s80.287 46.656 85.381 49.6c6.444 3.731 14.45 3.687 20.919.006 5.4-3.069 167.069-96.025 169.487-97.419 5.82-3.356 12.094-2.225 15.582-.187 2.73 1.6 9.143 5.25 14.087 8.068 1.256.713 2.419 1.375 3.4 1.938 4.85 2.762 4.631 10.437.3 12.937-2.219 1.282-52.712 30.338-102.737 59.132z" fill="#fff" fill-rule="nonzero"/></svg>
    Todoist
  </div>
</header>

<main>

<!-- ── View: Connect ──────────────────────────────────────────────────────── -->
<div id="view-connect" class="view">
  <h1>Import from ClickUp to Todoist</h1>
  <p class="subtitle">Connect both accounts to get started. Your tasks, subtasks, and attachments will be brought over automatically.</p>

  <div class="card-grid">
    <div class="service-card ${status.clickup ? 'connected' : ''}" id="card-clickup">
      <div class="service-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="48" height="48"><path fill="#4ac9f9" d="M8,15.044l-1.622,1.392l1.814,2.115C8.069,17.398,8.002,16.229,8,15.044z"/><path fill="#ff2bbe" d="M10.675,21.444l1.564,1.823l0.775-0.665c0,0,0-0.001,0-0.002l1.696-1.455l9.407-8.07 c0-0.001,0-0.002,0-0.003l0.038-0.032l1.862,1.59l4.574,3.904l5.511,4.706l0.391-0.458l1.325-1.552l1.354-1.586c0,0,0,0-0.001,0 l2.774-3.25l-5.015-4.282l-1.527-1.304l-1.522-1.299l0,0l-1.523-1.3l-1.523-1.3c0,0,0,0,0,0.001l-1.523-1.3l-1.521-1.3l0,0 l-1.523-1.301l-1.523-1.3l-0.603-0.515l-3.407,2.923l-3.444,2.955l-2.704,2.32l-2.359,2.024l-2.179,1.87l-3.671,3.15L10.675,21.444z"/><path fill="#4ac9f9" d="M27.073,36.625C26.088,36.866,25.06,37,24,37c-0.319,0-0.635-0.013-0.948-0.036 c-1.394-0.101-2.724-0.425-3.96-0.931c-1.378-0.564-2.639-1.354-3.732-2.331v0.001c-1.044-0.932-1.937-2.031-2.637-3.253 l-0.927,0.697l-5.491,4.132c1.292,2.023,2.926,3.804,4.811,5.277C11.045,39.712,11,38.861,11,38c0,0.861,0.045,1.712,0.116,2.555 c1.347,1.053,2.824,1.943,4.405,2.645c1.423,0.632,2.925,1.115,4.494,1.418C21.305,44.867,22.637,45,24,45 c0.137,0,0.271-0.011,0.407-0.014c1.44-0.028,2.843-0.2,4.197-0.505c-0.764-1.46-1.295-3.071-1.504-4.804 C26.975,38.642,26.975,37.622,27.073,36.625z"/><path fill="#4ac9f9" d="M38.867,32.398l-3.3-2.483c-0.934,1.824-2.286,3.397-3.929,4.596 c-1.348,0.984-2.893,1.709-4.564,2.115c-0.097,0.997-0.098,2.017,0.027,3.052c0.209,1.733,0.74,3.344,1.504,4.804 c1.343-0.302,2.636-0.732,3.867-1.279C33.7,42.658,34.865,42,35.955,41.24c2.445-1.706,4.516-3.912,6.054-6.478L38.867,32.398z"/><path fill="#e20caa" d="M6.378,16.436l1.814,2.115C8.069,17.398,8.002,16.229,8,15.044L6.378,16.436z"/><path fill="#ff2bbe" d="M12,15c0-1.214,0.083-2.409,0.228-3.584l-2.179,1.87l-2.048,1.758 c0.002,1.185,0.068,2.354,0.192,3.507l2.482,2.893l1.564,1.823l0.775-0.665C12.357,20.178,12,17.631,12,15z"/><path fill="#ff3da8" d="M17.291,7.072l-2.704,2.32l-2.359,2.024C12.083,12.591,12,13.786,12,15 c0,2.631,0.357,5.178,1.013,7.601l1.697-1.456l1.73-1.484C16.155,18.15,16,16.593,16,15C16,12.228,16.458,9.564,17.291,7.072z"/><path fill="#ff5190" d="M24.745,1.709l-0.603-0.515l-3.407,2.923l-3.444,2.955C16.458,9.564,16,12.228,16,15 c0,1.593,0.155,3.15,0.44,4.66l1.778-1.525l1.859-1.595C20.041,16.029,20,15.52,20,15C20,9.956,21.781,5.33,24.745,1.709z"/><path fill="#ff6d6e" d="M26.268,3.009l-1.523-1.3C21.781,5.33,20,9.956,20,15c0,0.52,0.041,1.029,0.078,1.54l1.928-1.654 l2.111-1.811c0.373-3.301,1.688-6.314,3.674-8.765L26.268,3.009z"/><path fill="#ff884d" d="M30.835,6.909l-1.523-1.3l-1.523-1.3c-1.986,2.451-3.301,5.464-3.674,8.765l0.04-0.034l1.862,1.59 l2.057,1.756C28.028,15.931,28,15.469,28,15C28,11.939,29.065,9.13,30.835,6.909z"/><path fill="#ff943f" d="M32,15c0-2.07,0.706-3.971,1.881-5.492l-1.523-1.3l-1.523-1.3C29.065,9.13,28,11.939,28,15 c0,0.469,0.028,0.931,0.076,1.387l2.515,2.147l5.511,4.706l0.391-0.458C33.809,21.224,32,18.326,32,15z"/><path fill="#ffa32d" d="M36,15c0-1.079,0.349-2.071,0.93-2.888l-1.527-1.304l-1.523-1.3C32.706,11.029,32,12.93,32,15 c0,3.326,1.809,6.224,4.493,7.782l1.325-1.552l1.354-1.586C37.317,18.912,36,17.114,36,15z"/><path fill="#ffc208" d="M36.93,12.112C36.349,12.929,36,13.921,36,15c0,2.114,1.317,3.912,3.171,4.644l2.774-3.25 L36.93,12.112z"/><g><path fill="#8638fd" d="M11.796,31.147l-5.491,4.132c1.292,2.023,2.926,3.804,4.811,5.277C11.045,39.712,11,38.861,11,38 C11,35.641,11.281,33.349,11.796,31.147z"/><path fill="#7b52fc" d="M15,38c0-1.465,0.127-2.899,0.36-4.297c-1.044-0.932-1.937-2.031-2.637-3.253l-0.927,0.697 C11.281,33.349,11,35.641,11,38c0,0.861,0.045,1.712,0.116,2.555c1.347,1.053,2.824,1.943,4.405,2.645C15.18,41.52,15,39.781,15,38z"/><path fill="#5b4aff" d="M15.521,43.2c1.423,0.632,2.925,1.115,4.494,1.418C19.357,42.529,19,40.306,19,38 c0-0.663,0.035-1.318,0.092-1.967c-1.378-0.564-2.639-1.354-3.732-2.331C15.127,35.101,15,36.535,15,38 C15,39.781,15.18,41.52,15.521,43.2z"/><path fill="#775dfc" d="M24.407,44.986C23.502,42.838,23,40.478,23,38c0-0.35,0.033-0.691,0.052-1.036 c-1.394-0.101-2.724-0.425-3.96-0.931C19.035,36.682,19,37.337,19,38c0,2.306,0.357,4.529,1.015,6.618 C21.305,44.867,22.637,45,24,45C24.137,45,24.271,44.989,24.407,44.986z"/><path fill="#716bfb" d="M24.407,44.986c1.44-0.028,2.843-0.2,4.197-0.505c-0.764-1.46-1.295-3.071-1.504-4.804 c-0.125-1.035-0.125-2.055-0.027-3.052C26.088,36.866,25.06,37,24,37c-0.319,0-0.635-0.013-0.948-0.036 C23.033,37.309,23,37.65,23,38C23,40.478,23.502,42.838,24.407,44.986z"/><path fill="#6094fa" d="M31,38c0-1.229,0.232-2.401,0.638-3.489c-1.348,0.984-2.893,1.709-4.564,2.115 c-0.097,0.997-0.098,2.017,0.027,3.052c0.209,1.733,0.74,3.344,1.504,4.804c1.343-0.302,2.636-0.732,3.867-1.279 C31.544,41.686,31,39.909,31,38z"/><path fill="#58a8fa" d="M32.472,43.203C33.7,42.658,34.865,42,35.955,41.24C35.353,40.305,35,39.195,35,38 c0-2.561,1.608-4.741,3.867-5.602l-3.3-2.483c-0.934,1.824-2.286,3.397-3.929,4.596C31.232,35.599,31,36.771,31,38 C31,39.909,31.544,41.686,32.472,43.203z"/><path fill="#4ac9f9" d="M42.009,34.762l-3.142-2.364C36.608,33.259,35,35.439,35,38c0,1.195,0.353,2.305,0.955,3.24 C38.4,39.534,40.471,37.328,42.009,34.762z"/></g></svg></div>
      <h2>ClickUp</h2>
      ${status.clickup
        ? `<span class="status-badge connected">✓ Connected</span><br>
           <button class="btn btn-danger" onclick="disconnect('clickup')">Disconnect</button>`
        : `<span class="status-badge disconnected">Not connected</span><br>
           <button class="btn btn-clickup" onclick="location.href='/auth/clickup'">Connect ClickUp</button>`}
    </div>
    <div class="service-card ${status.todoist ? 'connected' : ''}" id="card-todoist">
      <div class="service-icon"><svg width="48" height="48" viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" fill-rule="evenodd" clip-rule="evenodd" stroke-linejoin="round" stroke-miterlimit="2"><path d="M68.5 6h375C477.875 6 506 34.125 506 68.5v375c0 34.374-28.125 62.5-62.5 62.5h-375C34.125 506 6 477.873 6 443.5v-83.97l.881.513c21.325 12.419 71.75 41.781 84.1 48.756 7.475 4.22 14.625 4.113 21.831-.037 4.313-2.488 51.594-29.7 99.375-57.194l.232-.131.95-.55c49.712-28.606 99.58-57.306 101.787-58.581 4.331-2.5 4.55-10.169-.3-12.938l-3.4-1.937-.025-.019c-4.944-2.813-11.337-6.45-14.062-8.05-3.488-2.031-9.763-3.163-15.588.187-2.412 1.394-164.081 94.35-169.481 97.425-6.469 3.675-14.475 3.725-20.919-.006-5.094-2.95-85.381-49.6-85.381-49.6v-42.087l.887.518c21.325 12.42 71.744 41.782 84.094 48.75 7.475 4.22 14.625 4.12 21.831-.037 4.32-2.488 51.663-29.731 99.475-57.25l.382-.219.293-.169.17-.1c49.787-28.65 99.812-57.443 102.024-58.712 4.331-2.5 4.55-10.175-.3-12.944l-3.4-1.937c-4.944-2.813-11.356-6.469-14.087-8.069-3.488-2.031-9.763-3.162-15.588.188-2.412 1.393-164.081 94.35-169.481 97.424-6.469 3.675-14.475 3.725-20.919-.006C86.287 279.774 6 233.118 6 233.118v-42.081l.875.513c21.319 12.412 71.756 41.78 84.106 48.756 7.475 4.219 14.625 4.119 21.831-.038l99.594-57.318.125-.07c49.988-28.768 100.406-57.787 102.625-59.062 4.331-2.506 4.55-10.175-.3-12.943l-3.4-1.938c-4.944-2.812-11.356-6.469-14.087-8.062-3.488-2.038-9.763-3.17-15.588.18-2.412 1.395-164.081 94.357-169.481 97.426-6.469 3.675-14.475 3.725-20.919-.006C86.287 195.53 6 148.875 6 148.875V68.5C6 34.125 34.125 6 68.5 6z" fill="#e44232"/><path d="M112.812 240.262c4.32-2.487 51.738-29.775 99.594-57.312l.125-.075c49.988-28.77 100.406-57.782 102.625-59.063 4.331-2.5 4.55-10.175-.3-12.937l-3.4-1.938c-4.944-2.819-11.356-6.469-14.087-8.069-3.488-2.037-9.763-3.168-15.582.188-2.418 1.394-164.087 94.35-169.487 97.419-6.469 3.68-14.475 3.725-20.919-.007C86.287 195.525 6 148.868 6 148.868v42.169l.875.506c21.319 12.413 71.756 41.788 84.106 48.757 7.475 4.225 14.625 4.118 21.831-.038z" fill="#fff" fill-rule="nonzero"/><path d="M112.812 324.512c4.32-2.488 51.663-29.738 99.475-57.25l.382-.219c49.943-28.743 100.268-57.706 102.487-58.987 4.331-2.5 4.55-10.169-.3-12.938l-3.4-1.937c-4.944-2.813-11.356-6.469-14.087-8.069-3.488-2.031-9.763-3.162-15.582.188-2.418 1.393-164.087 94.35-169.487 97.424-6.469 3.675-14.475 3.725-20.919-.006-5.094-2.95-85.381-49.6-85.381-49.6v42.163l.887.518c21.325 12.42 71.744 41.775 84.094 48.75 7.475 4.22 14.625 4.113 21.831-.037z" fill="#fff" fill-rule="nonzero"/><path d="M212.419 351.43a354703.563 354703.563 0 00-99.607 57.326c-7.206 4.15-14.356 4.256-21.83.037-12.35-6.975-62.776-36.337-84.1-48.756L6 359.524v-42.168s80.287 46.656 85.381 49.6c6.444 3.731 14.45 3.687 20.919.006 5.4-3.069 167.069-96.025 169.487-97.419 5.82-3.356 12.094-2.225 15.582-.187 2.73 1.6 9.143 5.25 14.087 8.068 1.256.713 2.419 1.375 3.4 1.938 4.85 2.762 4.631 10.437.3 12.937-2.219 1.282-52.712 30.338-102.737 59.132z" fill="#fff" fill-rule="nonzero"/></svg></div>
      <h2>Todoist</h2>
      ${status.todoist
        ? `<span class="status-badge connected">✓ Connected</span><br>
           <button class="btn btn-danger" onclick="disconnect('todoist')">Disconnect</button>`
        : `<span class="status-badge disconnected">Not connected</span><br>
           <button class="btn btn-todoist" onclick="location.href='/auth/todoist'">Connect Todoist</button>`}
    </div>
  </div>

  <button class="btn btn-primary btn-lg" id="btn-configure" onclick="showView('configure')" ${(!status.clickup || !status.todoist) ? 'disabled' : ''}>
    Configure Import →
  </button>
</div>

<!-- ── View: Configure ───────────────────────────────────────────────────── -->
<div id="view-configure" class="view">
  <button class="back-link" onclick="showView('connect')">← Back</button>
  <h1>Configure Import</h1>
  <p class="subtitle">Choose which ClickUp lists to import and where they should land in Todoist.</p>

  <div class="card">
    <div class="form-section">
      <h2>From ClickUp</h2>
      <label>Workspace</label>
      <select id="workspace-select" onchange="loadLists(this.value)">
        <option value="">Loading workspaces…</option>
      </select>
      <div id="list-tree"><div class="tree-loading">Select a workspace to browse lists</div></div>
    </div>

    <div class="form-section">
      <h2>To Todoist</h2>
      <div class="radio-options">
        <label class="radio-row">
          <input type="radio" name="project-mode" value="existing" checked onchange="onProjectModeChange()">
          <span>
            <div class="label-text">Use an existing project</div>
            <div class="label-hint">Import all selected lists into one Todoist project</div>
          </span>
        </label>
        <label class="radio-row">
          <input type="radio" name="project-mode" value="new" onchange="onProjectModeChange()">
          <span>
            <div class="label-text">Create a new project</div>
            <div class="label-hint">Import all selected lists into a single new project</div>
          </span>
        </label>
        <label class="radio-row">
          <input type="radio" name="project-mode" value="per-list" onchange="onProjectModeChange()">
          <span>
            <div class="label-text">One project per ClickUp list</div>
            <div class="label-hint">Each selected list becomes its own Todoist project</div>
          </span>
        </label>
      </div>
      <div class="project-sub" id="sub-existing">
        <label>Destination project</label>
        <select id="project-select">
          <option value="">Loading projects…</option>
        </select>
      </div>
      <div class="project-sub" id="sub-new" style="display:none">
        <label>New project name</label>
        <input type="text" id="new-project-name" placeholder="e.g. Imported from ClickUp" />
      </div>
      <div class="project-sub" id="sub-per-list" style="display:none">
        <div class="alert alert-info" style="margin:0">Each selected list will be created as a separate project in Todoist, named after the list.</div>
      </div>
    </div>

    <div class="form-section">
      <h2>Options</h2>
      <label class="checkbox-row">
        <input type="checkbox" id="opt-attachments" checked>
        <span><span class="label-text">Include attachments</span><div class="label-hint">Downloads files from ClickUp and re-uploads them to Todoist</div></span>
      </label>
      <label class="checkbox-row">
        <input type="checkbox" id="opt-closed" checked>
        <span><span class="label-text">Include completed tasks</span><div class="label-hint">Imports tasks in all statuses, not just open ones</div></span>
      </label>
      <label class="checkbox-row">
        <input type="checkbox" id="opt-dryrun">
        <span><span class="label-text">Dry run</span><div class="label-hint">Preview what would be imported without making any changes</div></span>
      </label>
    </div>

    <button class="btn btn-primary btn-lg" id="btn-start" onclick="startImport()">Start Import →</button>
  </div>
</div>

<!-- ── View: Progress ────────────────────────────────────────────────────── -->
<div id="view-progress" class="view">
  <h1 id="progress-title">Importing…</h1>
  <p class="subtitle" id="progress-subtitle">Please keep this tab open.</p>
  <div class="progress-bar-wrap"><div class="progress-bar-fill" id="progress-bar"></div></div>
</div>

<!-- ── View: Done ────────────────────────────────────────────────────────── -->
<div id="view-done" class="view">
  <h1 id="done-title">Import complete ✓</h1>
  <p class="subtitle" id="done-subtitle"></p>
  <div class="summary-grid" id="summary-grid"></div>
  <div id="done-alerts"></div>
  <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
    <button class="btn btn-primary" onclick="showView('configure')">Import more lists</button>
    <a class="btn btn-todoist" href="https://www.todoist.com" target="_blank" rel="noopener noreferrer">Open Todoist</a>
    <button class="btn btn-ghost" id="btn-toggle-log" onclick="toggleLog()">Show log ▾</button>
  </div>
</div>

<!-- ── Persistent log (shared between progress + done views) ─────────────── -->
<div id="progress-log" style="margin-top:16px;display:none"></div>

</main>

<script>
// ── State ───────────────────────────────────────────────────────────────────
const state = {
  workspaces: [],
  listTree: [],
  projects: [],
  selectedLists: new Set(),
  progressTotal: 0,
  progressDone: 0,
};

// ── Views ───────────────────────────────────────────────────────────────────
function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById('view-' + name).classList.add('active');
  if (name === 'configure' && state.workspaces.length === 0) loadWorkspaces();
}

// Show the right initial view
window.addEventListener('DOMContentLoaded', () => {
  const connected = ${JSON.stringify({ clickup: status.clickup, todoist: status.todoist })};
  if (connected.clickup && connected.todoist) {
    showView('connect'); // stay on connect so user can review then click Configure
  } else {
    showView('connect');
  }
  // Auto-advance if returning from OAuth and both are now connected
  const params = new URLSearchParams(location.search);
  if (params.get('auth') === 'done' && connected.clickup && connected.todoist) {
    // Small delay so the user sees the connected state
    setTimeout(() => showView('configure'), 600);
  }
  history.replaceState({}, '', '/');
});

// ── OAuth disconnect ────────────────────────────────────────────────────────
async function disconnect(service) {
  await fetch('/auth/disconnect/' + service, { method: 'POST' });
  location.reload();
}

// ── Load workspaces ─────────────────────────────────────────────────────────
async function loadWorkspaces() {
  const sel = document.getElementById('workspace-select');
  sel.innerHTML = '<option>Loading…</option>';
  try {
    const data = await fetch('/api/workspaces').then(r => r.json());
    state.workspaces = data;
    sel.innerHTML = data.map(w => \`<option value="\${w.id}">\${esc(w.name)}</option>\`).join('');
    if (data.length > 0) loadLists(data[0].id);
  } catch (e) {
    sel.innerHTML = '<option>Failed to load workspaces</option>';
  }
}

// ── Load list tree for workspace ────────────────────────────────────────────
async function loadLists(workspaceId) {
  if (!workspaceId) return;
  const tree = document.getElementById('list-tree');
  tree.innerHTML = '<div class="tree-loading"><span class="spinner"></span> Loading lists…</div>';
  try {
    const data = await fetch('/api/lists?workspace_id=' + workspaceId).then(r => r.json());
    state.listTree = data;
    state.selectedLists.clear();
    renderListTree(data, tree);
    loadProjects();
  } catch (e) {
    tree.innerHTML = '<div class="tree-loading">Failed to load lists</div>';
  }
}

function renderListTree(spaces, container) {
  if (!spaces.length) { container.innerHTML = '<div class="tree-loading">No lists found</div>'; return; }
  container.innerHTML = spaces.map(space => \`
    <div class="tree-space">
      <div class="tree-space-header" onclick="toggleSpace('\${space.id}')">
        <input type="checkbox" id="space-\${space.id}" onclick="checkSpace(event, '\${space.id}')">
        <span>\${esc(space.name)}</span>
      </div>
      <div class="tree-space-body" id="body-\${space.id}">
        \${space.lists.map(l => listRow(l, 14)).join('')}
        \${space.folders.map(f => \`
          <div class="tree-folder">
            <div class="tree-folder-name">\${esc(f.name)}</div>
            \${f.lists.map(l => listRow(l, 40)).join('')}
          </div>
        \`).join('')}
      </div>
    </div>
  \`).join('');
}

function listRow(list, indent) {
  return \`<label class="tree-list" style="padding-left:\${indent}px">
    <input type="checkbox" data-listid="\${list.id}" onchange="toggleList('\${list.id}', this.checked)">
    <span class="tree-list-name">\${esc(list.name)}</span>
    <span class="tree-list-count">\${list.taskCount ?? ''}</span>
  </label>\`;
}

function toggleList(id, checked) {
  if (checked) state.selectedLists.add(id); else state.selectedLists.delete(id);
  updateSpaceCheckboxes();
}

function checkSpace(e, spaceId) {
  e.stopPropagation();
  const checked = e.target.checked;
  document.querySelectorAll(\`#body-\${spaceId} input[data-listid]\`).forEach(cb => {
    cb.checked = checked;
    toggleList(cb.dataset.listid, checked);
  });
}

function toggleSpace(spaceId) {
  const body = document.getElementById('body-' + spaceId);
  body.style.display = body.style.display === 'none' ? '' : 'none';
}

function updateSpaceCheckboxes() {
  state.listTree.forEach(space => {
    const allLists = [...document.querySelectorAll(\`#body-\${space.id} input[data-listid]\`)];
    const allChecked = allLists.length > 0 && allLists.every(cb => cb.checked);
    const spaceCheck = document.getElementById('space-' + space.id);
    if (spaceCheck) spaceCheck.checked = allChecked;
  });
}

// ── Load Todoist projects ───────────────────────────────────────────────────
async function loadProjects() {
  const sel = document.getElementById('project-select');
  sel.innerHTML = '<option value="">Loading…</option>';
  try {
    const data = await fetch('/api/todoist-projects').then(r => r.json());
    state.projects = data;
    sel.innerHTML = data.map(p => \`<option value="\${p.id}">\${esc(p.name)}</option>\`).join('');
  } catch (e) {
    sel.innerHTML = '<option value="">Failed to load projects</option>';
  }
}

function onProjectModeChange() {
  const mode = document.querySelector('input[name="project-mode"]:checked').value;
  document.getElementById('sub-existing').style.display  = mode === 'existing'  ? '' : 'none';
  document.getElementById('sub-new').style.display       = mode === 'new'       ? '' : 'none';
  document.getElementById('sub-per-list').style.display  = mode === 'per-list'  ? '' : 'none';
}

// ── Start import ────────────────────────────────────────────────────────────
async function startImport() {
  const listIds = [...state.selectedLists];
  if (listIds.length === 0) { alert('Please select at least one list.'); return; }

  const mode = document.querySelector('input[name="project-mode"]:checked').value;

  let projectId      = null;
  let newProjectName = null;

  if (mode === 'existing') {
    projectId = document.getElementById('project-select').value;
    if (!projectId) { alert('Please select a Todoist project.'); return; }
  } else if (mode === 'new') {
    newProjectName = document.getElementById('new-project-name').value.trim();
    if (!newProjectName) { alert('Please enter a name for the new project.'); return; }
  }
  // mode === 'per-list': no extra input needed

  // Build list map so server knows each list's name for per-list mode
  const listMap = {};
  document.querySelectorAll('input[data-listid]:checked').forEach(cb => {
    listMap[cb.dataset.listid] = cb.closest('.tree-list')?.querySelector('.tree-list-name')?.textContent || cb.dataset.listid;
  });

  const config = {
    listIds,
    listMap,
    projectMode:    mode,
    projectId:      projectId || null,
    newProjectName: newProjectName || null,
    includeAttachments: document.getElementById('opt-attachments').checked,
    includeClosed:      document.getElementById('opt-closed').checked,
    dryRun:             document.getElementById('opt-dryrun').checked,
  };

  await fetch('/api/import/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(config) });

  state.progressTotal = 0;
  state.progressDone  = 0;
  const logEl = document.getElementById('progress-log');
  logEl.innerHTML = '';
  logEl.style.display = 'block';
  document.getElementById('progress-bar').style.width = '0%';
  document.getElementById('progress-title').textContent = config.dryRun ? 'Dry run preview…' : 'Importing…';
  document.getElementById('progress-subtitle').textContent = config.dryRun ? 'No changes will be made.' : 'Please keep this tab open.';
  showView('progress');
  connectSSE();
}

// ── SSE progress stream ─────────────────────────────────────────────────────
function connectSSE() {
  const es = new EventSource('/api/import/stream');

  es.onmessage = (e) => {
    const event = JSON.parse(e.data);
    handleEvent(event);
    if (event.type === 'done') es.close();
  };

  es.onerror = () => {
    appendLog('err', 'Connection lost. The import may still be running.');
    es.close();
  };
}

function handleEvent(event) {
  const log = document.getElementById('progress-log');

  switch (event.type) {
    case 'list_start':
      state.progressTotal += event.total || 0;
      appendLog('info', \`Starting list — \${event.total} task(s)\`);
      break;
    case 'task':
      if (event.status === 'created')  { appendLog('ok',   \`\${event.name}\`); bump(); }
      if (event.status === 'dry_run')  { appendLog('info', \`[DRY RUN] \${event.name}\`); bump(); }
      if (event.status === 'error')    { appendLog('err',  \`\${event.name}\`, event.error); }
      break;
    case 'attachment':
      if (event.status === 'downloading') { appendLog('spin', \`↓ \${event.fileName}\`, \`from \${event.taskName}\`); }
      if (event.status === 'uploading')   { updateLastLog(\`↑ \${event.fileName}\`); }
      if (event.status === 'done')        { updateLastLog(\`📎 \${event.fileName} attached\`, null, 'ok'); }
      if (event.status === 'dry_run')     { appendLog('info', \`[DRY RUN] attachment: \${event.fileName}\`); }
      if (event.status === 'error')       { updateLastLog(\`\${event.fileName} — failed\`, event.error, 'err'); }
      break;
    case 'log':
      appendLog('info', event.message);
      break;
    case 'done':
      showDone(event.stats, event.dryRun);
      break;
  }
}

function bump() {
  state.progressDone++;
  if (state.progressTotal > 0) {
    const pct = Math.min(99, Math.round((state.progressDone / state.progressTotal) * 100));
    document.getElementById('progress-bar').style.width = pct + '%';
  }
}

let logCount = 0;
function appendLog(iconClass, text, sub) {
  const log = document.getElementById('progress-log');
  const id  = 'log-' + (++logCount);
  const icons = { ok: '✓', err: '✕', spin: '◌', info: '·' };
  log.insertAdjacentHTML('beforeend', \`
    <div class="log-entry" id="\${id}">
      <span class="log-icon \${iconClass}">\${icons[iconClass] || '·'}</span>
      <div class="log-text">\${esc(text)}\${sub ? \`<div class="sub">\${esc(sub)}</div>\` : ''}</div>
    </div>
  \`);
  log.scrollTop = log.scrollHeight;
  return id;
}

function updateLastLog(text, sub, newIconClass) {
  const log   = document.getElementById('progress-log');
  const last  = log.querySelector('.log-entry:last-child');
  if (!last) return appendLog(newIconClass || 'info', text, sub);
  last.querySelector('.log-text').innerHTML = esc(text) + (sub ? \`<div class="sub">\${esc(sub)}</div>\` : '');
  if (newIconClass) {
    const icons = { ok: '✓', err: '✕', spin: '◌', info: '·' };
    const ic = last.querySelector('.log-icon');
    ic.className = 'log-icon ' + newIconClass;
    ic.textContent = icons[newIconClass];
  }
}

// ── Done ────────────────────────────────────────────────────────────────────
function showDone(stats, dryRun) {
  document.getElementById('progress-bar').style.width = '100%';
  document.getElementById('done-title').textContent = dryRun ? 'Dry run complete ✓' : 'Import complete ✓';

  const total = stats.tasks + stats.taskErrors;
  document.getElementById('done-subtitle').textContent = dryRun
    ? \`\${stats.tasks} task(s) would be created, \${stats.attachments} attachment(s) would be uploaded.\`
    : \`\${stats.tasks} task(s) imported, \${stats.attachments} attachment(s) uploaded.\`;

  document.getElementById('summary-grid').innerHTML = \`
    <div class="summary-stat"><div class="n">\${stats.tasks}</div><div class="label">\${dryRun ? 'Tasks (preview)' : 'Tasks imported'}</div></div>
    <div class="summary-stat"><div class="n">\${stats.attachments}</div><div class="label">\${dryRun ? 'Attachments (preview)' : 'Attachments uploaded'}</div></div>
    \${stats.taskErrors ? \`<div class="summary-stat error-stat"><div class="n">\${stats.taskErrors}</div><div class="label">Task errors</div></div>\` : ''}
    \${stats.attachmentErrors ? \`<div class="summary-stat error-stat"><div class="n">\${stats.attachmentErrors}</div><div class="label">Attachment errors</div></div>\` : ''}
  \`;

  const hasErrors = stats.taskErrors || stats.attachmentErrors;
  document.getElementById('done-alerts').innerHTML = hasErrors
    ? \`<div class="alert alert-warning" style="margin-bottom:16px">⚠ Some items failed to import. Use the log below to see which ones.</div>\`
    : (dryRun ? '<div class="alert alert-info" style="margin-bottom:16px">This was a dry run. Click "Import more lists" and uncheck Dry run to run for real.</div>' : '');

  // Collapse the log on done — show it expanded only if there were errors
  const logEl = document.getElementById('progress-log');
  const toggleBtn = document.getElementById('btn-toggle-log');
  if (hasErrors) {
    logEl.style.display = 'block';
    toggleBtn.textContent = 'Hide log ▴';
  } else {
    logEl.style.display = 'none';
    toggleBtn.textContent = 'Show log ▾';
  }

  showView('done');
}

// ── Utils ───────────────────────────────────────────────────────────────────
function toggleLog() {
  const logEl    = document.getElementById('progress-log');
  const toggleBtn = document.getElementById('btn-toggle-log');
  const visible  = logEl.style.display !== 'none';
  logEl.style.display    = visible ? 'none' : 'block';
  toggleBtn.textContent  = visible ? 'Show log ▾' : 'Hide log ▴';
}

function esc(str) {
  return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Routes
// ─────────────────────────────────────────────────────────────────────────────

// Health check — used by Render, Railway, Fly, etc. to confirm the app is up
app.get('/health', (req, res) => res.json({ ok: true }));


// Main page
app.get('/', async (req, res) => {
  const { code, state } = req.query;

  // ClickUp redirects back to the base URL (it strips paths from redirect URIs)
  // Detect the OAuth callback by the presence of code + state params
  if (code && state) {
    const expected = req.session.oauthState?.clickup;
    if (!state || state !== expected) return res.redirect('/?error=invalid_state');
    try {
      const data = await cuExchangeCode(code);
      req.session.clickupToken = data.access_token;
      // Clear the state and redirect cleanly (no query params)
      delete req.session.oauthState;
      return res.redirect('/');
    } catch (err) {
      console.error('ClickUp token exchange failed:', err.message);
      return res.redirect('/?error=clickup_auth_failed');
    }
  }

  res.send(renderPage({
    clickup: !!req.session.clickupToken,
    todoist: !!req.session.todoistToken,
  }));
});

// ── ClickUp OAuth ──────────────────────────────────────────────────────────

app.get('/auth/clickup', (req, res) => {
  if (!CLICKUP.clientId) return res.status(500).send('CLICKUP_CLIENT_ID not configured');
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = req.session.oauthState || {};
  req.session.oauthState.clickup = state;
  // ClickUp supports state param for CSRF protection
  const url = `https://app.clickup.com/api?client_id=${encodeURIComponent(CLICKUP.clientId)}&redirect_uri=${encodeURIComponent(CLICKUP.redirectUri)}&state=${state}`;
  res.redirect(url);
});

app.get('/auth/clickup/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.redirect('/?error=no_code');
  const expected = req.session.oauthState?.clickup;
  if (!state || state !== expected) return res.redirect('/?error=invalid_state');
  try {
    const data = await cuExchangeCode(code);
    req.session.clickupToken = data.access_token;
    res.redirect('/?auth=done');
  } catch (err) {
    console.error('ClickUp token exchange failed:', err.message);
    res.redirect('/?error=clickup_auth_failed');
  }
});

// ── Todoist OAuth ──────────────────────────────────────────────────────────

app.get('/auth/todoist', (req, res) => {
  if (!TODOIST.clientId) return res.status(500).send('TODOIST_CLIENT_ID not configured');
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = req.session.oauthState || {};
  req.session.oauthState.todoist = state;
  const url = `https://app.todoist.com/oauth/authorize?client_id=${encodeURIComponent(TODOIST.clientId)}&scope=${TODOIST.scope}&state=${state}&redirect_uri=${encodeURIComponent(TODOIST.redirectUri)}`;
  res.redirect(url);
});

app.get('/auth/todoist/callback', async (req, res) => {
  const { code, state, error } = req.query;
  // Don't reflect the raw OAuth error value into the redirect — use a safe fixed string
  if (error) return res.redirect('/?error=todoist_auth_denied');
  const expected = req.session.oauthState?.todoist;
  if (!state || state !== expected) return res.redirect('/?error=invalid_state');
  try {
    const data = await tdExchangeCode(code);
    req.session.todoistToken = data.access_token;
    res.redirect('/?auth=done');
  } catch (err) {
    console.error('Todoist token exchange failed:', err.message);
    res.redirect('/?error=todoist_auth_failed');
  }
});

app.post('/auth/disconnect/:service', (req, res) => {
  if (req.params.service === 'clickup') delete req.session.clickupToken;
  if (req.params.service === 'todoist') delete req.session.todoistToken;
  res.json({ ok: true });
});

// ── API: ClickUp data ──────────────────────────────────────────────────────

app.get('/api/workspaces', async (req, res) => {
  if (!req.session.clickupToken) return res.status(401).json({ error: 'Not connected to ClickUp' });
  try {
    const data = await cuGetTeams(req.session.clickupToken);
    res.json((data.teams || []).map(t => ({ id: t.id, name: t.name })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/lists', async (req, res) => {
  if (!req.session.clickupToken) return res.status(401).json({ error: 'Not connected to ClickUp' });
  const { workspace_id } = req.query;
  if (!workspace_id) return res.status(400).json({ error: 'workspace_id required' });
  try {
    const tree = await cuGetListTree(req.session.clickupToken, workspace_id);
    res.json(tree);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── API: Todoist data ──────────────────────────────────────────────────────

app.get('/api/todoist-projects', async (req, res) => {
  if (!req.session.todoistToken) return res.status(401).json({ error: 'Not connected to Todoist' });
  try {
    const projects = await tdGetProjects(req.session.todoistToken);
    res.json(projects.map(p => ({ id: p.id, name: p.name })));
  } catch (err) {
    console.error('todoist-projects error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── API: Import ────────────────────────────────────────────────────────────

app.post('/api/import/start', (req, res) => {
  if (!req.session.clickupToken || !req.session.todoistToken) {
    return res.status(401).json({ error: 'Not connected' });
  }
  const { listIds, listMap, projectMode, projectId, newProjectName, includeAttachments, includeClosed, dryRun } = req.body;

  // Input validation
  const VALID_MODES = ['existing', 'new', 'per-list'];
  if (!Array.isArray(listIds) || !listIds.length) return res.status(400).json({ error: 'listIds must be a non-empty array' });
  if (listIds.some(id => typeof id !== 'string' || !/^\w+$/.test(id))) return res.status(400).json({ error: 'Invalid listId format' });
  if (listIds.length > 100) return res.status(400).json({ error: 'Too many lists selected (max 100)' });
  if (!VALID_MODES.includes(projectMode)) return res.status(400).json({ error: 'Invalid projectMode' });
  if (newProjectName && typeof newProjectName === 'string' && newProjectName.length > 200) return res.status(400).json({ error: 'Project name too long' });
  // Sanitise listMap — only keep keys that are valid list IDs
  const safeListMap = {};
  if (listMap && typeof listMap === 'object') {
    for (const [k, v] of Object.entries(listMap)) {
      if (/^\w+$/.test(k) && typeof v === 'string') safeListMap[k] = v.slice(0, 200);
    }
  }

  console.log(`[import/start] projectMode=${projectMode} listCount=${listIds.length}`);
  req.session.importConfig = { listIds, listMap: safeListMap, projectMode, projectId, newProjectName, includeAttachments: !!includeAttachments, includeClosed: !!includeClosed, dryRun: !!dryRun };
  res.json({ ok: true });
});

app.get('/api/import/stream', async (req, res) => {
  if (!req.session.clickupToken || !req.session.todoistToken) {
    return res.status(401).end();
  }
  const config = req.session.importConfig;
  if (!config) return res.status(400).end();

  // SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  req.socket.setTimeout(0);

  const tokens = { clickup: req.session.clickupToken, todoist: req.session.todoistToken };
  let closed = false;
  req.on('close', () => { closed = true; });

  function emit(event) {
    if (closed) return;
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  }

  try {
    await runImport(config, tokens, emit);
  } catch (err) {
    emit({ type: 'error', message: err.message });
    emit({ type: 'done', stats: { tasks: 0, taskErrors: 1, attachments: 0, attachmentErrors: 0 }, dryRun: config.dryRun });
  } finally {
    if (!closed) res.end();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\nClickUp → Todoist Importer`);
  console.log(`Running at: ${BASE_URL}`);
  if (!CLICKUP.clientId || !TODOIST.clientId) {
    console.log('\n⚠  Missing OAuth credentials — copy .env.example to .env and fill in your app IDs\n');
  }
});
