/* Compare Share —— 前端逻辑
 *
 * 目录授权走飞牛官方 SDK @trimjs/web-app：
 *   - pickUserFile({directory:true})  唤起官方目录选择器并授权给本应用
 *   - authorizeUserFile(path)         授权用户手填的路径
 *   - openAppSetting()                打开系统里的应用设置页
 * 授权成功后一律调用后端 /api/auth/paths 回读官方授权列表，
 * 不采信 SDK 返回的路径（与飞牛文档的建议一致）。
 */

/* 系统里手动授权的路径，界面直接告诉用户怎么走 */
const MANUAL_AUTH_PATH = '应用中心 → 已安装 → Compare Share → 应用设置 → 访问权限 → 选择允许访问的文件夹';

/* 飞牛官方 SDK 本地内置，避免 NAS 处于隔离内网时目录授权不可用；
 * 本地文件缺失时回退到 CDN。 */
const SDK_LOCAL = 'trimjs-web-app.js';
const SDK_CDN = 'https://cdn.jsdelivr.net/npm/@trimjs/web-app@0.4.2/dist/index.js';

/* SDK 与飞牛宿主握手不设超时，宿主不应答时 ready() 会永久挂起。
 * 这里强制加超时，并把初始化放到数据加载之后，保证界面永远可用。 */
const SDK_READY_TIMEOUT = 6000;

function withTimeout(promise, ms, label) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} 超时（${ms}ms）`)), ms);
    Promise.resolve(promise).then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

const state = {
  config: {},
  status: {},
  peers: [],
  files: [],
  transfers: [],
  auth: { user: [], shared: [], labels: {}, available: false },
  sdk: null,
  sdkReady: false,
  isEmbedded: false,
  sendTarget: null,
  sendPicked: new Set(),
  browsePath: '',
};

/* ---------- 工具 ---------- */

const $ = (sel) => document.querySelector(sel);

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  let body = null;
  try { body = await res.json(); } catch (_) { /* 空响应 */ }
  if (!res.ok) {
    throw new Error((body && (body.message || body.error)) || `请求失败 (${res.status})`);
  }
  return body;
}

function toast(message, kind = '') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = message;
  $('#toasts').appendChild(el);
  setTimeout(() => {
    el.style.transition = 'opacity .2s, transform .2s';
    el.style.opacity = '0';
    el.style.transform = 'translateX(16px)';
    setTimeout(() => el.remove(), 220);
  }, 3600);
}

function fmtSize(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, n = bytes;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  const pad = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function relTime(ts) {
  const diff = Date.now() / 1000 - ts;
  if (diff < 60) return '刚刚';
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`;
  return `${Math.floor(diff / 86400)} 天前`;
}

function esc(text) {
  const div = document.createElement('div');
  div.textContent = String(text ?? '');
  return div.innerHTML;
}

const ICONS = {
  folder: '<svg viewBox="0 0 24 24" fill="none"><path d="M3 7.5A1.5 1.5 0 0 1 4.5 6h4l2 2.5h7A1.5 1.5 0 0 1 19 10v7a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 3 17V7.5Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>',
  file: '<svg viewBox="0 0 24 24" fill="none"><path d="M6 3.5h7l5 5v12H6v-17Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M13 3.5v5h5" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>',
  down: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 4v11m0 0 4-4m-4 4-4-4M5 19h14" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  up: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 20V9m0 0 4 4m-4-4-4 4M5 5h14" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none"><path d="m5 13 4.5 4.5L19 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
};

/* ---------- 视图切换 ---------- */

const VIEW_META = {
  devices: ['附近设备', '正在扫描局域网中支持 LocalSend 的设备'],
  inbox: ['收件箱', '已接收的文件，保存在设置的下载目录中'],
  transfers: ['传输记录', '最近的发送与接收活动'],
  settings: ['设置', '设备信息、接收目录与传输安全'],
};

document.querySelectorAll('.nav-item').forEach((btn) => {
  btn.addEventListener('click', () => {
    const view = btn.dataset.view;
    document.querySelectorAll('.nav-item').forEach((b) => b.classList.toggle('is-active', b === btn));
    document.querySelectorAll('.view').forEach((v) => v.classList.toggle('is-active', v.dataset.view === view));
    $('#viewTitle').textContent = VIEW_META[view][0];
    $('#viewSub').textContent = VIEW_META[view][1];
    if (view === 'inbox') loadFiles();
    if (view === 'transfers') loadTransfers();
  });
});

/* ---------- 数据加载 ---------- */

async function loadStatus() {
  try {
    const s = await api('/api/status');
    state.status = s;
    $('#statusDot').className = 'dot ok';
    $('#statusText').textContent = '服务运行中';
    $('#metaProtocol').textContent = s.protocol.toUpperCase();
    $('#metaPort').textContent = `${s.port} / ${s.webPort}`;
    $('#metaFingerprint').textContent = (s.fingerprint || '').slice(0, 16);
    $('#metaFingerprint').title = s.fingerprint || '';
    $('#inboxPath').textContent = s.downloadDir || '—';
  } catch (err) {
    $('#statusDot').className = 'dot err';
    $('#statusText').textContent = '服务不可用';
  }
}

async function loadPeers() {
  try {
    const { peers } = await api('/api/peers');
    state.peers = peers || [];
    renderPeers();
    $('#navPeerCount').textContent = state.peers.filter((p) => p.online).length;
  } catch (err) { /* 静默，下一轮重试 */ }
}

function typeLabel(type) {
  return ({ mobile: '手机', desktop: '电脑', server: '服务器', headless: '无头设备', web: '网页' })[type] || '设备';
}

function renderPeers() {
  const list = $('#peerList');
  const empty = $('#peerEmpty');
  const online = state.peers.filter((p) => p.online);

  if (!state.peers.length) {
    list.innerHTML = '';
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  list.innerHTML = state.peers.map((p) => {
    const initial = (p.alias || '?').trim().charAt(0).toUpperCase();
    return `
      <article class="peer-card">
        <div class="peer-top">
          <div class="peer-avatar">${esc(initial)}</div>
          <div class="peer-meta">
            <div class="peer-name" title="${esc(p.alias)}">${esc(p.alias)}</div>
            <div class="peer-sub">
              <span class="peer-badge ${p.online ? '' : 'off'}">${p.online ? '在线' : '离线'}</span>
              <span>${esc(typeLabel(p.deviceType))}</span>
            </div>
          </div>
        </div>
        <div class="peer-info">
          <span><code>${esc(p.host)}:${esc(p.port)}</code></span>
          <span>${esc(p.deviceModel || '未知型号')} · ${relTime(p.lastSeen)}</span>
        </div>
        <button class="btn btn-primary" data-send="${esc(p.fingerprint || p.host)}" ${p.online ? '' : 'disabled'}>
          ${ICONS.up} 发送文件
        </button>
      </article>`;
  }).join('');

  list.querySelectorAll('[data-send]').forEach((btn) => {
    btn.addEventListener('click', () => openSendDialog(btn.dataset.send));
  });
}

async function loadFiles() {
  try {
    const { files } = await api('/api/files');
    state.files = files || [];
    $('#navFileCount').textContent = state.files.length;
    const list = $('#fileList');
    if (!state.files.length) {
      list.innerHTML = '<div class="list-empty">还没有收到文件</div>';
      return;
    }
    list.innerHTML = state.files.map((f) => `
      <div class="list-row">
        <div class="list-icon in">${ICONS.down}</div>
        <div class="list-main">
          <div class="list-title" title="${esc(f.fileName)}">${esc(f.fileName)}</div>
          <div class="list-sub"><span>${fmtSize(f.size)}</span><span>${fmtTime(f.modified)}</span></div>
        </div>
      </div>`).join('');
  } catch (err) { /* 静默 */ }
}

async function loadTransfers() {
  try {
    const { transfers } = await api('/api/transfers');
    state.transfers = transfers || [];
    const list = $('#transferList');
    if (!state.transfers.length) {
      list.innerHTML = '<div class="list-empty">暂无传输记录</div>';
      return;
    }
    const LABEL = { done: '完成', failed: '失败', transferring: '传输中', connecting: '连接中', preparing: '准备中' };
    list.innerHTML = state.transfers.map((t) => {
      const incoming = t.direction === 'in';
      const count = t.files ? t.files.length : 0;
      const detail = t.error ? esc(t.error) : (t.note ? esc(t.note) : `${count} 个文件`);
      return `
      <div class="list-row">
        <div class="list-icon ${incoming ? 'in' : 'out'}">${incoming ? ICONS.down : ICONS.up}</div>
        <div class="list-main">
          <div class="list-title">${incoming ? '来自' : '发送到'} ${esc(t.alias || t.host || '未知')}</div>
          <div class="list-sub">
            <span>${count} 个文件</span>
            <span>${fmtSize(t.bytes || t.total || 0)}</span>
            <span>${fmtTime(t.time)}</span>
          </div>
        </div>
        <div class="list-actions">
          <span class="state-pill ${esc(t.state)}">${LABEL[t.state] || esc(t.state)}</span>
          ${detail ? `<span class="muted small">${detail}</span>` : ''}
        </div>
      </div>`;
    }).join('');
  } catch (err) { /* 静默 */ }
}

/* ---------- 设置 ---------- */

function fillSettings() {
  const c = state.config;
  $('#inpAlias').value = c.alias || '';
  $('#selType').value = c.device_type || 'server';
  $('#inpDownloadDir').value = c.download_dir || '';
  $('#inpPort').value = c.port || 53317;
  $('#chkHttps').checked = !!c.https;
  $('#chkAutoAccept').checked = !!c.auto_accept;
  const hasPin = !!(state.status.pinRequired);
  $('#chkPin').checked = hasPin;
  $('#pinRow').hidden = !hasPin;
  if (hasPin && state.status.pin) $('#pinValue').textContent = state.status.pin;
}

async function loadConfig() {
  try {
    const { config } = await api('/api/config');
    state.config = config;
  } catch (err) {
    console.warn('读取配置失败：', err);
  }
  await loadStatus();
  await loadAuth();
  fillSettings();
}

async function saveConfig() {
  const patch = {
    alias: $('#inpAlias').value.trim(),
    device_type: $('#selType').value,
    download_dir: $('#inpDownloadDir').value.trim(),
    port: parseInt($('#inpPort').value, 10) || 53317,
    https: $('#chkHttps').checked,
    auto_accept: $('#chkAutoAccept').checked,
  };
  const hint = $('#saveHint');
  try {
    const { config } = await api('/api/config', { method: 'POST', body: JSON.stringify(patch) });
    state.config = config;
    hint.textContent = '已保存';
    toast('设置已保存', 'ok');
    await loadStatus();
    setTimeout(() => { hint.textContent = ''; }, 2500);
  } catch (err) {
    hint.textContent = '';
    toast(err.message, 'err');
  }
}

/* ---------- 飞牛目录授权 ---------- */

async function initSdk() {
  // 仅当页面被飞牛桌面以内嵌方式打开时，SDK 桥才可用
  state.isEmbedded = window.parent !== window;
  if (!state.isEmbedded) return;

  const load = (url) => import(/* webpackIgnore: true */ url);

  let mod = null;
  try {
    mod = await withTimeout(load(SDK_LOCAL), SDK_READY_TIMEOUT, '加载本地 SDK');
  } catch (err) {
    console.warn('本地飞牛 SDK 不可用，改用 CDN', err);
    try {
      mod = await withTimeout(load(SDK_CDN), SDK_READY_TIMEOUT, '加载 CDN SDK');
    } catch (err2) {
      console.warn('飞牛 SDK 加载失败，目录授权将不可用', err2);
      return;
    }
  }

  try {
    const TrimApp = mod.TrimApp || mod.default;
    state.sdk = new TrimApp();
    // 宿主不应答时 ready() 永不 resolve，必须限时
    await withTimeout(state.sdk.ready(), SDK_READY_TIMEOUT, '飞牛宿主握手');
    state.sdkReady = true;
  } catch (err) {
    console.warn('飞牛 SDK 初始化未完成，目录授权将不可用：', err);
    state.sdk = null;
    state.sdkReady = false;
  }
}

function setAuthState(kind, text) {
  const box = $('#authBox');
  box.classList.remove('warn', 'err');
  if (kind === 'warn') box.classList.add('warn');
  if (kind === 'err') box.classList.add('err');
  $('#authState').textContent = text;
}

async function loadAuth() {
  try {
    const auth = await api('/api/auth/paths');
    state.auth = auth;
    renderAuth();
  } catch (err) {
    setAuthState('err', '查询失败');
    $('#authHint').textContent = err.message;
  }
}

function renderAuth() {
  const auth = state.auth;
  const box = $('#authBox');
  const paths = [...(auth.user || []), ...(auth.shared || [])];
  const dir = $('#inpDownloadDir').value.trim();
  const dirAuthorized = dir && paths.some((p) => dir === p || dir.startsWith(p + '/'));

  $('#authPaths').innerHTML = paths.length
    ? paths.map((p) => `
        <div class="auth-path">
          ${ICONS.check}
          <span class="p" title="${esc(p)}">${esc((auth.labels && auth.labels[p]) || p)}</span>
        </div>`).join('')
    : '';

  box.classList.remove('warn', 'err');

  const picker = detectPicker();
  // 宿主版本较老时应用内选择器不可用，引导用户到系统设置里授权
  const canPickInApp = !!picker;
  let capNote = '';
  if (!state.isEmbedded) {
    capNote = '当前不在飞牛桌面中，目录选择器不可用。';
  } else if (!state.sdkReady) {
    capNote = '未能连接飞牛宿主，目录选择器不可用。';
  } else if (!canPickInApp) {
    capNote = `当前系统版本不支持在应用内选择目录，请在系统中授权：${MANUAL_AUTH_PATH}。`;
  }

  if (!auth.available) {
    setAuthState('warn', '当前环境不支持');
    $('#authHint').textContent = auth.error || '请在飞牛桌面中打开本应用以使用目录授权。';
  } else if (paths.length === 0 && auth.error) {
    setAuthState('warn', '授权查询受限');
    $('#authHint').textContent =
      `无法读取授权列表：${auth.error}。若刚安装或升级，请重启应用后再试。`;
    box.classList.add('warn');
  } else if (paths.length === 0) {
    setAuthState('warn', '未授权');
    $('#authHint').textContent = capNote
      || `尚未授权任何目录。可点「选择并授权目录」，或在系统中手动授权：${MANUAL_AUTH_PATH}。`;
  } else if (dirAuthorized) {
    setAuthState('ok', '已授权');
    $('#authHint').textContent = `当前下载目录在授权范围内（共 ${paths.length} 个授权目录）。`;
  } else {
    setAuthState('warn', `已授权 ${paths.length} 个目录`);
    $('#authHint').textContent = '当前下载目录不在已授权范围内，收到的文件可能无法写入。';
  }

  // 应用内选择器不可用时，按钮改为直接打开系统应用设置，并展开分步引导
  const pickBtn = $('#btnPickDir');
  pickBtn.textContent = canPickInApp ? '选择并授权目录' : '打开系统应用设置';
  $('#btnAuthCurrent').hidden = !canPickInApp;
  $('#authGuide').hidden = canPickInApp || paths.length > 0;

  if (capNote && paths.length) {
    $('#authHint').textContent += ` ${capNote}`;
  }
}

function requireSdk() {
  if (state.sdkReady) return true;
  if (!state.isEmbedded) {
    toast(`目录选择器需在飞牛桌面中打开本应用。也可在系统中手动授权：${MANUAL_AUTH_PATH}`, 'err');
  } else {
    toast(`未能连接飞牛宿主。可在系统中手动授权：${MANUAL_AUTH_PATH}`, 'err');
  }
  return false;
}

/* 探测宿主实际提供的目录选择能力。
 * 不同 fnOS 版本的宿主方法集不同：
 *   pickUserFile  较新版本才提供，可直接把目录授权给本应用
 *   pickFile      更老的通用接口（走 openFolder）
 * 逐个探测，都不支持时降级为手动输入路径 + authorizeUserFile。 */
function detectPicker() {
  if (!state.sdk || !state.sdkReady) return null;
  let methods = null;
  try {
    methods = state.sdk.getWebMethods
      ? state.sdk.getWebMethods()
      : (state.sdk.osConnector && state.sdk.osConnector.methods);
  } catch (_) {
    methods = null;
  }
  if (!methods) return null;

  if (typeof methods.pickUserFile === 'function') return 'pickUserFile';
  if (typeof methods.pickFile === 'function') return 'pickFile';
  if (typeof methods.pickSharedFile === 'function') return 'pickSharedFile';
  return null;
}

function callSdk(name, ...args) {
  const fn = state.sdk && state.sdk[name];
  if (typeof fn !== 'function') throw new Error(`SDK 不支持 ${name}`);
  return fn.apply(state.sdk, args);
}

async function pickAndAuthorize() {
  if (!requireSdk()) return;

  const picker = detectPicker();
  if (!picker) {
    // 宿主不提供选择器：直接带用户去系统设置里手动授权
    await openAppSetting();
    toast(`请在系统中授权：${MANUAL_AUTH_PATH}`, 'ok');
    return;
  }

  try {
    let dirs = [];

    if (picker === 'pickUserFile') {
      const result = await callSdk('pickUserFile', {
        directory: true,
        title: '选择授权目录',
        okText: '确认授权',
        sidebarGroup: ['myFiles', 'otherShare', 'favorites'],
      });
      if (result === undefined) return;            // 用户取消
      if (result.code !== 0) { toast(result.msg || '授权失败', 'err'); return; }
      dirs = result.data || [];

    } else if (picker === 'pickFile') {
      // 老版本通用选择器：只负责选路径，授权需另外调用 authorizeUserFile
      const picked = await callSdk('pickFile', {
        directory: true,
        multiple: false,
        title: '选择目录',
      });
      if (!picked || !picked.length) return;
      dirs = picked;

    } else {
      const result = await callSdk('pickSharedFile', { title: '选择授权目录' });
      if (result === undefined) return;
      if (result.code !== 0) { toast(result.msg || '授权失败', 'err'); return; }
      dirs = result.data || [];
    }

    // pickFile 不自动授权，需要为选中的目录补一次授权
    if (picker === 'pickFile' && dirs.length) {
      let granted = 0;
      for (const dir of dirs) {
        try {
          const r = await callSdk('authorizeUserFile', dir);
          if (r && r.code === 0) granted += 1;
        } catch (err) {
          console.warn('授权失败：', dir, err);
        }
      }
      if (!granted) {
        toast('已选择目录但授权未成功，可在系统应用设置中手动授权', 'err');
      }
    }

    await refreshAuthAfterGrant();
  } catch (err) {
    const msg = String((err && err.message) || err);
    if (msg === 'Operation failed') return;          // 官方实现的「取消」是 reject
    if (/is not a function/.test(msg)) {
      toast('当前系统版本不支持目录选择器，请手动填写路径后点「授权当前路径」', 'err');
      return;
    }
    toast(`授权未完成：${msg}`, 'err');
  }
}

async function authorizeCurrentPath() {
  if (!requireSdk()) return;
  const path = $('#inpDownloadDir').value.trim();
  if (!path) { toast('请先填写下载目录', 'err'); return; }
  if (!path.startsWith('/')) {
    toast('请填写以 / 开头的完整路径，例如 /vol1/1000/音乐', 'err');
    return;
  }
  const picker = detectPicker();
  // 优先用带授权语义的接口；老宿主只有 pickFile 时，直接尝试 authorizeUserFile
  const method = (picker === 'pickSharedFile') ? 'authorizeSharedFile' : 'authorizeUserFile';
  try {
    const result = await callSdk(method, path);
    if (result === undefined) return;
    if (result && result.code !== 0) {
      toast(result.msg || '授权失败', 'err');
      return;
    }
    await refreshAuthAfterGrant();
  } catch (err) {
    const msg = String((err && err.message) || err);
    if (msg === 'Operation failed') return;
    if (/is not a function/.test(msg)) {
      toast('当前系统版本不支持在应用内授权，请点「打开系统应用设置」手动添加', 'err');
      return;
    }
    toast(`授权未完成：${msg}`, 'err');
  }
}

async function refreshAuthAfterGrant() {
  // 授权由系统侧完成，必须回读官方列表确认
  await loadAuth();
  const paths = [...(state.auth.user || []), ...(state.auth.shared || [])];
  if (paths.length) {
    toast('授权成功', 'ok');
  } else {
    toast('系统未返回授权目录。若已在系统设置中授权，请点「刷新授权状态」；也可能是该路径的授权需重启应用后生效', 'err');
  }
}

async function openAppSetting() {
  if (!requireSdk()) return;
  try { await state.sdk.openAppSetting(); }
  catch (err) { toast('无法打开应用设置', 'err'); }
}

/* ---------- 发送 ---------- */

async function openSendDialog(peerKey) {
  const peer = state.peers.find((p) => (p.fingerprint || p.host) === peerKey);
  if (!peer) return;
  state.sendTarget = peer;
  state.sendPicked = new Set();
  state.browsePath = '';
  $('#sendTargetName').textContent = peer.alias;
  $('#sendSelection').textContent = '未选择文件';
  $('#btnConfirmSend').disabled = true;
  $('#sendModal').hidden = false;
  await browse('');
}

function closeSendDialog() {
  $('#sendModal').hidden = true;
  state.sendTarget = null;
  state.sendPicked = new Set();
}

function updateSendSelection() {
  const n = state.sendPicked.size;
  $('#sendSelection').textContent = n ? `已选择 ${n} 项` : '未选择文件';
  $('#btnConfirmSend').disabled = n === 0;
}

async function browse(path) {
  try {
    const data = await api(`/api/browse?path=${encodeURIComponent(path)}`);
    state.browsePath = data.path || '';
    renderBrowse(data);
  } catch (err) {
    toast(err.message, 'err');
  }
}

function renderBrowse(data) {
  const crumb = $('#browseCrumb');
  crumb.innerHTML = '';

  const rootBtn = document.createElement('button');
  rootBtn.textContent = '根目录';
  rootBtn.addEventListener('click', () => browse(''));
  crumb.appendChild(rootBtn);

  if (data.path) {
    const parts = data.path.split('/').filter(Boolean);
    let acc = '';
    parts.forEach((seg) => {
      acc += `/${seg}`;
      const sep = document.createTextNode(' / ');
      const btn = document.createElement('button');
      const target = acc;
      btn.textContent = seg;
      btn.addEventListener('click', () => browse(target));
      crumb.append(sep, btn);
    });
  }

  const list = $('#browseList');
  if (data.error) {
    list.innerHTML = `<div class="list-empty">${esc(data.error)}</div>`;
    return;
  }
  if (!data.entries || !data.entries.length) {
    list.innerHTML = '<div class="list-empty">此目录为空</div>';
    return;
  }

  list.innerHTML = '';
  if (data.parent) {
    const up = document.createElement('button');
    up.className = 'browse-row dir';
    up.innerHTML = `${ICONS.folder}<span class="nm">.. 返回上级</span>`;
    up.addEventListener('click', () => browse(data.parent));
    list.appendChild(up);
  }

  data.entries.forEach((entry) => {
    const row = document.createElement('button');
    row.className = `browse-row${entry.dir ? ' dir' : ''}`;
    if (state.sendPicked.has(entry.path)) row.classList.add('is-picked');
    row.innerHTML = `
      ${entry.dir ? ICONS.folder : ICONS.file}
      <span class="nm">${esc(entry.name)}</span>
      <span class="sz">${entry.dir ? '文件夹' : fmtSize(entry.size)}</span>`;

    row.addEventListener('click', () => {
      if (entry.dir) { browse(entry.path); return; }
      if (state.sendPicked.has(entry.path)) state.sendPicked.delete(entry.path);
      else state.sendPicked.add(entry.path);
      row.classList.toggle('is-picked');
      updateSendSelection();
    });
    list.appendChild(row);
  });

  if (state.sendPicked.size) updateSendSelection();
}

async function confirmSend() {
  if (!state.sendTarget || !state.sendPicked.size) return;
  const btn = $('#btnConfirmSend');
  btn.disabled = true;
  btn.textContent = '发送中…';
  try {
    const body = {
      peer: state.sendTarget.fingerprint || state.sendTarget.host,
      paths: Array.from(state.sendPicked),
    };
    await api('/api/send', { method: 'POST', body: JSON.stringify(body) });
    toast(`已发送到 ${state.sendTarget.alias}`, 'ok');
    closeSendDialog();
    loadTransfers();
  } catch (err) {
    toast(err.message, 'err');
  } finally {
    btn.disabled = false;
    btn.textContent = '开始发送';
  }
}

/* ---------- 事件绑定 ---------- */

function bindEvents() {
  $('#btnAnnounce').addEventListener('click', async () => {
    const btn = $('#btnAnnounce');
    btn.disabled = true;
    try {
      await api('/api/announce', { method: 'POST', body: '{}' });
      toast('已发出广播，正在搜索…');
      await loadPeers();
      // 广播之外再做一次网段扫描：无线网络常过滤多播，扫描能兜住
      const r = await api('/api/scan', { method: 'POST', body: '{}' });
      await loadPeers();
      const n = state.peers.filter((p) => p.online).length;
      toast(r && r.found ? `发现 ${r.found} 台新设备` : `当前共 ${n} 台设备在线`);
    } catch (err) {
      toast(err.message, 'err');
    } finally {
      btn.disabled = false;
    }
  });
  $('#btnAnnounce2').addEventListener('click', () => $('#btnAnnounce').click());

  $('#btnPickSend').addEventListener('click', () => {
    const online = state.peers.filter((p) => p.online);
    if (!online.length) { toast('请先等待设备被发现', 'err'); return; }
    openSendDialog(online[0].fingerprint || online[0].host);
  });

  $('#btnRefreshFiles').addEventListener('click', loadFiles);
  $('#btnRefreshTransfers').addEventListener('click', loadTransfers);

  $('#chkPin').addEventListener('change', async (e) => {
    if (e.target.checked) {
      const { pin } = await api('/api/pin', { method: 'POST', body: JSON.stringify({}) });
      $('#pinValue').textContent = pin;
      $('#pinRow').hidden = false;
      toast(`已开启 PIN 校验：${pin}`, 'ok');
    } else {
      await api('/api/pin', { method: 'POST', body: JSON.stringify({ clear: true }) });
      $('#pinRow').hidden = true;
      toast('已关闭 PIN 校验');
    }
  });

  $('#btnNewPin').addEventListener('click', async () => {
    await api('/api/pin', { method: 'POST', body: JSON.stringify({ clear: true }) });
    const { pin } = await api('/api/pin', { method: 'POST', body: JSON.stringify({}) });
    $('#pinValue').textContent = pin;
    toast(`新的 PIN 码：${pin}`, 'ok');
  });

  $('#btnSaveConfig').addEventListener('click', saveConfig);
  $('#inpDownloadDir').addEventListener('change', renderAuth);

  $('#btnPickDir').addEventListener('click', pickAndAuthorize);
  $('#btnAuthCurrent').addEventListener('click', authorizeCurrentPath);
  $('#btnRefreshAuth').addEventListener('click', loadAuth);
  $('#btnOpenAppSetting').addEventListener('click', openAppSetting);

  $('#btnCloseSend').addEventListener('click', closeSendDialog);
  $('#btnCancelSend').addEventListener('click', closeSendDialog);
  $('#btnConfirmSend').addEventListener('click', confirmSend);
  $('#sendModal').addEventListener('click', (e) => {
    if (e.target === $('#sendModal')) closeSendDialog();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !$('#sendModal').hidden) closeSendDialog();
  });
}

/* ---------- 启动 ---------- */

async function boot() {
  bindEvents();

  // 关键：数据加载不能等在 SDK 后面。飞牛宿主握手可能一直不返回，
  // 若串行等待，界面会永久停在初始状态（协议/端口/指纹显示“—”）。
  const sdkTask = initSdk().catch((err) => {
    console.warn('SDK 初始化异常：', err);
  });

  await loadConfig();
  await loadPeers();
  await loadFiles();
  loadTransfers();

  // SDK 就绪后再刷新一次授权状态，此时目录选择器才可用
  sdkTask.then(() => { if (state.sdkReady) loadAuth(); });

  let tick = 0;
  setInterval(async () => {
    tick += 1;
    await loadStatus();
    if (tick % 2 === 0) await loadPeers();
    if (tick % 6 === 0) { await loadFiles(); await loadTransfers(); }
  }, 3000);
}

boot();
