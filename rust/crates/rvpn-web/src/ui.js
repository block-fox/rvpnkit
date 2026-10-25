/* RvpnKit Web UI. No CDN, build step, or third-party runtime. */
"use strict";

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;"
})[c]);
const icons = {
  dashboard: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  network: '<rect x="8" y="3" width="8" height="6" rx="1.5"/><path d="M12 9v5M5 14h14M5 14v3m14-3v3"/><rect x="2" y="17" width="6" height="4" rx="1"/><rect x="16" y="17" width="6" height="4" rx="1"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2m20 0v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/><circle cx="9" cy="7" r="4"/>',
  compass: '<circle cx="12" cy="12" r="9"/><path d="m16 8-2.5 5.5L8 16l2.5-5.5Z"/>',
  activity: '<path d="M2 12h4l3-8 6 16 3-8h4"/>',
  settings: '<path d="m9 3-1 3-3 1-2 4 2 2v4l4 3 3-1 3 1 4-3v-4l2-2-2-4-3-1-1-3Z"/><circle cx="12" cy="12" r="3"/>',
  refresh: '<path d="M20 7a9 9 0 1 0 1 9M20 3v5h-5"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/>',
  monitor: '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
  gamepad: '<path d="M7 7h10a4 4 0 0 1 4 4l1 6a2 2 0 0 1-3.5 1.5L16 16H8l-2.5 2.5A2 2 0 0 1 2 17l1-6a4 4 0 0 1 4-4Z"/><path d="M7 10v5m-2.5-2.5h5M16 11h.01M19 14h.01"/>',
  download: '<path d="M12 3v12m-4-4 4 4 4-4M4 16v5h16v-5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  copy: '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
  search: '<circle cx="10.5" cy="10.5" r="7"/><path d="m16 16 5 5"/>',
  star: '<path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2-5.6-3-5.6 3 1.1-6.2L3 9.6l6.2-.9Z"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  message: '<path d="M4 5h16v11H8l-4 4Z"/><path d="M8 9h8m-8 3h5"/>'
};
const icon = name => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${icons[name] || icons.network}</svg>`;
$$('[data-icon]').forEach(el => el.replaceWith(document.createRange().createContextualFragment(icon(el.dataset.icon))));
const storage = {
  get(key, fallback) {
    try {
      return JSON.parse(localStorage.getItem(`rvpnkit-${key}`)) ?? fallback;
    } catch {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem(`rvpnkit-${key}`, JSON.stringify(value));
    } catch {/* Private browsing remains usable. */}
  }
};
const savedFavorites = storage.get('favorites', []);
const state = {
  data: null,
  connected: false,
  loading: false,
  sending: false,
  publicLoading: false,
  publicResults: [],
  publicLoaded: false,
  measuredLatencies: storage.get('latencies', {}),
  apiConfig: null,
  probing: false,
  selectedNetwork: '',
  selection: new Set(),
  memberPage: 0,
  page: 'overview',
  favorites: new Set(Array.isArray(savedFavorites) ? savedFavorites.filter(x => typeof x === 'string') : []),
  favoritesOnly: false,
  activities: [],
  timer: null,
  dialogAction: null
};
function normalized(value) {
  return String(value ?? '').toLocaleLowerCase('zh-CN').replace(/[\s\-_./:[\]{}()]+/g, '');
}
function fuzzyScore(value, query) {
  const haystack = normalized(value), needle = normalized(query);
  if (!needle) return 0;
  if (haystack.includes(needle)) return 1000 - (haystack.length - needle.length);
  let cursor = 0, score = 0;
  for (const char of needle) {
    const found = haystack.indexOf(char, cursor);
    if (found < 0) return -1;
    score += Math.max(1, 80 - (found - cursor));
    cursor = found + 1;
  }
  return score;
}
const pages = {
  overview: ['总览', '一切就绪，准备联机。', '网络、伙伴和下一场冒险，都在这里。', 'YOUR NETWORK, AT A GLANCE'],
  networks: ['我的网络', '每一个网络，都是一个小世界。', '收藏常去的地方，或为下一次冒险创建一个新空间。', 'YOUR LITTLE WORLDS'],
  members: ['网络成员', '一起玩的，都在这里。', '找到伙伴，查看设备信息，管理网络成员。', 'BETTER TOGETHER'],
  public: ['发现网络', '去遇见，下一个联机伙伴。', '从你喜欢的游戏开始，发现更多共同的热爱。', 'FIND YOUR NEXT ADVENTURE'],
  chat: ['聊天与远程', '直接联系网络里的伙伴。', '优先调用 Radmin Viewer；没有安装时再打开官方客户端。', 'TALK TO YOUR TEAM'],
  activity: ['活动记录', '每一次变化，都有迹可循。', '只记录当前会话中实际观察到的变化和操作。', 'A LITTLE HISTORY'],
  settings: ['设置', '让这里，更像你的工作空间。', '调整外观、设备别名和刷新习惯。', 'MAKE YOURSELF AT HOME']
};
function go(page) {
  if (!pages[page]) page = 'overview';
  location.hash = page;
  if (state.page === page) renderPage();
}
function renderPage() {
  state.page = location.hash.slice(1) in pages ? location.hash.slice(1) : 'overview';
  const p = pages[state.page];
  $('#breadcrumb').textContent = p[0];
  $('#page-title').textContent = p[1];
  $('#page-description').textContent = p[2];
  $('#eyebrow').textContent = p[3];
  $$('.page').forEach(el => el.hidden = el.id !== `page-${state.page}`);
  $$('[data-page]').forEach(el => {
    el.classList.toggle('active', el.dataset.page === state.page);
    el.setAttribute('aria-current', el.dataset.page === state.page ? 'page' : 'false');
    el.setAttribute('title', pages[el.dataset.page][0]);
  });
  renderNetworks();
  renderMembers();
  renderChat();
  renderActivity();
  if (state.page === 'public' && !state.publicLoaded && !state.publicLoading) loadPublic('');
}
function theme(value) {
  const t = value === 'dark' ? 'dark' : 'light';
  document.documentElement.dataset.theme = t;
  storage.set('theme', t);
  $('#theme-setting').value = t;
}
let storedTheme = storage.get('theme', 'light');
// Migrate the plain text preference written by 0.2.
try {
  if (localStorage.getItem('rvpnkit-theme') === 'dark') storedTheme = 'dark';
} catch {}
theme(storedTheme);
$('#theme-toggle').onclick = () => theme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
$('#theme-setting').onchange = e => theme(e.target.value);
const interval = Number(storage.get('interval', 10));
$('#refresh-interval').value = [0, 5, 10, 30].includes(interval) ? String(interval) : '10';
$('#compact-setting').checked = storage.get('compact', false) === true;
document.body.classList.toggle('compact', $('#compact-setting').checked);
$('#compact-setting').onchange = e => {
  storage.set('compact', e.target.checked);
  document.body.classList.toggle('compact', e.target.checked);
};
function toast(message, error = false) {
  const el = document.createElement('div');
  el.className = 'toast' + (error ? ' error' : '');
  el.textContent = message;
  $('#toasts').append(el);
  setTimeout(() => el.remove(), 4500);
}
function log(message, error = false) {
  if (state.activities[0]?.message === message && state.activities[0]?.error === error) return;
  state.activities.unshift({
    time: new Date().toISOString(),
    message,
    error
  });
  state.activities.length = Math.min(100, state.activities.length);
  renderActivity();
}
async function api(path, body) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(path, {
      signal: controller.signal,
      cache: 'no-store',
      ...(body === undefined ? {} : {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
      })
    });
    const result = await response.json().catch(() => {
      throw new Error('服务返回了无法识别的数据');
    });
    if (!response.ok || result.ok !== true) throw new Error(result.error || `HTTP ${response.status}`);
    return result.data;
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('连接超时，请确认服务可用后重试');
    throw e;
  } finally {
    clearTimeout(timeout);
  }
}
async function loadApiSettings() {
  if (!$('#api-enabled')) return;
  try {
    const config = await api('/api/read-api');
    state.apiConfig = config;
    $('#api-enabled').checked = config.enabled === true;
    $('#api-bind-ip').value = config.bindIp || '127.0.0.1';
    $('#api-port').value = config.port || 8790;
    $('#api-token').value = '';
    $('#api-status').textContent = config.active ? '运行中：' + config.active : config.enabled ? '已启用但未运行' : '未启用';
  } catch (error) {
    $('#api-status').textContent = error.message;
  }
}
async function applyApiSettings() {
  const payload = {
    enabled: $('#api-enabled').checked,
    bindIp: $('#api-bind-ip').value.trim(),
    port: Number($('#api-port').value),
    token: $('#api-token').value
  };
  try {
    const config = await api('/api/read-api', payload);
    state.apiConfig = config;
    $('#api-token').value = '';
    $('#api-status').textContent = config.active ? '运行中：' + config.active : '未启用';
    toast(config.active ? '只读 API 已启动：' + config.active : '只读 API 已关闭');
  } catch (error) {
    toast(error.message, true);
  }
}
async function loadFirewallRules() {
  if (!$('#firewall-rules')) return;
  try {
    const data = await api('/api/firewall');
    $('#firewall-rules').innerHTML = (data.rules || []).map(rule => '<span class="firewall-rule mono">' + esc(rule.ip) + '<button class="icon-btn" data-firewall-ip="' + esc(rule.ip) + '" title="解除阻断" aria-label="解除阻断 ' + esc(rule.ip) + '">×</button></span>').join('') || '<span class="muted">暂无 RvpnKit 阻断规则</span>';
  } catch (error) {
    $('#firewall-rules').textContent = error.message;
  }
}
async function firewallAction(action, ip) {
  try {
    await api('/api/firewall', {action, ip});
    toast(action === 'block' ? '已阻断 ' + ip : '已解除阻断 ' + ip);
    await loadFirewallRules();
  } catch (error) {
    toast(error.message, true);
  }
}
function nets() {
  return state.data?.networks || [];
}
function currentNetwork() {
  return nets().find(n => n.guid === state.selectedNetwork);
}
function networkKind(network) {
  return network.publicNetwork === true ? 'public' : 'private';
}
function networkKindText(network) {
  return networkKind(network) === 'public' ? '公共网络' : '私有网络';
}
function latencyValue(member) {
  return member.virtualIp ? state.measuredLatencies[member.virtualIp] ?? null : null;
}
function latencyText(member) {
  const value = latencyValue(member);
  if (value == null) return memberStatus(member) === '在线' ? '测量中…' : '—';
  const bars = value <= 30 ? '▮▮▮▮' : value <= 80 ? '▮▮▮▫' : value <= 160 ? '▮▮▫▫' : '▮▫▫▫';
  return `${bars} ${value} ms`;
}
async function probeMembers(members) {
  if (state.probing) return;
  const ips = [...new Set(members.map(m => m.virtualIp).filter(Boolean))]
    .filter(ip => state.measuredLatencies[ip] === undefined)
    .slice(0, 32);
  if (!ips.length) return;
  state.probing = true;
  try {
    const data = await api('/api/probe', {ips});
    (data.results || []).forEach(item => {
      state.measuredLatencies[item.ip] = item.latencyMs;
    });
    storage.set('latencies', state.measuredLatencies);
    renderMembers();
  } catch {
    // The remote agent may not expose local ICMP probing; keep the snapshot usable.
  } finally {
    state.probing = false;
  }
}
function writable() {
  return state.connected && state.data?.canWrite && !state.data?.demo && !state.sending;
}
function updatePermissions() {
  const can = writable();
  const canManage = can && currentNetwork()?.role === 2;
  ['join-top', 'create-top', 'power-request'].forEach(id => $('#' + id).disabled = !can);
  $$('#alias-form input,#alias-form button').forEach(el => el.disabled = !can);
  $$('[data-batch]').forEach(el => el.disabled = !canManage);
  $$('[data-net-action]').forEach(el => el.disabled = !can || el.dataset.netAction === 'delete' && nets().find(n => n.guid === el.dataset.guid)?.role !== 2);
  $$('[data-public-join]').forEach(el => el.disabled = !can);
  $('#export-top').disabled = !state.data;
  $('#export-settings').disabled = !state.data;
  $('#copy-ip').disabled = !state.data?.self?.virtualIp;
  if ($('#chat-official')) $('#chat-official').disabled = state.data?.demo === true;
}
async function refresh(manual = false) {
  if (state.loading || state.sending) return;
  state.loading = true;
  $('#refresh').classList.add('spinning');
  $('#refresh').disabled = true;
  try {
    const data = await api('/api/state' + (manual ? '?refresh=1' : ''));
    const old = state.data;
    const wasConnected = state.connected;
    // The .NET agent also uses this public camelCase envelope.
    data.networks = (data.networks || []).map(n => ({
      ...n,
      members: (n.members || []).map(m => ({
        ...m,
        nodeId: String(m.nodeId)
      }))
    }));
    if (data.self) data.self.nodeId = String(data.self.nodeId);
    state.data = data;
    state.connected = true;
    if (!data.networks.some(n => n.guid === state.selectedNetwork)) {
      state.selectedNetwork = data.networks[0]?.guid || '';
      state.selection.clear();
      state.memberPage = 0;
    }
    const ids = new Set(currentNetwork()?.members.map(m => m.nodeId) || []);
    state.selection = new Set([...state.selection].filter(id => ids.has(id)));
    if (!wasConnected) log(data.demo ? '已打开只读演示工作空间' : '已连接服务，读取网络快照');
    if (old) {
      const oldNets = new Map(old.networks.map(n => [n.guid, n]));
      const newIds = new Set(data.networks.map(n => n.guid));
      data.networks.forEach(n => {
        const prev = oldNets.get(n.guid);
        if (!prev) log(`快照新增网络「${n.name}」`);else {
          const before = new Set(prev.members.map(m => m.nodeId));
          const after = new Set(n.members.map(m => m.nodeId));
          const added = [...after].filter(x => !before.has(x)).length;
          const removed = [...before].filter(x => !after.has(x)).length;
          if (added || removed) log(`「${n.name}」成员变化：新增 ${added}，移除 ${removed}`);
        }
      });
      old.networks.filter(n => !newIds.has(n.guid)).forEach(n => log(`快照已移除网络「${n.name}」`));
    }
    $('#connection-banner').hidden = true;
    $('#demo-banner').hidden = !data.demo;
    const time = new Date().toLocaleTimeString('zh-CN', {
      hour12: false
    });
    $('#sync-label').textContent = `同步于 ${time}`;
    $('#footer-status').textContent = `最近同步 ${time} · ${data.demo ? '演示模式' : data.canWrite ? '可读写连接' : '只读连接'}`;
    renderData();
    if (manual) toast('快照已更新');
  } catch (e) {
    state.connected = false;
    $('#connection-banner').hidden = false;
    $('#connection-banner').textContent = `暂时无法连接服务。请启动 Radmin VPN，或检查 --agent 地址后点击刷新。${state.data ? ' 当前显示上次快照。' : ''}`;
    $('#side-status').textContent = '服务连接中断';
    $('#hero-status').textContent = '服务暂不可用 · 等待重新连接';
    $('#sync-label').textContent = state.data ? '数据可能已过期' : '尚未连接';
    $('#permission').textContent = '服务不可用';
    $('#settings-permission').textContent = '服务不可用';
    $('#footer-status').textContent = '连接失败 · 可手动刷新重试';
    log(e.message, true);
    if (manual) toast(e.message, true);
  } finally {
    state.loading = false;
    $('#refresh').classList.remove('spinning');
    $('#refresh').disabled = false;
    ['side-dot', 'hero-dot', 'device-dot'].forEach(id => {
      $('#' + id).classList.toggle('good', state.connected);
      $('#' + id).classList.toggle('bad', !state.connected);
    });
    updatePermissions();
    schedule();
  }
}
function schedule() {
  clearTimeout(state.timer);
  const seconds = Number($('#refresh-interval').value);
  if (seconds && !document.hidden) state.timer = setTimeout(() => refresh(), seconds * 1000);
}
$('#refresh-interval').onchange = e => {
  storage.set('interval', Number(e.target.value));
  schedule();
};
document.addEventListener('visibilitychange', () => {
  if (document.hidden) clearTimeout(state.timer);else if (Number($('#refresh-interval').value)) refresh();
});
function renderData() {
  const data = state.data,
    me = data.self;
  $('#nav-networks').textContent = nets().length;
  const unique = new Set(nets().flatMap(n => n.members.map(m => m.nodeId))).size;
  $('#nav-members').textContent = unique;
  $('#top-alias').textContent = me?.alias || '本机设备';
  $('#device-name').textContent = me?.alias || '未读取到设备别名';
  $('#device-node').textContent = me ? `节点 #${me.nodeId}` : '快照未提供本机信息';
  $('#device-ip').textContent = me?.virtualIp || '未提供';
  $('#side-status').textContent = data.demo ? '只读演示空间' : '本地服务已连接';
  $('#hero-status').textContent = data.demo ? '演示空间 · 只读预览' : '已读取服务快照 · 准备好一起出发';
  $('#permission').textContent = data.demo ? '演示模式' : data.canWrite ? '可读写连接' : '只读连接';
  $('#settings-permission').textContent = $('#permission').textContent;
  if (document.activeElement !== $('#alias-input') && !$('#alias-input').dataset.edited) $('#alias-input').value = me?.alias || '';
  const favorites = nets().filter(n => state.favorites.has(n.guid)).length;
  const admins = nets().filter(n => n.role === 2).length;
  const stats = [['我的网络', nets().length, '个', 'network', `${admins} 个由我管理`], ['网络成员', unique, '位', 'users', '跨网络去重后的成员数'], ['成员记录', nets().reduce((s, n) => s + n.members.length, 0), '条', 'activity', '各网络成员记录总和'], ['收藏网络', favorites, '个', 'star', '把常去的地方放在心上']];
  $('#stats').innerHTML = stats.map(([label, value, unit, i, detail]) => `<article class="card stat"><div><div class="stat-label">${label}</div><div class="stat-value">${value}<small>${unit}</small></div><div class="stat-detail">${detail}</div></div><div class="stat-icon">${icon(i)}</div></article>`).join('');
  $('#overview-net-count').textContent = nets().length;
  renderNetworks();
  renderMembers();
  renderChat();
  renderActivity();
  updatePermissions();
}
function empty(title, description, i = 'network') {
  return `<div class="empty">${icon(i)}<h3>${esc(title)}</h3><p>${esc(description)}</p></div>`;
}
function networkCard(n, full = false) {
  const favorite = state.favorites.has(n.guid),
    guid = esc(n.guid);
  const role = n.role === 2 ? '管理员' : n.role === 1 ? '普通成员' : '角色未知';
  return `<article class="card network-card"><div class="network-card-top"><div class="network-avatar">${icon('network')}</div><span class="role-badge ${n.role === 2 ? 'admin' : ''}">${role}</span><button class="icon-btn favorite-btn ${favorite ? 'active' : ''}" data-favorite="${guid}" aria-label="${favorite ? '取消收藏' : '收藏'} ${esc(n.name)}" aria-pressed="${favorite}">${favorite ? '★' : '☆'}</button></div><h3 title="${esc(n.name)}">${esc(n.name)}</h3><p class="guid mono" title="${guid}">${esc(n.guid.slice(0, 8))} · ${esc(n.guid.slice(-8))}</p><div class="network-card-bottom"><div class="member-stack">${n.members.slice(0, 3).map(m => `<span class="mini-avatar" title="${esc(m.alias || m.nodeId)}">${esc(Array.from(m.alias || '#')[0])}</span>`).join('')}<small>${n.members.length} 位成员</small></div><button class="text-btn" data-members="${guid}">查看成员 <span>→</span></button></div>${full ? `<div class="network-actions"><button class="text-btn" data-copy-guid="${guid}">复制 GUID</button><button class="text-btn" data-net-action="enabled" data-guid="${guid}">启用 / 禁用</button><button class="text-btn danger" data-net-action="leave" data-guid="${guid}">离开</button>${n.role === 2 ? `<button class="text-btn danger" data-net-action="delete" data-guid="${guid}">删除</button>` : ''}</div>` : ''}</article>`;
}
function renderNetworks() {
  const selectedKind = $('#network-kind')?.value || 'all';
  const sorted = [...nets()].filter(n => selectedKind === 'all' || networkKind(n) === selectedKind).sort((a, b) => Number(state.favorites.has(b.guid)) - Number(state.favorites.has(a.guid)) || a.name.localeCompare(b.name, 'zh-CN'));
  $('#overview-networks').innerHTML = sorted.slice(0, 3).map(n => networkCard(n)).join('') || empty('还没有加入网络', '点击右上角「加入网络」，开始你的第一次联机。');
  $$('#overview-networks .network-card').forEach((card, index) => {
    const network = sorted[index];
    const badge = document.createElement('span');
    badge.className = 'role-badge network-kind ' + networkKind(network);
    badge.textContent = networkKindText(network);
    card.querySelector('.network-card-top')?.insertBefore(badge, card.querySelector('.favorite-btn'));
  });
  const q = $('#network-search').value.trim().toLocaleLowerCase(),
    role = $('#network-role').value;
  const filtered = sorted
    .map(n => ({n, score: fuzzyScore(`${n.name} ${n.guid} ${networkKindText(n)}`, q)}))
    .filter(item => item.score >= 0 && (!state.favoritesOnly || state.favorites.has(item.n.guid)) && (role === 'all' || (role === 'admin' ? item.n.role === 2 : item.n.role === 1)))
    .sort((a, b) => b.score - a.score || a.n.name.localeCompare(b.n.name, 'zh-CN'))
    .map(item => item.n);
  $('#network-summary').textContent = `共 ${nets().length} 个网络 · 当前显示 ${filtered.length} 个`;
  $('#all-networks').innerHTML = filtered.map(n => networkCard(n, true)).join('') || empty(q || state.favoritesOnly || role !== 'all' || selectedKind !== 'all' ? '没有匹配的网络' : '还没有加入网络', '试试其他筛选条件，或加入一个新的网络。');
  $$('#all-networks .network-card').forEach((card, index) => {
    const network = filtered[index];
    const badge = document.createElement('span');
    badge.className = `role-badge network-kind ${networkKind(network)}`;
    badge.textContent = networkKindText(network);
    card.querySelector('.network-card-top')?.insertBefore(badge, card.querySelector('.favorite-btn'));
  });
  updatePermissions();
}
function filteredMembers() {
  const q = $('#member-search').value.trim();
  return [...(currentNetwork()?.members || [])]
    .map(m => ({m, score: fuzzyScore(`${m.alias || ''} ${m.nodeId} ${m.cloudNodeIp || m.publicIp || ''} ${m.virtualIp || ''} ${m.virtualIpv6 || ''} ${m.connectionText || ''} ${m.online === true ? '在线' : m.online === false ? '离线' : '未知'}`, q)}))
    .filter(item => item.score >= 0)
    .sort((a, b) => $('#member-sort').value === 'id' ? BigInt(a.m.nodeId) < BigInt(b.m.nodeId) ? -1 : BigInt(a.m.nodeId) > BigInt(b.m.nodeId) ? 1 : 0 : b.score - a.score || (a.m.alias || a.m.nodeId).localeCompare(b.m.alias || b.m.nodeId, 'zh-CN'))
    .map(item => item.m);
}
function memberStatus(m) {
  return m.connectionOk === true || m.online === true ? '在线' : m.connectionOk === false || m.online === false ? '离线' : '未知';
}
function memberRole(m) {
  return m.role === 2 ? '管理员' : m.role === 1 ? '成员' : m.role === 3 ? '申请中' : '未知';
}
function memberChannel(m) {
  return m.connectionText || (m.channelType == null ? '未知通道' : ({0: '直连', 1: '中继'}[m.channelType] || `通道 ${m.channelType}`));
}
function renderMembers() {
  const select = $('#member-network'),
    options = nets().map(n => `<option value="${esc(n.guid)}">${esc(n.name)} · ${n.members.length} 人</option>`).join('');
  if (select.innerHTML !== options) select.innerHTML = options || '<option value="">暂无网络</option>';
  select.value = state.selectedNetwork;
  const list = filteredMembers(),
    max = Math.max(1, Math.ceil(list.length / 50));
  state.memberPage = Math.max(0, Math.min(state.memberPage, max - 1));
  const visible = list.slice(state.memberPage * 50, (state.memberPage + 1) * 50);
  state.visibleMembers = visible;
  $('#members-body').innerHTML = visible.map(m => `<tr><td><input type="checkbox" data-select-member="${esc(m.nodeId)}" ${state.selection.has(m.nodeId) ? 'checked' : ''} aria-label="选择 ${esc(m.alias || m.nodeId)}"></td><td><div class="member-label"><span class="avatar">${esc(Array.from(m.alias || '#')[0])}</span><div>${esc(m.alias || '未提供别名')}${m.nodeId === state.data?.self?.nodeId ? '<small>本机设备</small>' : ''}<small>${esc(memberRole(m))}</small></div></div></td><td class="mono">${esc(m.nodeId)}</td><td class="mono muted">${esc(m.virtualIp || '未提供')}<small>${esc(m.virtualIpv6 || '')}</small></td><td><span class="status-pill ${memberStatus(m) === '在线' ? 'online' : memberStatus(m) === '离线' ? 'offline' : ''}">${esc(memberStatus(m))}</span><small>${esc(memberChannel(m))} · ${esc(latencyText(m))}</small></td><td class="mono muted">${esc(m.cloudNodeIp || m.publicIp || '未提供')}</td><td><button class="text-btn" data-member-detail="${esc(m.nodeId)}">查看详情 ↗</button></td></tr>`).join('') || `<tr><td colspan="7">${empty('没有可显示的成员', currentNetwork() ? '试试其他搜索关键词。' : '先加入一个网络。', 'users')}</td></tr>`;
  probeMembers(visible);
  visible.forEach((member, index) => {
    const row = $('#members-body').rows[index];
    if (!row) return;
    const name = row.cells[1]?.querySelector('.member-label div');
    if (name) {
      const bars = document.createElement('span');
      bars.className = 'latency-bars';
      bars.textContent = latencyText(member).split(' ')[0];
      name.prepend(bars, ' ');
    }
    if (row.cells[4]) {
      const small = row.cells[4].querySelector('small');
      if (small) small.textContent = memberChannel(member) + ' · ' + latencyText(member);
    }
    if (row.cells[5]) row.cells[5].textContent = member.cloudNodeIp || member.publicIp || '未提供';
  });
  $('#members-summary').textContent = `共 ${list.length} 位匹配成员 · ${state.selection.size} 位已选`;
  $('#page-number').textContent = `${state.memberPage + 1} / ${max}`;
  $('#prev-page').disabled = state.memberPage === 0;
  $('#next-page').disabled = state.memberPage + 1 >= max;
  $('#batchbar').hidden = !state.selection.size;
  $('#selection-count').textContent = `已选 ${state.selection.size} 位成员`;
  $('#select-page').checked = visible.length > 0 && visible.every(m => state.selection.has(m.nodeId));
  $('#select-page').indeterminate = visible.some(m => state.selection.has(m.nodeId)) && !$('#select-page').checked;
  $('#export-members').disabled = !list.length;
  updatePermissions();
}
function renderChat() {
  const select = $('#chat-network');
  if (!select) return;
  const options = nets().map(n => `<option value="${esc(n.guid)}">${esc(n.name)} · ${n.members.length} 人</option>`).join('');
  if (select.innerHTML !== options) select.innerHTML = options || '<option value="">暂无网络</option>';
  select.value = state.selectedNetwork;
  const query = $('#chat-search').value.trim();
  const members = (currentNetwork()?.members || []).filter(m => fuzzyScore(`${m.alias || ''} ${m.nodeId} ${m.virtualIp || ''}`, query) >= 0);
  $('#chat-members').innerHTML = members.map(m => `<article class="card network-card"><div class="network-card-top"><div class="network-avatar">${icon('message')}</div><span class="role-badge">${esc(memberStatus(m))}</span></div><h3>${esc(m.alias || '未提供别名')}</h3><p class="guid mono">${esc(m.virtualIp || '无虚拟 IPv4')} · ${esc(m.nodeId)}</p><div class="network-actions"><button class="btn small" data-chat-action="chat" data-chat-ip="${esc(m.virtualIp || '')}">文本聊天</button><button class="btn small" data-chat-action="voice" data-chat-ip="${esc(m.virtualIp || '')}">语音聊天</button><button class="text-btn" data-chat-action="full_control" data-chat-ip="${esc(m.virtualIp || '')}">远程控制</button></div></article>`).join('') || empty('没有匹配成员', '先选择网络或换个关键词。', 'users');
}
function renderActivity() {
  const row = a => `<div class="activity-row"><span class="activity-icon ${a.error ? 'error' : ''}">${icon(a.error ? 'activity' : 'check')}</span><span class="activity-message">${esc(a.message)}</span><time class="activity-time" datetime="${a.time}">${new Date(a.time).toLocaleTimeString('zh-CN', {
    hour12: false
  })}</time></div>`;
  $('#overview-activity').innerHTML = state.activities.slice(0, 3).map(row).join('') || empty('暂时没有活动', '操作请求和网络变化会出现在这里。', 'activity');
  $('#activity-list').innerHTML = state.activities.map(row).join('') || empty('干干净净的新开始', '连接服务后，新的活动会记录在这里。', 'activity');
}
function openDialog(title, content, submit, action) {
  if ($('#action-dialog').open) $('#action-dialog').close();
  $('#dialog-title').textContent = title;
  $('#dialog-content').innerHTML = content;
  $('#dialog-submit').textContent = submit;
  $('#dialog-submit').hidden = !action;
  state.dialogAction = action;
  $('#action-dialog').showModal();
}
function joinDialog(create = false, name = '') {
  if (!writable()) return toast('当前连接无法写入，请检查服务权限', true);
  const passwordFields = create ? '<label class="form-field">网络密码<input id="dialog-password" type="password" minlength="6" maxlength="256" required placeholder="至少 6 个字符" autocomplete="new-password"></label><label class="form-field">确认密码<input id="dialog-confirm-password" type="password" minlength="6" maxlength="256" required placeholder="再次输入网络密码" autocomplete="new-password"></label>' : '<label class="form-field">网络密码（可选）<input id="dialog-password" type="password" minlength="6" maxlength="256" placeholder="没有密码就留空" autocomplete="current-password"></label>';
  openDialog(create ? '创建一个新网络' : '加入你的联机小队', `<label class="form-field">网络名称<input id="dialog-name" maxlength="20" required value="${esc(name)}" placeholder="输入完整网络名称" autocomplete="off"></label>${passwordFields}<p class="dialog-note">${create ? '网络名称最多 20 个字符，密码至少 6 个字符。邀请好友加入相同网络即可联机。' : '请使用网络管理员提供的名称与密码；留空表示无密码网络。'} 请求发出后，需要等待服务处理。</p>`, create ? '创建网络' : '加入网络', async () => {
    const name = $('#dialog-name').value.trim(),
      password = $('#dialog-password').value;
    if (!name) throw new Error('请填写网络名称');
    if (Array.from(name).length > 20) throw new Error('网络名称最多 20 个字符');
    if (password && Array.from(password).length < 6) throw new Error('网络密码至少 6 个字符');
    if (create && password !== $('#dialog-confirm-password').value) throw new Error('两次密码输入不一致');
    await command(`/api/networks/${create ? 'create' : 'join'}`, {
      name,
      password,
      ...(create ? {confirmPassword: $('#dialog-confirm-password').value} : {})
    }, `${create ? '创建' : '加入'}网络「${name}」`);
  });
}
async function command(path, body, label) {
  if (!writable()) throw new Error('当前连接不可写');
  state.sending = true;
  updatePermissions();
  try {
    await api(path, body);
    log(`服务已确认请求：${label}`);
    toast('服务已确认请求，正在重新读取状态');
  } catch (e) {
    log(`${label}：${e.message}`, true);
    throw e;
  } finally {
    state.sending = false;
    updatePermissions();
    schedule();
  }
  setTimeout(() => refresh(true), 600);
}
function confirmOperation(title, description, action) {
  openDialog(title, `<p class="dialog-note">${esc(description)}</p>`, '确认发送请求', action);
}
function networkOperation(guid, op) {
  const n = nets().find(n => n.guid === guid);
  if (!n) return;
  if (op === 'enabled') {
    openDialog('设置网络启用状态', `<p class="dialog-note">${esc(n.name)} · 当前状态：${n.enabled == null ? '未知' : n.enabled ? '已启用' : '已禁用'}。请选择目标状态。</p><label class="form-field">目标状态<select id="network-enabled"><option value="true" ${n.enabled === true ? 'selected' : ''}>启用网络</option><option value="false" ${n.enabled === false ? 'selected' : ''}>禁用网络</option></select></label>`, '发送请求', () => command(`/api/networks/${guid}/enabled`, {
      enabled: $('#network-enabled').value === 'true'
    }, `设置「${n.name}」启用状态`));
  } else confirmOperation(op === 'delete' ? '删除这个网络？' : '离开这个网络？', op === 'delete' ? `即将向服务请求删除「${n.name}」。这会影响该网络的所有成员，请确认你拥有管理权限。` : `即将离开「${n.name}」。重新加入可能需要密码。`, () => command(`/api/networks/${guid}/${op}`, {}, `${op === 'delete' ? '删除' : '离开'}「${n.name}」`));
}
async function batch(op) {
  const n = currentNetwork();
  if (!n || !state.selection.size) return;
  const labels = {
    approve: '批准加入',
    grant: '授予管理员',
    revoke: '撤销管理员',
    kick: '移出网络'
  };
  const members = n.members.filter(m => state.selection.has(m.nodeId));
  const guid = n.guid,
    name = n.name;
  confirmOperation(`${labels[op]} ${members.length} 位成员？`, `网络「${name}」。请确认拥有该网络的管理权限。操作将按顺序发送，失败会停止；此前已发送的请求不会撤回。`, async () => {
    if (!writable()) throw new Error('当前连接不可写');
    state.sending = true;
    updatePermissions();
    let completed = 0;
    try {
      for (const m of members) {
        await api(`/api/networks/${guid}/members/${m.nodeId}/${op}`, {
          name
        });
        completed++;
      }
      state.selection.clear();
      toast(`已发送 ${completed} 个请求，等待服务处理`);
    } finally {
      log(`${labels[op]}：已发送 ${completed} / ${members.length} 个请求`);
      state.sending = false;
      updatePermissions();
      setTimeout(() => refresh(), 600);
      schedule();
    }
  });
}
async function copy(value) {
  try {
    await navigator.clipboard.writeText(String(value));
    toast('已复制到剪贴板');
  } catch {
    openDialog('复制内容', `<label class="form-field">请手动选择并复制<input readonly value="${esc(value)}"></label>`, '关闭', null);
  }
}
function download(name, content, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([content], {
    type
  }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function exportSnapshot() {
  if (!state.data) return;
  const data = JSON.parse(JSON.stringify(state.data));
  data.networks.forEach(n => delete n.token);
  download('rvpnkit-snapshot.json', JSON.stringify({
    exportedAt: new Date().toISOString(),
    ...data
  }, null, 2));
  toast('快照已导出，请妥善保管成员信息');
}
function exportBackup() {
  if (!state.data) return toast('还没有可备份的状态', true);
  const data = JSON.parse(JSON.stringify(state.data));
  (data.networks || []).forEach(n => delete n.token);
  download('rvpnkit-backup.json', JSON.stringify({
    schema: 1,
    exportedAt: new Date().toISOString(),
    state: data,
    favorites: [...state.favorites],
    settings: {
      theme: document.documentElement.dataset.theme,
      interval: Number($('#refresh-interval').value),
      compact: $('#compact-setting').checked
    },
    note: '网络密码不会写入备份；导入只恢复本地清单和界面偏好。'
  }, null, 2));
  toast('换机备份已导出');
}
$('#backup-export').onclick = exportBackup;
$('#backup-import').onclick = () => $('#backup-file').click();
$('#backup-file').onchange = async e => {
  const file = e.target.files?.[0];
  if (!file) return;
  try {
    const bundle = JSON.parse(await file.text());
    if (bundle.schema !== 1 || !bundle.state || !Array.isArray(bundle.state.networks)) throw new Error('不是有效的 RvpnKit 备份');
    state.data = bundle.state;
    state.connected = false;
    state.favorites = new Set(Array.isArray(bundle.favorites) ? bundle.favorites.filter(x => typeof x === 'string') : []);
    storage.set('favorites', [...state.favorites]);
    const settings = bundle.settings || {};
    if (settings.theme) theme(settings.theme);
    if ([0, 5, 10, 30].includes(Number(settings.interval))) $('#refresh-interval').value = String(settings.interval);
    $('#compact-setting').checked = settings.compact === true;
    document.body.classList.toggle('compact', $('#compact-setting').checked);
    state.selectedNetwork = state.data.networks[0]?.guid || '';
    renderData();
    toast('备份已导入；服务中的网络成员需要手动核对');
  } catch (error) {
    toast(error.message || '备份读取失败', true);
  } finally {
    e.target.value = '';
  }
};
function csvField(v) {
  let s = String(v ?? '');
  if (/^[\s]*[=+\-@]/.test(s) || /^[\t\r\n]/.test(s)) s = "'" + s;
  return '"' + s.replaceAll('"', '""') + '"';
}
$('#export-members').onclick = () => {
  const rows = [['网络', '别名', '节点 ID', '虚拟 IPv4', '虚拟 IPv6', '云端节点 IP', '状态', '角色', '通道', '延迟 ms', '产品版本'], ...filteredMembers().map(m => [currentNetwork().name, m.alias, m.nodeId, m.virtualIp, m.virtualIpv6, m.cloudNodeIp || m.publicIp, memberStatus(m), memberRole(m), memberChannel(m), latencyValue(m) ?? '', m.productVersion || ''])];
  download('rvpnkit-members.csv', '\ufeff' + rows.map(row => row.map(csvField).join(',')).join('\r\n'), 'text/csv;charset=utf-8');
};
$('#export-top').onclick = exportSnapshot;
$('#export-settings').onclick = exportSnapshot;
$('#export-activity').onclick = () => download('rvpnkit-activity.json', JSON.stringify(state.activities, null, 2));
$('#clear-activity').onclick = () => {
  state.activities = [];
  renderActivity();
};
$('#clear-favorites').onclick = () => confirmOperation('清空本地收藏？', '仅移除本浏览器的收藏标记，不会退出任何网络。', async () => {
  state.favorites.clear();
  storage.set('favorites', []);
  if (state.data) renderData();
  toast('收藏已清空');
});
$('#refresh').onclick = () => refresh(true);
$('#join-top').onclick = () => joinDialog();
$('#create-top').onclick = () => joinDialog(true);
$('#copy-ip').onclick = () => copy(state.data?.self?.virtualIp || '');
$('#network-search').oninput = renderNetworks;
$('#network-role').onchange = renderNetworks;
$('#network-kind').onchange = renderNetworks;
$('#favorites-only').onclick = e => {
  state.favoritesOnly = !state.favoritesOnly;
  e.currentTarget.setAttribute('aria-pressed', state.favoritesOnly);
  renderNetworks();
};
$('#member-network').onchange = e => {
  state.selectedNetwork = e.target.value;
  state.selection.clear();
  state.memberPage = 0;
  renderMembers();
};
$('#member-search').oninput = () => {
  state.memberPage = 0;
  renderMembers();
};
$('#member-sort').onchange = renderMembers;
$('#chat-network').onchange = e => {
  state.selectedNetwork = e.target.value;
  renderChat();
};
$('#chat-search').oninput = renderChat;
$('#chat-official').onclick = async () => {
  try {
    await api('/api/desktop', {action: 'official'});
    toast('已打开官方客户端');
  } catch (error) {
    toast(error.message, true);
  }
};
$('#api-apply').onclick = applyApiSettings;
$('#firewall-form').onsubmit = e => {
  e.preventDefault();
  firewallAction('block', $('#firewall-ip').value.trim());
};
$$('[data-firewall-action]').forEach(el => {
  el.onclick = () => firewallAction(el.dataset.firewallAction, $('#firewall-ip').value.trim());
});
$('#prev-page').onclick = () => {
  state.memberPage--;
  renderMembers();
};
$('#next-page').onclick = () => {
  state.memberPage++;
  renderMembers();
};
$('#select-page').onchange = e => {
  state.visibleMembers.forEach(m => e.target.checked ? state.selection.add(m.nodeId) : state.selection.delete(m.nodeId));
  renderMembers();
};
$('#clear-selection').onclick = () => {
  state.selection.clear();
  renderMembers();
};
$('#batch-copy').onclick = () => copy([...state.selection].join('\n'));
$$('[data-batch]').forEach(el => el.onclick = () => batch(el.dataset.batch));
$('#alias-input').oninput = e => e.target.dataset.edited = 'true';
$('#alias-form').onsubmit = async e => {
  e.preventDefault();
  const alias = $('#alias-input').value.trim();
  if (!alias) return;
  try {
    await command('/api/alias', {
      alias
    }, '更新设备别名');
    delete $('#alias-input').dataset.edited;
  } catch (error) {
    toast(error.message, true);
  }
};
$('#power-request').onclick = () => openDialog('发送 VPN 电源请求', '<p class="dialog-note">快照不提供可靠的电源状态。请选择要请求的目标状态。</p><label class="form-field">目标状态<select id="power-target"><option value="true">开启 VPN</option><option value="false">关闭 VPN</option></select></label>', '发送请求', () => command('/api/power', {
  on: $('#power-target').value === 'true'
}, '切换 VPN 电源'));
async function loadPublic(search = '') {
  if (state.publicLoading) return;
  state.publicLoading = true;
  $('#public-submit').disabled = true;
  $('#public-summary').textContent = search ? '正在筛选公共网络…' : '正在后台读取公共网络列表…';
  try {
    const data = await api('/api/public?search=' + encodeURIComponent(search));
    state.publicResults = data.networks || [];
    state.publicLoaded = true;
    $('#public-summary').textContent = `找到 ${state.publicResults.length} 个可加入的网络`;
    $('#public-results').innerHTML = state.publicResults.map((name, index) => `<article class="card network-card"><div class="network-card-top"><span class="network-avatar">${icon('compass')}</span><span class="role-badge">公共网络</span></div><h3 title="${esc(name)}">${esc(name)}</h3><p class="guid">由 Radmin VPN 服务提供</p><button class="btn" data-public-join="${index}">加入网络 →</button></article>`).join('') || empty('没有找到匹配网络', '换个关键词再试一次。', 'compass');
    log(`搜索公共网络，返回 ${state.publicResults.length} 个结果`);
  } catch (error) {
    $('#public-summary').textContent = '搜索失败，可重试';
    toast(error.message, true);
    log(error.message, true);
  } finally {
    state.publicLoading = false;
    $('#public-submit').disabled = false;
    updatePermissions();
  }
}
$('#public-form').onsubmit = async e => {
  e.preventDefault();
  const search = $('#public-search').value.trim();
  await loadPublic(search);
};
$('#dialog-close').onclick = $('#dialog-cancel').onclick = () => $('#action-dialog').close();
$('#action-dialog').addEventListener('close', () => {
  $('#dialog-content').replaceChildren();
  state.dialogAction = null;
});
$('#action-form').onsubmit = async e => {
  e.preventDefault();
  if (!state.dialogAction) return $('#action-dialog').close();
  $('#dialog-submit').disabled = true;
  $('#dialog-cancel').disabled = true;
  $('#dialog-close').disabled = true;
  try {
    await state.dialogAction();
    $('#action-dialog').close();
  } catch (error) {
    toast(error.message, true);
  } finally {
    $('#dialog-submit').disabled = false;
    $('#dialog-cancel').disabled = false;
    $('#dialog-close').disabled = false;
  }
};
$('#action-dialog').addEventListener('cancel', e => {
  if ($('#dialog-submit').disabled) e.preventDefault();
});
document.addEventListener('click', e => {
  const b = e.target.closest('button');
  if (!b || b.disabled) return;
  if (b.dataset.page) go(b.dataset.page);
  if (b.dataset.go) go(b.dataset.go);
  if (b.dataset.favorite) {
    const g = b.dataset.favorite;
    state.favorites.has(g) ? state.favorites.delete(g) : state.favorites.add(g);
    storage.set('favorites', [...state.favorites]);
    if (state.data) renderData();
  }
  if (b.dataset.members) {
    state.selectedNetwork = b.dataset.members;
    state.selection.clear();
    state.memberPage = 0;
    go('members');
    renderMembers();
  }
  if (b.dataset.copyGuid) copy(b.dataset.copyGuid);
  if (b.dataset.netAction) networkOperation(b.dataset.guid, b.dataset.netAction);
  if (b.dataset.publicJoin !== undefined) joinDialog(false, state.publicResults[Number(b.dataset.publicJoin)]);
  if (b.dataset.chatAction) {
    api('/api/desktop', {action: b.dataset.chatAction, address: b.dataset.chatIp || undefined})
      .then(() => toast('已启动 Radmin 工具'))
      .catch(error => toast(error.message, true));
  }
  if (b.dataset.firewallIp) {
    firewallAction('unblock', b.dataset.firewallIp);
  }
  if (b.dataset.memberDetail) {
    const m = currentNetwork()?.members.find(m => m.nodeId === b.dataset.memberDetail);
    if (m) openDialog('成员详情', `<dl class="details"><dt>别名</dt><dd>${esc(m.alias || '未提供')}</dd><dt>节点 ID</dt><dd class="mono">${esc(m.nodeId)}</dd><dt>虚拟 IPv4</dt><dd class="mono">${esc(m.virtualIp || '未提供')}</dd><dt>虚拟 IPv6</dt><dd class="mono">${esc(m.virtualIpv6 || '未提供')}</dd><dt>云端节点 IP</dt><dd class="mono">${esc(m.cloudNodeIp || m.publicIp || '未提供')}</dd><dt>状态</dt><dd>${esc(memberStatus(m))}</dd><dt>角色</dt><dd>${esc(memberRole(m))}</dd><dt>通道</dt><dd>${esc(memberChannel(m))}</dd><dt>延迟</dt><dd>${esc(latencyText(m))}</dd><dt>产品版本</dt><dd>${esc(m.productVersion || '未提供')}</dd><dt>所在网络</dt><dd>${esc(currentNetwork().name)}</dd></dl>`, '复制节点 ID', () => copy(m.nodeId));
  }
});
document.addEventListener('change', e => {
  const id = e.target.dataset.selectMember;
  if (id) {
    e.target.checked ? state.selection.add(id) : state.selection.delete(id);
    renderMembers();
  }
});
document.addEventListener('keydown', e => {
  if (e.ctrlKey || e.altKey || e.metaKey || e.repeat || $('#action-dialog').open || e.target.closest('input,textarea,select,[contenteditable=true]')) return;
  if (e.key.toLowerCase() === 'r') {
    e.preventDefault();
    refresh(true);
  }
  if (e.key === '/') {
    const input = $(`#page-${state.page} input:not([type=checkbox])`);
    if (input) {
      e.preventDefault();
      input.focus();
    }
  }
});
window.addEventListener('hashchange', renderPage);
renderPage();
renderActivity();
loadApiSettings();
loadFirewallRules();
updatePermissions();
refresh();
