/* Raqib demo: the same pages as the Python site, run in the browser.
   The detection engine (engine.js) runs in a Web Worker; accounts live in this browser;
   incidents, reports and project info go to the artifact's shared database when it is available. */
{
  'use strict';

  // ---------- helpers and fixed data ----------
  const $ = (s, r = document) => r.querySelector(s);
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmt = (n) => Number(n || 0).toLocaleString('en-US');
  const pct = (v, d = 1) => (v == null || !Number.isFinite(v) ? '—' : (v * 100).toFixed(d) + '٪');
  const fix = (v, d = 3) => (Number.isFinite(v) ? v.toFixed(d) : '—');
  const g3 = (v) => (Number.isFinite(v) ? String(Number(v.toPrecision(3))) : '—');
  const stamp = () => new Date().toISOString().slice(0, 16).replace('T', ' ');
  const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

  const PAGES = JSON.parse($('#pages-data').textContent);
  const LAB = JSON.parse($('#lab-data').textContent);
  const CLASSES = ['Normal', 'DDoS', 'PortScan', 'BruteForce', 'Exfiltration'];
  const TYPES = ['camera', 'thermostat', 'smart_plug'];
  const NUM_COLS = ['packet_rate', 'avg_packet_size', 'byte_rate', 'flow_duration', 'unique_dst_ports',
    'syn_ratio', 'failed_conn_ratio', 'telnet_ratio', 'outbound_ratio'];
  const ATTACK_AR = { Normal: 'حركة طبيعية', DDoS: 'إغراق DDoS', PortScan: 'فحص المنافذ', BruteForce: 'تخمين كلمات المرور', Exfiltration: 'تسريب البيانات' };
  const DEVICE_AR = { camera: 'كاميرا', thermostat: 'منظّم حرارة', smart_plug: 'مقبس ذكي' };
  const FEATURE_AR = {
    packet_rate: 'معدل الحزم (حزمة/ث)', avg_packet_size: 'متوسط حجم الحزمة (بايت)', byte_rate: 'معدل البيانات (بايت/ث)',
    flow_duration: 'مدة الاتصال (ث)', unique_dst_ports: 'عدد المنافذ المقصودة', syn_ratio: 'نسبة حزم SYN',
    failed_conn_ratio: 'نسبة الاتصالات الفاشلة', telnet_ratio: 'نسبة اتصالات Telnet', outbound_ratio: 'نسبة البيانات الخارجة',
  };
  const MODEL_KEYS = ['if', 'ae', 'rf'];
  const MODEL_NAMES = { if: 'Isolation Forest', ae: 'Autoencoder', rf: 'Random Forest', vote: 'تصويت الأغلبية' };
  const POLICIES = { majority: 'أغلبية النماذج (2 من 3)', any: 'أي نموذج يكفي', all: 'كل النماذج معاً', if: 'Isolation Forest وحده', ae: 'Autoencoder وحده', rf: 'Random Forest وحده' };
  const DEVICES = [
    ['كاميرا البوابة الرئيسية', 'camera', '192.168.10.21'], ['كاميرا موقف السيارات', 'camera', '192.168.10.22'],
    ['كاميرا الممر الشرقي', 'camera', '192.168.10.23'], ['منظّم حرارة المختبر', 'thermostat', '192.168.10.41'],
    ['منظّم حرارة القاعة 3', 'thermostat', '192.168.10.42'], ['منظّم حرارة المكتبة', 'thermostat', '192.168.10.43'],
    ['منظّم حرارة غرفة الخوادم', 'thermostat', '192.168.10.44'], ['مقبس الطابعة', 'smart_plug', '192.168.10.61'],
    ['مقبس آلة القهوة', 'smart_plug', '192.168.10.62'], ['مقبس المكيّف', 'smart_plug', '192.168.10.63'],
    ['مقبس إضاءة الممر', 'smart_plug', '192.168.10.64'], ['مقبس شاشة الاستقبال', 'smart_plug', '192.168.10.65'],
  ].map(([name, type, ip], id) => ({ id, name, type, ip }));
  const SITE_DEFAULT = {
    title_en: 'Machine Learning-Based Anomaly Detection in IoT', title_ar: 'كشف الشذوذ في شبكات إنترنت الأشياء باستخدام تعلّم الآلة',
    researchers: 'علي محمد قاسم عيسى', supervisor: '', university: 'جامعة شط العرب', college: 'كلية العلوم',
    department: 'قسم علوم الحاسوب', year: '2025 – 2026', email: '',
  };
  const SITE_LABELS = {
    title_en: 'عنوان البحث بالإنجليزية', title_ar: 'عنوان البحث بالعربية', researchers: 'الباحثون (اسم في كل سطر)',
    supervisor: 'المشرف', university: 'الجامعة', college: 'الكلية', department: 'القسم', year: 'العام الدراسي', email: 'بريد التواصل (اختياري)',
  };
  const attackName = (k) => ATTACK_AR[k] || (k && k !== 'unknown' ? k : 'نمط غير معروف');

  // ---------- storage: this browser, and the shared database when the viewer provides it ----------
  const local = {
    get(key, fallback) { try { const v = localStorage.getItem('raqib-demo.' + key); return v ? JSON.parse(v) : fallback; } catch (e) { return fallback; } },
    set(key, value) { try { localStorage.setItem('raqib-demo.' + key, JSON.stringify(value)); } catch (e) { /* storage unavailable */ } },
  };
  // remote = what the shared database holds; local = what this browser kept; pending = writes in flight.
  // The lists the pages read (shared.incidents / shared.reports) are always the merge of the three.
  const CAP = { incidents: 300, reports: 100 };
  const shared = {
    db: null, blocked: false, wrote: false,
    remote: { incidents: [], reports: [] },
    pending: { incidents: new Map(), reports: new Map() },
    incidents: local.get('incidents', []), reports: local.get('reports', []),
    site: Object.assign({}, SITE_DEFAULT, local.get('site', {})),
  };

  function docsOf(snap) {
    const list = Array.isArray(snap) ? snap : (snap && (snap.docs || snap.results || snap.items)) || [];
    return list.map((d) => {
      const data = typeof d.data === 'function' ? d.data() : (d.data && typeof d.data === 'object' ? d.data : d);
      return Object.assign({}, data, { id: d.id || (data && data.id) });
    }).filter((x) => x && x.id);
  }
  function docOf(snap) {
    if (!snap) return null;
    if (typeof snap.data === 'function') return snap.exists === false ? null : snap.data();
    return snap.data && typeof snap.data === 'object' ? snap.data : snap;
  }
  const byNewest = (a, b) => String(b.created || '').localeCompare(String(a.created || ''));

  function merge(kind) {
    const seen = new Set(), out = [];
    const all = [...shared.pending[kind].values(), ...shared.remote[kind], ...local.get(kind, [])];
    for (const x of all) if (x && x.id && !seen.has(x.id)) { seen.add(x.id); out.push(x); }
    shared[kind] = out.sort(byNewest).slice(0, CAP[kind]);
  }

  async function runtime() {
    // window.claude is provided by the artifact viewer; give it a moment in case it arrives after this script.
    for (let i = 0; i < 20 && !(window.claude && window.claude.use); i++) await new Promise((r) => setTimeout(r, 150));
    return window.claude && window.claude.use ? window.claude : null;
  }

  async function connectDb() {
    let db = null;
    try { const rt = await runtime(); db = rt ? await rt.use('db') : null; } catch (e) { db = null; }
    if (!db) { renderStorageNote(); return; }
    shared.db = db;
    const query = (name, n) => { try { return db.collection(name).orderBy('created', 'desc').limit(n); } catch (e) { return db.collection(name); } };
    const watch = (ref, apply) => {
      try { ref.onSnapshot((snap) => { apply(snap); refresh(); }, () => {}); } catch (e) { /* not available in this view */ }
    };
    watch(query('incidents', CAP.incidents), (s) => { shared.remote.incidents = docsOf(s); merge('incidents'); });
    watch(query('reports', CAP.reports), (s) => { shared.remote.reports = docsOf(s); merge('reports'); });
    watch(db.doc('site/settings'), (s) => { const d = docOf(s); if (d) shared.site = Object.assign({}, SITE_DEFAULT, d); });
    renderStorageNote();
  }

  async function saveShared(kind, record) {
    shared.pending[kind].set(record.id, record); merge(kind);
    let savedShared = false;
    if (shared.db && !shared.blocked) {
      try {
        await shared.db.collection(kind).doc(record.id).set(record);
        shared.remote[kind] = [record].concat(shared.remote[kind].filter((x) => x.id !== record.id));
        savedShared = true;
        if (!shared.wrote) { shared.wrote = true; renderStorageNote(); }
      } catch (e) { shared.blocked = true; renderStorageNote(); }
    }
    if (!savedShared) local.set(kind, [record].concat(local.get(kind, []).filter((x) => x.id !== record.id)).slice(0, CAP[kind]));
    shared.pending[kind].delete(record.id); merge(kind);
  }
  // Returns false when the record lives in the shared database and this viewer may not delete it.
  async function removeShared(kind, id) {
    local.set(kind, local.get(kind, []).filter((x) => x.id !== id));
    shared.pending[kind].delete(id);
    let ok = true;
    if (shared.remote[kind].some((x) => x.id === id)) {
      if (shared.db && !shared.blocked) {
        try { await shared.db.collection(kind).doc(id).delete(); shared.remote[kind] = shared.remote[kind].filter((x) => x.id !== id); }
        catch (e) { ok = false; }
      } else ok = false;
    }
    merge(kind);
    return ok;
  }
  async function saveSite(values) {
    shared.site = Object.assign({}, SITE_DEFAULT, values);
    if (shared.db && !shared.blocked) {
      try { await shared.db.doc('site/settings').set(values); return true; } catch (e) { /* only the owner and editors may change it */ }
    }
    local.set('site', values);
    return false;
  }
  function renderStorageNote() {
    $('#storage-note').textContent = !shared.db ? 'الحوادث والتقارير تُحفظ في هذا المتصفح فقط.'
      : shared.blocked ? 'ترى السجلات المشتركة، أما سجلاتك فتُحفظ في هذا المتصفح لأن الكتابة في قاعدة البيانات المشتركة غير متاحة لك.'
      : shared.wrote ? 'الحوادث والتقارير تُحفظ في قاعدة بيانات الرابط المشتركة.'
      : 'متصل بقاعدة بيانات الرابط المشتركة.';
  }

  // ---------- demo accounts (kept in this browser) ----------
  const auth = { users: local.get('users', []), current: null };
  auth.current = auth.users.find((u) => u.id === local.get('session', '')) || null;
  async function digest(text) {
    try {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
      return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
      let h = 2166136261;
      for (const ch of text) { h ^= ch.codePointAt(0); h = Math.imul(h, 16777619) >>> 0; }
      return 'f' + h.toString(16);
    }
  }
  function signIn(user) { auth.current = user; local.set('session', user.id); }
  async function createUser(name, username, password) {
    const salt = uid();
    const user = { id: uid(), name, username, salt, hash: await digest(salt + password), role: auth.users.length ? 'analyst' : 'admin', created: stamp() };
    auth.users.push(user);
    local.set('users', auth.users);
    return user;
  }

  // ---------- page frame ----------
  const view = $('#view');
  const PUBLIC = ['home', 'about', 'team', 'references', 'login', 'register'];
  const NAV = [['home', 'الرئيسية'], ['about', 'عن البحث'], ['team', 'الفريق'], ['references', 'المراجع'], null,
    ['live', 'المراقبة الحية'], ['lab', 'المختبر'], ['data', 'بياناتك'], ['incidents', 'سجل الحوادث'], ['reports', 'التقارير']];
  let route = 'home', base = 'home', afterLogin = 'live', flashMsg = null, incidentFilter = 'all', armed = null;

  function flash(text, kind) { flashMsg = { text, kind }; }
  function renderFrame() {
    const u = auth.current;
    $('#account').innerHTML = u
      ? `<span class="who"><b>${esc(u.name)}</b><small>${u.role === 'admin' ? 'مدير' : 'محلل'}</small></span><button class="btn btn-small" type="button" data-action="logout">خروج</button>`
      : '<a class="btn btn-small" href="#login">دخول</a><a class="btn btn-small btn-primary" href="#register">حساب جديد</a>';
    const links = NAV.map((item) => {
      if (!item) return '<span class="tabs-sep" aria-hidden="true"></span>';
      const [key, label] = item;
      const on = key === base || (key === 'reports' && base === 'report');
      return `<a href="#${key}"${on ? ' aria-current="page"' : ''}>${label}${!u && !PUBLIC.includes(key) ? '<i class="lock" aria-label="يحتاج دخول"></i>' : ''}</a>`;
    });
    if (u && u.role === 'admin') links.push(`<a href="#admin"${base === 'admin' ? ' aria-current="page"' : ''}>الإدارة</a>`);
    $('#nav').innerHTML = links.join('');
    const activeLink = $('#nav [aria-current]');
    if (activeLink) activeLink.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    const s = shared.site;
    $('#footer').innerHTML = `<span>رقيب · ${esc(s.title_en)}</span><span>${esc(s.department)} · ${esc(s.college)} · ${esc(s.university)} · ${esc(s.year)}</span>`;
  }

  function show() {
    let name = (location.hash || '').slice(1) || 'home';
    let b = name.startsWith('report-') ? 'report' : name;
    if (![...PUBLIC, 'live', 'lab', 'data', 'incidents', 'reports', 'report', 'admin'].includes(b)) { name = 'home'; b = 'home'; }
    if (!PUBLIC.includes(b) && !auth.current) {
      afterLogin = name;
      flash('صفحات النظام تحتاج حساباً: سجّل الدخول أو جرّب الدخول السريع.', 'error');
      if (location.hash !== '#login') { location.hash = 'login'; return; }
      name = 'login'; b = 'login';
    }
    if (b === 'admin' && auth.current.role !== 'admin') { name = 'home'; b = 'home'; }
    route = name; base = b; armed = null;
    renderFrame();
    renderView();
    window.scrollTo(0, 0);
    if (b === 'live') startLive();
  }
  function go(name) { if (location.hash === '#' + name) show(); else location.hash = name; }
  // keepNote: a re-render caused by new data (not by the user) keeps the message already on screen.
  let shownFlash = null;
  function renderView(keepNote) {
    if (flashMsg) { shownFlash = flashMsg; flashMsg = null; } else if (keepNote !== true) shownFlash = null;
    const note = shownFlash ? `<p class="flash flash-${shownFlash.kind}" role="status">${esc(shownFlash.text)}</p>` : '';
    view.innerHTML = note + (VIEWS[base] || VIEWS.home)();
    view.querySelectorAll('[data-set]').forEach((el) => { el.textContent = shared.site[el.dataset.set] || ''; });
    if (base === 'live') drawPanel();
  }
  let refreshQueued = false;
  function refresh() {
    if (refreshQueued) return;
    refreshQueued = true;
    requestAnimationFrame(() => {
      refreshQueued = false;
      renderFrame();
      if (['team', 'incidents', 'reports', 'report', 'admin', 'home', 'about'].includes(base) && !view.contains(document.activeElement)) renderView(true);
    });
  }

  // ---------- views ----------
  const VIEWS = {
    home: () => PAGES.home,
    about: () => PAGES.about,
    references: () => PAGES.references,
    team: () => {
      const s = shared.site;
      const people = s.researchers.split('\n').map((n) => n.trim()).filter(Boolean)
        .map((n) => `<div class="panel person"><span class="avatar" aria-hidden="true">${esc(n[0])}</span><b>${esc(n)}</b><span class="muted">باحث</span></div>`);
      if (s.supervisor) people.push(`<div class="panel person"><span class="avatar avatar-sup" aria-hidden="true">${esc(s.supervisor[0])}</span><b>${esc(s.supervisor)}</b><span class="muted">المشرف</span></div>`);
      else if (auth.current && auth.current.role === 'admin') people.push('<a class="panel person person-empty" href="#admin"><b>أضف اسم المشرف</b><span class="muted">من صفحة الإدارة</span></a>');
      return `<section class="view-head"><h1>الفريق والمشرف</h1><p>${esc(s.department)} · ${esc(s.college)} · ${esc(s.university)} · العام الدراسي ${esc(s.year)}</p></section>
        <section class="people">${people.join('')}</section>
        <section class="panel prose"><h2>عن المشروع</h2><p>«رقيب» مشروع تخرج بعنوان «${esc(s.title_ar)}» (${esc(s.title_en)}). بُني بلغة Python: الموقع بإطار Flask، والنماذج بمكتبة scikit-learn، وقاعدة البيانات SQLite. هذه الصفحة جزء من النموذج التجريبي الذي يعمل داخل المتصفح.</p>${s.email ? `<p>للتواصل: <span class="data">${esc(s.email)}</span></p>` : ''}</section>`;
    },
    login: () => `<section class="auth panel"><h1>تسجيل الدخول</h1>
      <p class="muted">صفحات النظام (المراقبة والمختبر وبياناتك والسجلات) تحتاج حساباً. في هذا النموذج تُحفظ الحسابات في متصفحك فقط.</p>
      <form class="auth-form" data-form="login">
        <label class="field">اسم المستخدم <input type="text" name="username" autocomplete="username" required dir="ltr"></label>
        <label class="field">كلمة المرور <input type="password" name="password" autocomplete="current-password" required dir="ltr"></label>
        <button class="btn btn-primary" type="submit">دخول</button>
      </form>
      <div class="quick"><b>تريد التجربة فقط؟</b><span class="muted">ادخل بحساب تجريبي جاهز دون تسجيل.</span><button class="btn" type="button" data-action="quick">دخول سريع بحساب تجريبي</button></div>
      <p class="muted">ليس لديك حساب؟ <a href="#register">أنشئ حساباً جديداً</a></p></section>`,
    register: () => `<section class="auth panel"><h1>إنشاء حساب</h1>
      ${auth.users.length ? '' : '<p class="flash flash-ok">لا يوجد أي حساب بعد في هذا المتصفح: أول حساب يُنشأ يصبح مدير الموقع.</p>'}
      <form class="auth-form" data-form="register">
        <label class="field">الاسم الكامل <input type="text" name="name" required maxlength="80"></label>
        <label class="field">اسم المستخدم (حروف إنجليزية وأرقام) <input type="text" name="username" required maxlength="40" autocomplete="username" dir="ltr"></label>
        <label class="field">كلمة المرور (8 أحرف على الأقل) <input type="password" name="password" required minlength="8" autocomplete="new-password" dir="ltr"></label>
        <label class="field">تأكيد كلمة المرور <input type="password" name="confirm" required minlength="8" autocomplete="new-password" dir="ltr"></label>
        <button class="btn btn-primary" type="submit">إنشاء الحساب</button>
      </form>
      <p class="muted">لديك حساب؟ <a href="#login">سجّل الدخول</a></p></section>`,
    live: () => `<section class="view-head"><h1>المراقبة الحية</h1><p>اثنا عشر جهازاً ذكياً ترسل سجلاً عن حركتها كل ثانية، والنماذج الثلاثة تحكم على كل سجل. أطلق هجوماً من المحاكي وراقب كيف يُكتشف.</p></section>
      <section class="panel" aria-label="التحكم في المحاكاة"><div class="control-row">
        <button class="btn" type="button" data-action="run">${live.settings.running ? 'إيقاف مؤقت' : 'تشغيل'}</button>
        <label class="field">السرعة <select id="speed">${[1, 2, 4].map((v) => `<option value="${v}"${v === live.settings.speed ? ' selected' : ''}>${v}×</option>`).join('')}</select></label>
        <label class="field">قرار الإنذار <select id="policy">${Object.entries(POLICIES).map(([k, v]) => `<option value="${k}"${k === live.settings.policy ? ' selected' : ''}>${v}</option>`).join('')}</select></label>
        <label class="field">الحساسية (مئين العتبة) <select id="sensitivity">${[95, 99, 99.5, 99.9].map((v) => `<option value="${v}"${v === live.settings.pct ? ' selected' : ''}>${v}</option>`).join('')}</select></label>
        <label class="check"><input type="checkbox" id="auto"${live.settings.auto ? ' checked' : ''}> هجمات تلقائية</label>
        <button class="btn" type="button" data-action="reset">تصفير الإحصاءات</button>
      </div></section>
      <section class="panel" aria-label="محاكي الهجمات"><h2 class="panel-title">محاكي الهجمات</h2>
        <form class="control-row" data-form="attack">
          <label class="field">الجهاز المستهدف <select name="device">${DEVICES.map((d) => `<option value="${d.id}"${d.id === 4 ? ' selected' : ''}>${esc(d.name)}</option>`).join('')}</select></label>
          <label class="field">نوع الهجوم <select name="kind">${CLASSES.slice(1).map((c, i) => `<option value="${i + 1}">${ATTACK_AR[c]}</option>`).join('')}</select></label>
          <label class="field">المدة <select name="duration"><option value="15">15 ثانية</option><option value="30" selected>30 ثانية</option><option value="60">60 ثانية</option></select></label>
          <label class="check"><input type="checkbox" name="stealthy" value="1"> نسخة خفية</label>
          <button class="btn btn-danger" type="submit">إطلاق الهجوم</button>
          <button class="btn" type="button" data-action="stop">إيقاف كل الهجمات</button>
        </form></section>
      <div id="panel"></div>`,
    lab: () => `<section class="view-head"><h1>المختبر</h1><p>تقييم النماذج الثلاثة على ${fmt(LAB.rows)} سجل محاكى: 70٪ للتدريب و30٪ للاختبار. هذه النتائج والأشكال أنتجتها نسخة بايثون نفسها.</p></section>${reportHtml(LAB, 'figures/')}`,
    data: () => dataView(),
    incidents: () => incidentsView(),
    reports: () => reportsView(),
    report: () => reportView(),
    admin: () => adminView(),
  };

  // ---------- report (same layout as _report.html) ----------
  function reportHtml(r, figureBase) {
    const rows = r.table.map((row) => `<tr><td><i class="sw sw-${row.key}"></i>${esc(row.name)}</td>${['accuracy', 'precision', 'recall', 'f1', 'auc', 'fpr'].map((m) => `<td class="data">${fix(row[m])}</td>`).join('')}
      <td>${row.train_s == null ? '—' : `<span class="data">${fix(row.train_s, 1)}</span> ث`}</td><td class="data">${row.micros == null ? '—' : Math.round(row.micros) + ' µs'}</td></tr>`).join('');
    const figs = figureBase && r.figures ? `<section class="figs">${r.figures.map((f) => `<figure class="panel fig${f.wide ? ' fig-wide' : ''}"><img src="${figureBase}${esc(f.file)}" alt="${esc(f.caption)}" loading="lazy"><figcaption>${esc(f.caption)}</figcaption></figure>`).join('')}</section>` : '';
    const perAttack = r.per_attack.map((p) => `<tr><td>${esc(attackName(p.type))}</td><td class="data">${fmt(p.count)}</td>${MODEL_KEYS.concat('vote').map((k) => `<td class="data">${pct(p[k], 0)}</td>`).join('')}</tr>`).join('');
    let zero = '';
    if (r.zero_day && r.zero_day.length) {
      const worst = r.zero_day.slice().sort((a, b) => a.rf - b.rf)[0];
      zero = `<section class="panel"><h2 class="panel-title">تجربة الهجوم المجهول (Zero-day)</h2><div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>الهجوم المخفي</th><th>RF</th><th>IF</th><th>AE</th></tr></thead><tbody>
        ${r.zero_day.map((z) => `<tr><td>${esc(attackName(z.type))}</td>${['rf', 'if', 'ae'].map((k) => `<td class="data">${pct(z[k], 0)}</td>`).join('')}</tr>`).join('')}
        </tbody></table></div><p class="insight">عندما أخفينا «${esc(attackName(worst.type))}» عن Random Forest كشف ${pct(worst.rf, 0)} منه فقط، بينما كشف Autoencoder ${pct(worst.ae, 0)}، لأن النماذج غير المُشرفة تتعلم شكل الحركة الطبيعية ولا تحتاج أن ترى الهجوم من قبل.</p></section>`;
    }
    return `<section class="panel"><h2 class="panel-title">ملخص التجربة</h2><dl class="facts">
        <div><dt>السجلات بعد التنظيف</dt><dd class="data">${fmt(r.rows)}</dd></div>
        <div><dt>الخصائص بعد المعالجة</dt><dd class="data">${fmt(r.features)}</dd></div>
        <div><dt>التدريب / الاختبار</dt><dd class="data">${fmt(r.train_rows)} / ${fmt(r.test_rows)}</dd></div>
        <div><dt>نسبة الهجمات</dt><dd class="data">${pct(r.attack_share)}</dd></div>
        <div><dt>دورات Autoencoder</dt><dd class="data">${r.ae_epochs} (الأفضل ${r.ae_best_epoch})</dd></div></dl></section>
      <section class="panel"><h2 class="panel-title">مقارنة النماذج على بيانات الاختبار</h2><div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>النموذج</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th><th>ROC-AUC</th><th>FPR</th><th>زمن التدريب</th><th>زمن السجل</th></tr></thead>
        <tbody>${rows}</tbody></table></div>
        <p class="note">العتبة: المئين 99 من درجات الحركة الطبيعية في التدريب، فيُتوقع أن يخطئ كل نموذج غير مُشرف في نحو 1٪ من الحركة الطبيعية. تصويت الأغلبية يُطلق الإنذار عندما يتفق نموذجان من ثلاثة.</p></section>
      ${figs}
      <div class="grid2"><section class="panel"><h2 class="panel-title">نسبة الكشف لكل نوع هجوم</h2><div class="tbl-wrap"><table class="tbl">
        <thead><tr><th>الهجوم</th><th>العدد</th><th>IF</th><th>AE</th><th>RF</th><th>الأغلبية</th></tr></thead><tbody>${perAttack}</tbody></table></div></section>${zero}</div>`;
  }

  // ---------- engines (Web Worker from engine.js, inline fallback) ----------
  function createEngine(onMsg) {
    const E = { ok: false, inline: false, log: [], w: null };
    const attach = (w) => { w.onmessage = (ev) => { const m = ev.data; if (m && m.type === 'hello') { E.ok = true; E.log = []; return; } onMsg(m); }; };
    const fallback = () => {
      if (E.inline) return;
      try { if (E.w && E.w.terminate) E.w.terminate(); } catch (e) { /* ignore */ }
      E.inline = true;
      const w = { onmessage: null, terminate() {} };
      const scope = { onmessage: null, postMessage: (m) => setTimeout(() => w.onmessage && w.onmessage({ data: m }), 0) };
      ENGINE(scope); // eslint-disable-line no-undef
      w.postMessage = (m) => setTimeout(() => scope.onmessage && scope.onmessage({ data: m }), 0);
      E.w = w; attach(w); E.ok = true;
      const replay = E.log.slice(); E.log = [];
      replay.forEach((m) => w.postMessage(m));
    };
    try {
      const src = '(' + ENGINE.toString() + ')(self);'; // eslint-disable-line no-undef
      E.w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
      attach(E.w);
      E.w.onerror = (e) => { if (!E.ok) { if (e.preventDefault) e.preventDefault(); fallback(); } };
      E.w.postMessage({ type: 'hello' });
      setTimeout(() => { if (!E.ok) fallback(); }, 4000);
    } catch (e) { fallback(); }
    E.send = (m) => { if (!E.ok && !E.inline) E.log.push(m); E.w.postMessage(m); };
    return E;
  }

  // ---------- live monitoring ----------
  const live = {
    engine: null, ready: false, progress: 0, tick: 0, devs: [], hist: DEVICES.map(() => []), m: null, perf: null,
    incidents: new Map(), saved: new Set(), featMeta: null, baseline: null, sel: 4, launches: {}, error: null,
    settings: { running: true, speed: 1, policy: 'majority', pct: 99, auto: true },
  };
  function startLive() {
    if (live.engine) return;
    live.engine = createEngine(onLive);
    live.engine.send({ type: 'init', devices: DEVICES.map((d) => TYPES.indexOf(d.type)), pct: 99, policy: 'majority', speed: 1, auto: true, run: true });
  }
  let panelQueued = false;
  function onLive(m) {
    if (m.type === 'progress') live.progress = m.pct || 0;
    else if (m.type === 'ready') { live.ready = true; live.featMeta = m.featMeta; live.baseline = m.baseline; }
    else if (m.type === 'state') live.settings.running = m.running;
    else if (m.type === 'error') live.error = m.code;
    else if (m.type === 'tick') {
      live.tick = m.tick; live.m = m.m; live.perf = m.perf;
      m.devs.forEach((d, i) => { live.devs[i] = d; const h = live.hist[i]; h.push({ r: d.r, agg: d.agg, truth: d.truth }); if (h.length > 90) h.shift(); });
      m.incidents.forEach((inc) => {
        live.incidents.set(inc.id, inc);
        if (inc.status === 'resolved' && !live.saved.has(inc.id)) { live.saved.add(inc.id); saveIncident(inc); }
      });
    }
    if (base === 'live' && !panelQueued) { panelQueued = true; requestAnimationFrame(() => { panelQueued = false; drawPanel(); }); }
  }
  function topVote(votes) { let best = 0, k = 0; votes.forEach((v, i) => { if (i > 0 && v > best) { best = v; k = i; } }); return best > 0 ? CLASSES[k] : 'unknown'; }
  function saveIncident(inc) {
    const d = DEVICES[inc.dev], launch = live.launches[inc.dev];
    const by = inc.truth && launch && inc.start <= launch.until && inc.last >= launch.from ? launch.name : null;
    saveShared('incidents', {
      id: uid(), device: d.name, ip: d.ip, device_type: d.type, start: inc.start, end: inc.end, duration: inc.end - inc.start + 1,
      peak: Math.round(inc.peak * 10) / 10, alarms: inc.records, hits_if: inc.hits[0], hits_ae: inc.hits[1], hits_rf: inc.hits[2],
      guess: topVote(inc.votes), truth: inc.truth ? CLASSES[inc.truthKind] : null, launched_by: by, created: stamp(),
    });
  }
  const points = (values, w, h, len) => { const step = w / (len - 1), start = len - values.length; return values.map((v, i) => `${((start + i) * step).toFixed(1)},${(h - (v / 100) * h).toFixed(1)}`).join(' '); };
  const clock = (t) => [Math.floor(t / 3600), Math.floor(t / 60) % 60, t % 60].map((v) => String(v).padStart(2, '0')).join(':');

  function drawPanel() {
    const box = $('#panel');
    if (!box) return;
    if (!live.ready || !live.devs.length) {
      box.innerHTML = `<section class="panel boot"><h2 class="panel-title">${live.error ? 'تعذّر تشغيل المحرك' : 'تدريب النماذج الثلاثة داخل متصفحك...'}</h2><div class="pbar"><i style="width:${Math.round(live.progress * 100)}%"></i></div><p class="muted">${live.error ? esc(live.error) : 'يحدث هذا مرة واحدة ويأخذ ثوانٍ قليلة، ثم تبدأ الأجهزة بإرسال حركتها.'}</p></section>`;
      return;
    }
    const m = live.m || {}, active = live.devs.filter((d) => d.state === 2).length, s = live.settings;
    const recall = m.tp + m.fn ? m.tp / (m.tp + m.fn) : null, fpr = m.fp + m.tn ? m.fp / (m.fp + m.tn) : null;
    const mttd = m.ttdN ? m.ttdSum / m.ttdN : null, ms = live.perf ? live.perf.us / 1000 : null;
    const cards = DEVICES.map((dev, i) => {
      const d = live.devs[i], state = d.state === 2 ? 'incident' : d.dec ? 'suspect' : 'ok';
      const spark = points(live.hist[i].slice(-30).map((h) => h.agg), 160, 28, 30);
      return `<button type="button" class="dev" data-device="${i}" data-state="${state}" aria-pressed="${i === live.sel}">
        <span class="dev-name">${esc(dev.name)}</span><span class="dev-ip data">${dev.ip}</span>
        <svg class="spark" viewBox="0 0 160 28" preserveAspectRatio="none" aria-hidden="true"><polyline points="${spark}"/></svg>
        <span class="dev-risk">الخطر <b class="data">${Math.round(d.agg)}</b>${state === 'incident' ? '<span class="chip chip-crit">حادثة</span>' : state === 'suspect' ? '<span class="chip chip-warn">مشتبه</span>' : ''}</span>
        <span class="bar"><i style="width: ${d.agg.toFixed(1)}%"></i></span>
        ${d.att ? `<span class="sim-tag">هجوم محاكى: ${ATTACK_AR[CLASSES[d.att.kind]]}${d.att.stealth ? ' (خفي)' : ''}</span>` : ''}</button>`;
    }).join('');
    const fd = DEVICES[live.sel], f = live.devs[live.sel], hist = live.hist[live.sel], W = 640, H = 200;
    const spans = [];
    let run = null;
    hist.concat([{ truth: 0 }]).forEach((h, i) => {
      if (h.truth && run === null) run = i;
      if (!h.truth && run !== null) { spans.push(`<rect class="att" x="${((90 - hist.length + run) * W / 89).toFixed(1)}" y="0" width="${((i - run) * W / 89).toFixed(1)}" height="${H}"/>`); run = null; }
    });
    const lines = MODEL_KEYS.map((k, j) => `<polyline class="ln ln-${k}" points="${points(hist.map((h) => h.r[j]), W, H, 90)}"/>`).join('');
    const reasons = [];
    for (let q = 0; q < f.top.length; q += 2) {
      const fm = live.featMeta[f.top[q]], share = f.top[q + 1];
      if (fm.num >= 0) reasons.push({ name: FEATURE_AR[NUM_COLS[fm.num]], share, value: f.raw[fm.num], normal: live.baseline[TYPES.indexOf(fd.type)][fm.num] });
      else reasons.push({ name: `${fm.col} = ${fm.cat}`, share, value: null, normal: null });
    }
    const incs = Array.from(live.incidents.values()).sort((a, b) => b.id - a.id).slice(0, 10).map((inc) => {
      const activeNow = inc.status === 'active', truth = inc.truth ? CLASSES[inc.truthKind] : null;
      return `<li class="inc" data-active="${activeNow ? 1 : 0}"><div class="inc-top"><b>${attackName(topVote(inc.votes))}</b><span class="chip ${activeNow ? 'chip-crit' : ''}">${activeNow ? 'نشطة' : 'مغلقة'}</span></div>
        <div class="muted">#${inc.id} · ${esc(DEVICES[inc.dev].name)} · بدأت عند الثانية ${inc.start} · المدة ${(inc.end || live.tick) - inc.start + 1} ث</div>
        <div class="inc-foot">${MODEL_KEYS.map((k, j) => `<span class="mod ${inc.hits[j] ? 'on' : ''}">${k.toUpperCase()}</span>`).join('')}<span class="truth ${truth ? 'ok' : 'bad'}">${truth ? 'هجوم حقيقي: ' + ATTACK_AR[truth] : 'إنذار كاذب'}</span></div></li>`;
    }).join('');
    box.innerHTML = `<section class="status" data-state="${active ? 'alert' : 'ok'}"><div><h2>${active ? `حادثة أمنية نشطة على ${active} من الأجهزة` : 'الشبكة آمنة'}</h2><p>${active ? 'راجع قائمة الحوادث، واضغط على الجهاز المصاب لترى سبب الإنذار.' : 'كل الأجهزة تعمل ضمن سلوكها الطبيعي.'}</p></div>
        <div class="clock"><span>زمن المحاكاة</span><b class="data">${clock(live.tick)}</b><small>${s.running ? 'تعمل' : 'متوقفة'} · ${s.speed}×</small></div></section>
      <section class="kpis">
        <div class="kpi"><span>السجلات المحلَّلة</span><b class="data">${fmt(m.records)}</b></div>
        <div class="kpi"><span>نسبة الكشف (Recall)</span><b class="data">${pct(recall)}</b></div>
        <div class="kpi"><span>الإنذارات الكاذبة (FPR)</span><b class="data">${pct(fpr, 2)}</b></div>
        <div class="kpi"><span>متوسط زمن الاكتشاف</span><b>${mttd == null ? '—' : `<span class="data">${mttd.toFixed(1)}</span> ث`}</b></div>
        <div class="kpi"><span>زمن تحليل السجل</span><b class="data">${ms == null ? '—' : ms.toFixed(3) + ' ms'}</b></div>
        <div class="kpi"><span>الحوادث: حقيقية / كاذبة</span><b class="data">${m.incTrue || 0} / ${m.incFalse || 0}</b></div></section>
      <section class="panel"><div class="panel-h"><h2 class="panel-title">الأجهزة</h2><span class="muted">اضغط على جهاز لفحصه</span></div><div class="devgrid">${cards}</div></section>
      <div class="grid2"><section class="panel">
        <div class="panel-h"><h2 class="panel-title">فاحص الجهاز: ${esc(fd.name)}</h2><span class="data muted">${fd.ip} · ${DEVICE_AR[fd.type]}</span></div>
        <svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="درجة الخطر لآخر 90 ثانية">${spans.join('')}<line class="thr" x1="0" x2="${W}" y1="${H / 2}" y2="${H / 2}"/>${lines}<polyline class="ln ln-final" points="${points(hist.map((h) => h.agg), W, H, 90)}"/></svg>
        <div class="legend">${MODEL_KEYS.map((k) => `<span class="key"><i class="sw sw-${k}"></i>${MODEL_NAMES[k]}</span>`).join('')}<span class="key"><i class="sw sw-final"></i>القرار النهائي</span><span class="key"><i class="sw sw-att"></i>هجوم حقيقي</span><span class="key"><i class="sw sw-thr"></i>العتبة 50</span></div>
        <div class="verdicts">${MODEL_KEYS.map((k, j) => `<div class="verdict"><span>${MODEL_NAMES[k]}</span><b class="data">${Math.round(f.r[j])}</b><span class="chip ${f.r[j] >= 50 ? 'chip-crit' : ''}">${f.r[j] >= 50 ? 'شاذ' : 'طبيعي'}</span></div>`).join('')}</div>
        <p class="final">القرار النهائي: <b>${f.dec ? 'إنذار' : 'طبيعي'}</b> · درجة الخطر ${Math.round(f.agg)} · النوع حسب Random Forest: ${f.pred > 0 ? ATTACK_AR[CLASSES[f.pred]] : '—'}</p>
        <h3 class="sub">لماذا؟ الخصائص الأبعد عن سلوك الجهاز الطبيعي</h3>
        <ul class="why">${reasons.map((r) => `<li><div class="why-h"><span>${esc(r.name)}</span><span class="data">${pct(r.share, 0)}</span></div>${r.value == null ? '' : `<div class="why-v">الآن <b class="data">${g3(r.value)}</b> · الطبيعي <b class="data">${g3(r.normal)}</b></div>`}<span class="bar"><i style="width: ${(r.share * 100).toFixed(1)}%"></i></span></li>`).join('')}</ul>
      </section><section class="panel"><h2 class="panel-title">الحوادث</h2>${incs ? `<ul class="incs">${incs}</ul>` : '<p class="muted empty">لا توجد حوادث بعد.</p>'}</section></div>`;
  }

  // ---------- your data (CSV) ----------
  const csv = { engine: null, stage: 'idle', progress: 0, parsed: null, fileName: '', error: null, label: null, normal: null };
  const CSV_ERRORS = {
    EMPTY_FILE: 'الملف فارغ.', TOO_FEW_ROWS: 'الملف فيه أقل من 50 سجلاً.', NO_FILE: 'اختر ملفاً أولاً.',
    NOT_ENOUGH_NORMAL: 'لا توجد سجلات كافية بقيمة الحركة الطبيعية المختارة.', NO_ANOMALIES: 'لا توجد هجمات كافية في الملف لتقييم النماذج.',
    NO_FEATURES: 'لم يبقَ أي عمود يصلح خاصية بعد استبعاد المعرّفات.',
  };
  function csvEngine() { if (!csv.engine) csv.engine = createEngine(onCsv); return csv.engine; }
  function onCsv(m) {
    if (m.type === 'csvProgress') { csv.progress = m.pct || 0; const bar = $('#csv-bar'); if (bar) bar.style.width = Math.round(csv.progress * 100) + '%'; return; }
    if (m.type === 'csvParsed') {
      csv.parsed = m; csv.stage = 'parsed';
      const c = m.candidates.find((x) => x.col === m.guess.col) || m.candidates[0];
      csv.label = c ? c.col : null; csv.normal = m.guess.normal || (c && c.values[0] ? c.values[0].v : null);
    } else if (m.type === 'csvReport') {
      const summary = summarize(m.report);
      csv.stage = 'idle'; csv.parsed = null;
      saveShared('reports', summary);
      flash('اكتمل التحليل وحُفظ التقرير.', 'ok');
      go('report-' + summary.id);
      return;
    } else if (m.type === 'error') { csv.stage = csv.parsed ? 'parsed' : 'idle'; csv.error = CSV_ERRORS[m.code] || 'تعذّر تحليل الملف: ' + m.code; }
    if (base === 'data') renderView();
  }
  function dataView() {
    const p = csv.parsed, busy = csv.stage === 'parsing' || csv.stage === 'analyzing';
    let config = '';
    if (p && csv.stage !== 'analyzing') {
      const cand = p.candidates.find((c) => c.col === csv.label) || p.candidates[0];
      config = `<form class="csv-config" data-form="analyze">
        <p class="note" style="grid-column:1/-1">الملف <span class="data">${esc(p.name)}</span>: ${fmt(p.rowsKept)} سجل و${p.columns.length} عموداً. اختر عمود التصنيف وقيمة الحركة الطبيعية ثم حلّل.</p>
        <label class="field">عمود التصنيف <select name="label">${p.candidates.map((c) => `<option value="${c.col}"${c.col === csv.label ? ' selected' : ''}>${esc(c.name)}</option>`).join('')}</select></label>
        <label class="field">قيمة الحركة الطبيعية <select name="normal">${cand ? cand.values.map((v) => `<option value="${esc(v.v)}"${v.v === csv.normal ? ' selected' : ''}>${esc(v.v)} (${fmt(v.n)})</option>`).join('') : ''}</select></label>
        <div class="control-row"><button class="btn btn-primary" type="submit">حلّل الملف</button></div></form>`;
    }
    return `<section class="view-head"><h1>بياناتك</h1><p>اختر ملف CSV من مجموعة بيانات حقيقية مثل CICIoT2023 أو TON_IoT أو UNSW-NB15، فيدرّب رقيب النماذج الثلاثة عليه داخل متصفحك ويقيّمها، ويحفظ التقرير. الملف لا يغادر جهازك.</p></section>
      <section class="panel">
        <div class="upload">
          <label class="field">ملف CSV <input type="file" id="csv-file" accept=".csv,text/csv"${busy ? ' disabled' : ''}></label>
          <div class="control-row"><button class="btn" type="button" data-action="sample"${busy ? ' disabled' : ''}>جرّب بملف تجربة جاهز</button></div>
        </div>
        ${busy ? `<div class="boot" style="margin-top:14px"><p class="note">${csv.stage === 'parsing' ? 'جارٍ قراءة الملف...' : 'جارٍ التدريب والتقييم...'}</p><div class="pbar"><i id="csv-bar" style="width:${Math.round(csv.progress * 100)}%"></i></div></div>` : ''}
        ${csv.error ? `<p class="errbox">${esc(csv.error)}</p>` : ''}
        ${config}
      </section>`;
  }
  function percentile(sorted, p) {
    if (!sorted.length) return NaN;
    const idx = (sorted.length - 1) * p / 100, lo = Math.floor(idx), hi = Math.ceil(idx);
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
  }
  function calibrator(train) {
    const sorted = Float64Array.from(train).sort(), thr = percentile(sorted, 99), med = percentile(sorted, 50);
    const ratio = Math.log(Math.max(med, 1e-12) / thr), k = ratio < -1e-9 ? -Math.log(9) / ratio : 8;
    return { thr, risk: (s) => 100 / (1 + (Math.max(s, 1e-12) / thr) ** (-k)) };
  }
  function aucOf(score, y) {
    const idx = Array.from(score.keys()).sort((a, b) => score[a] - score[b]);
    let rank = 0, pos = 0, sumPos = 0;
    for (let i = 0; i < idx.length;) {
      let j = i; while (j + 1 < idx.length && score[idx[j + 1]] === score[idx[i]]) j++;
      const avg = (i + j) / 2 + 1;
      for (let k = i; k <= j; k++) if (y[idx[k]]) { sumPos += avg; pos++; }
      rank = j + 1; i = j + 1;
    }
    const neg = rank - pos;
    return pos && neg ? (sumPos - (pos * (pos + 1)) / 2) / (pos * neg) : NaN;
  }
  function summarize(rep) {
    const n = rep.yTest.length, y = rep.yTest, type = rep.typeTest, K = rep.classes.length;
    const cal = { if: calibrator(rep.trainNorm.if), ae: calibrator(rep.trainNorm.ae) };
    const alarm = { if: new Uint8Array(n), ae: new Uint8Array(n), rf: new Uint8Array(n), vote: new Uint8Array(n) };
    const voteScore = new Float64Array(n);
    for (let i = 0; i < n; i++) {
      const r = [cal.if.risk(rep.scores.if[i]), cal.ae.risk(rep.scores.ae[i]), 100 * rep.scores.rf[i]];
      alarm.if[i] = r[0] >= 50; alarm.ae[i] = r[1] >= 50; alarm.rf[i] = r[2] >= 50;
      alarm.vote[i] = alarm.if[i] + alarm.ae[i] + alarm.rf[i] >= 2;
      voteScore[i] = r.slice().sort((a, b) => a - b)[1];
    }
    const cnt = new Array(K).fill(0);
    for (let i = 0; i < n; i++) cnt[type[i]]++;
    const hits = {};
    const table = MODEL_KEYS.concat('vote').map((key) => {
      let tp = 0, fp = 0, fn = 0, tn = 0; const hit = new Array(K).fill(0);
      for (let i = 0; i < n; i++) { const a = alarm[key][i]; if (a) hit[type[i]]++; if (a && y[i]) tp++; else if (a) fp++; else if (y[i]) fn++; else tn++; }
      hits[key] = hit;
      return {
        key, name: MODEL_NAMES[key], accuracy: (tp + tn) / n, precision: tp + fp ? tp / (tp + fp) : 0, recall: tp + fn ? tp / (tp + fn) : 0,
        f1: tp ? (2 * tp) / (2 * tp + fp + fn) : 0, auc: key === 'vote' ? aucOf(voteScore, y) : rep.auc[key], fpr: fp + tn ? fp / (fp + tn) : 0,
        train_s: key === 'vote' ? null : rep.timing[key] / 1000, micros: key === 'vote' ? null : rep.us[key],
      };
    });
    const attacks = rep.classes.map((c, i) => i).filter((i) => i !== rep.normalClass && cnt[i] > 0).sort((a, b) => cnt[b] - cnt[a]);
    const per = attacks.map((c) => Object.assign({ type: rep.classes[c], count: cnt[c] }, ...MODEL_KEYS.concat('vote').map((k) => ({ [k]: hits[k][c] / cnt[c] }))));
    const zero = (rep.zeroDay || []).filter((z) => Number.isFinite(z.rf) && cnt[z.cls] > 0)
      .map((z) => ({ type: rep.classes[z.cls], rf: z.rf, if: hits.if[z.cls] / cnt[z.cls], ae: hits.ae[z.cls] / cnt[z.cls] }));
    const vote = table[3];
    return {
      id: uid(), filename: csv.parsed ? csv.parsed.name : csv.fileName, label_col: csv.labelName, normal_value: csv.normal,
      owner: auth.current ? auth.current.name : '', created: stamp(), rows: csv.parsed ? csv.parsed.rowsKept : n,
      features: rep.featNames.length, train_rows: rep.rfInfo ? rep.rfInfo.nTrain : 0, test_rows: n,
      attack_share: y.reduce((a, b) => a + b, 0) / n, ae_epochs: rep.ae.epochs, ae_best_epoch: rep.ae.bestEpoch,
      dropped: rep.excludedNames || [], f1: vote.f1, table, per_attack: per, zero_day: zero,
    };
  }

  // ---------- incidents, reports, admin ----------
  function incidentsView() {
    const all = shared.incidents.slice().sort(byNewest);
    const real = all.filter((i) => i.truth), falseOnes = all.filter((i) => !i.truth);
    const rows = { all, real, false: falseOnes }[incidentFilter];
    const avg = all.length ? all.reduce((a, i) => a + (Number(i.duration) || 0), 0) / all.length : null;
    const byType = {};
    real.forEach((i) => { byType[i.truth] = (byType[i.truth] || 0) + 1; });
    const types = Object.entries(byType).sort((a, b) => b[1] - a[1]);
    const admin = auth.current.role === 'admin';
    return `<section class="view-head"><h1>سجل الحوادث</h1><p>كل حادثة تُغلق في المراقبة الحية تُحفظ هنا، مع حقيقتها: هجوم حقيقي من المحاكي أم إنذار كاذب.</p></section>
      <section class="kpis"><div class="kpi"><span>كل الحوادث المحفوظة</span><b class="data">${all.length}</b></div><div class="kpi"><span>هجمات حقيقية</span><b class="data">${real.length}</b></div>
        <div class="kpi"><span>إنذارات كاذبة</span><b class="data">${falseOnes.length}</b></div><div class="kpi"><span>متوسط مدة الحادثة</span><b>${avg == null ? '—' : `<span class="data">${avg.toFixed(1)}</span> ث`}</b></div></section>
      <section class="panel"><div class="panel-h"><div class="seg" role="group" aria-label="تصفية">${[['all', 'الكل'], ['real', 'هجمات حقيقية'], ['false', 'إنذارات كاذبة']].map(([k, l]) => `<a href="#incidents" data-action="filter" data-v="${k}"${incidentFilter === k ? ' aria-current="true"' : ''}>${l}</a>`).join('')}</div>
        ${admin && all.length ? `<button class="btn btn-small${armed === 'clear' ? ' btn-confirm' : ''}" type="button" data-action="clear">${armed === 'clear' ? 'اضغط مرة أخرى لمسح السجل' : 'مسح السجل'}</button>` : ''}</div>
        ${rows.length ? `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>الجهاز</th><th>النوع المتوقع</th><th>الحقيقة</th><th>المدة</th><th>أعلى خطر</th><th>النماذج</th><th>أطلقه</th><th>الوقت</th></tr></thead><tbody>
        ${rows.map((i) => `<tr><td>${esc(i.device)}<br><span class="muted data">${esc(i.ip)}</span></td><td>${esc(attackName(i.guess))}</td>
          <td class="truth ${i.truth ? 'ok' : 'bad'}">${i.truth ? esc(attackName(i.truth)) : 'إنذار كاذب'}</td><td><span class="data">${Number(i.duration) || 0}</span> ث</td>
          <td class="data">${Math.round(Number(i.peak) || 0)}</td><td>${MODEL_KEYS.map((k) => `<span class="mod ${Number(i['hits_' + k]) ? 'on' : ''}">${k.toUpperCase()}</span>`).join(' ')}</td>
          <td>${esc(i.launched_by || (i.truth ? 'تلقائي' : '—'))}</td><td class="data">${esc(i.created)}</td></tr>`).join('')}</tbody></table></div>`
          : `<p class="muted empty">لا توجد حوادث محفوظة بعد. افتح <a href="#live">المراقبة الحية</a> وانتظر حتى تُغلق أول حادثة.</p>`}</section>
      ${types.length ? `<section class="panel"><h2 class="panel-title">الهجمات الحقيقية حسب النوع</h2><ul class="bars">${types.map(([t, c]) => `<li><span>${esc(attackName(t))}</span><span class="bar"><i style="width: ${(c / real.length * 100).toFixed(1)}%"></i></span><b class="data">${c}</b></li>`).join('')}</ul></section>` : ''}`;
  }
  function reportsView() {
    const rows = shared.reports.slice().sort(byNewest);
    return `<section class="view-head"><h1>التقارير المحفوظة</h1><p>تقارير الملفات التي حُلّلت في صفحة «بياناتك». في نسخة بايثون يرى كل محلل تقاريره، ويرى المدير الجميع.</p></section>
      <section class="panel">${rows.length ? `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>الملف</th><th>السجلات</th><th>F1 (الأغلبية)</th><th>صاحبه</th><th>التاريخ</th></tr></thead><tbody>
      ${rows.map((r) => `<tr><td><a href="#report-${esc(r.id)}">${esc(r.filename)}</a></td><td class="data">${fmt(r.rows)}</td><td class="data">${fix(Number(r.f1))}</td><td>${esc(r.owner || '—')}</td><td class="data">${esc(r.created)}</td></tr>`).join('')}
      </tbody></table></div>` : '<p class="muted empty">لا توجد تقارير بعد. <a href="#data">حلّل ملفاً من صفحة «بياناتك»</a>.</p>'}</section>`;
  }
  function reportView() {
    const id = route.slice('report-'.length), r = shared.reports.find((x) => x.id === id);
    if (!r) return '<section class="auth panel"><h1>التقرير غير موجود</h1><p>ربما حُذف، أو ما زال يُحمَّل من قاعدة البيانات.</p><a class="btn" href="#reports">كل التقارير</a></section>';
    let body;   // records from the shared database are untrusted: a damaged one must not break the page
    try { body = reportHtml(r, null); } catch (e) { body = '<p class="note">بيانات هذا التقرير ناقصة أو بصيغة قديمة، فلا يمكن عرض تفاصيلها.</p>'; }
    return `<section class="view-head"><h1>تقرير الملف <span class="data">${esc(r.filename)}</span></h1>
      <p>حلّله ${esc(r.owner || 'مستخدم')} في <span class="data">${esc(r.created)}</span>. عمود التصنيف <span class="data">${esc(r.label_col)}</span>، وقيمة الحركة الطبيعية <span class="data">${esc(r.normal_value)}</span>.</p></section>
      ${r.dropped && r.dropped.length ? `<p class="note">أعمدة استُبعدت لأنها معرّفات أو تصنيفات إضافية قد تكشف الإجابة للنموذج: <span class="data">${esc(r.dropped.join(', '))}</span></p>` : ''}
      ${body}
      <p class="note">في نسخة بايثون يحفظ التقرير معه سبعة أشكال (ROC ومصفوفات الالتباس وغيرها) كما في صفحة المختبر.</p>
      <div class="danger-zone"><button class="btn${armed === 'report' ? ' btn-confirm' : ''}" type="button" data-action="delete-report">${armed === 'report' ? 'اضغط مرة أخرى للحذف' : 'حذف التقرير'}</button></div>`;
  }
  function adminView() {
    const me = auth.current;
    return `<section class="view-head"><h1>الإدارة</h1><p>المستخدمون وصلاحياتهم، ومعلومات المشروع التي تظهر في صفحة «الفريق» والتذييل. في هذا النموذج الحسابات محلية في متصفحك.</p></section>
      <section class="panel"><h2 class="panel-title">المستخدمون</h2><div class="tbl-wrap"><table class="tbl"><thead><tr><th>الاسم</th><th>اسم المستخدم</th><th>الصلاحية</th><th>تاريخ التسجيل</th><th></th></tr></thead><tbody>
      ${auth.users.map((u) => `<tr><td>${esc(u.name)}</td><td class="data">${esc(u.username)}</td><td>${u.role === 'admin' ? 'مدير' : 'محلل'}</td><td class="data">${esc(u.created)}</td>
        <td class="row-actions">${u.id === me.id ? '<span class="muted">أنت</span>' : `<button class="btn btn-small" type="button" data-action="role" data-id="${u.id}">${u.role === 'admin' ? 'اجعله محللاً' : 'اجعله مديراً'}</button><button class="btn btn-small" type="button" data-action="delete-user" data-id="${u.id}">حذف</button>`}</td></tr>`).join('')}
      </tbody></table></div></section>
      <section class="panel"><h2 class="panel-title">معلومات المشروع</h2><form class="settings" data-form="settings">
      ${Object.entries(SITE_LABELS).map(([k, l]) => `<label class="field">${l}${k === 'researchers' ? `<textarea name="${k}" rows="3">${esc(shared.site[k])}</textarea>` : `<input type="text" name="${k}" value="${esc(shared.site[k])}"${k === 'title_en' || k === 'email' ? ' dir="ltr"' : ''}>`}</label>`).join('')}
      <div class="control-row"><button class="btn btn-primary" type="submit">حفظ</button></div></form></section>`;
  }

  // ---------- events ----------
  document.addEventListener('click', async (event) => {
    const el = event.target.closest('[data-action], [data-device]');
    if (!el) return;
    if (el.dataset.device !== undefined && el.matches('.dev')) { live.sel = Number(el.dataset.device); drawPanel(); return; }
    const action = el.dataset.action;
    const send = (m) => live.engine && live.engine.send(m);
    if (action === 'logout') { auth.current = null; local.set('session', ''); go('home'); }
    else if (action === 'quick') {
      let user = auth.users.find((u) => u.username === 'demo');
      if (!user) user = await createUser('زائر تجريبي', 'demo', uid());
      signIn(user); flash(`دخلت بالحساب التجريبي (${user.role === 'admin' ? 'مدير' : 'محلل'}).`, 'ok'); go(afterLogin);
    } else if (action === 'run') {
      live.settings.running = !live.settings.running; send({ type: 'run', on: live.settings.running });
      el.textContent = live.settings.running ? 'إيقاف مؤقت' : 'تشغيل'; drawPanel();
    } else if (action === 'reset') { send({ type: 'resetStats' }); live.incidents.clear(); drawPanel(); }
    else if (action === 'stop') send({ type: 'stopAttacks' });
    else if (action === 'sample') { csv.stage = 'parsing'; csv.error = null; csv.progress = 0; csv.fileName = 'raqib_sample.csv'; csvEngine().send({ type: 'csvSample', maxRows: 50000 }); renderView(); }
    else if (action === 'filter') { event.preventDefault(); incidentFilter = el.dataset.v; renderView(); }
    else if (action === 'clear') {
      if (armed !== 'clear') { armed = 'clear'; renderView(); return; }
      armed = null;
      let kept = 0;
      for (const i of shared.incidents.slice()) if (!(await removeShared('incidents', i.id))) kept++;
      flash(kept ? `مُسحت سجلاتك. عدد الحوادث المشتركة الباقية: ${kept}، ولا يحذفها إلا صاحب الرابط.` : 'مُسح سجل الحوادث.', kept ? 'error' : 'ok');
      renderView();
    } else if (action === 'delete-report') {
      if (armed !== 'report') { armed = 'report'; renderView(); return; }
      armed = null;
      const ok = await removeShared('reports', route.slice('report-'.length));
      if (ok) { flash('حُذف التقرير.', 'ok'); go('reports'); }
      else { flash('هذا التقرير محفوظ في قاعدة البيانات المشتركة، ولا يحذفه إلا صاحب الرابط.', 'error'); renderView(); }
    } else if (action === 'role') {
      const u = auth.users.find((x) => x.id === el.dataset.id); if (u) u.role = u.role === 'admin' ? 'analyst' : 'admin';
      local.set('users', auth.users); flash('تغيّرت صلاحية المستخدم.', 'ok'); renderView();
    } else if (action === 'delete-user') {
      auth.users = auth.users.filter((x) => x.id !== el.dataset.id); local.set('users', auth.users); flash('حُذف المستخدم.', 'ok'); renderView();
    }
  });

  document.addEventListener('change', (event) => {
    const t = event.target, send = (m) => live.engine && live.engine.send(m);
    if (t.id === 'speed') { live.settings.speed = Number(t.value); send({ type: 'speed', value: live.settings.speed }); }
    else if (t.id === 'policy') { live.settings.policy = t.value; send({ type: 'policy', value: t.value }); }
    else if (t.id === 'sensitivity') { live.settings.pct = Number(t.value); send({ type: 'pct', value: live.settings.pct }); }
    else if (t.id === 'auto') { live.settings.auto = t.checked; send({ type: 'auto', on: t.checked }); }
    else if (t.id === 'csv-file' && t.files && t.files[0]) {
      csv.stage = 'parsing'; csv.error = null; csv.progress = 0; csv.fileName = t.files[0].name;
      csvEngine().send({ type: 'csvFile', file: t.files[0], name: t.files[0].name, maxRows: 50000 }); renderView();
    } else if (t.name === 'label' && csv.parsed) {
      csv.label = Number(t.value); const c = csv.parsed.candidates.find((x) => x.col === csv.label);
      csv.normal = c && c.values[0] ? c.values[0].v : null; renderView();
    } else if (t.name === 'normal') csv.normal = t.value;
  });

  document.addEventListener('submit', async (event) => {
    const form = event.target.closest('[data-form]');
    if (!form) return;
    event.preventDefault();
    const data = Object.fromEntries(new FormData(form).entries());
    const kind = form.dataset.form;
    if (kind === 'login') {
      const user = auth.users.find((u) => u.username === String(data.username).trim().toLowerCase());
      if (user && user.hash === await digest(user.salt + data.password)) { signIn(user); go(afterLogin); }
      else { flash('اسم المستخدم أو كلمة المرور غير صحيحة.', 'error'); renderView(); }
    } else if (kind === 'register') {
      const name = String(data.name).trim(), username = String(data.username).trim().toLowerCase();
      let error = null;
      if (!name || !/^[a-z0-9_.]+$/.test(username)) error = 'اكتب اسمك واسم مستخدم من حروف إنجليزية وأرقام فقط.';
      else if (String(data.password).length < 8) error = 'كلمة المرور يجب أن تكون 8 أحرف على الأقل.';
      else if (data.password !== data.confirm) error = 'كلمتا المرور غير متطابقتين.';
      else if (auth.users.some((u) => u.username === username)) error = 'اسم المستخدم مستعمل، اختر اسماً آخر.';
      if (error) { flash(error, 'error'); renderView(); return; }
      const first = !auth.users.length, user = await createUser(name, username, String(data.password));
      signIn(user); flash('أُنشئ حسابك. ' + (first ? 'أنت مدير الموقع لأنك أول من سجّل في هذا المتصفح.' : 'مرحباً بك في رقيب.'), 'ok'); go(afterLogin);
    } else if (kind === 'attack') {
      const dev = Number(data.device), duration = Number(data.duration);
      live.sel = dev;
      live.launches[dev] = { name: auth.current.name, from: live.tick + 1, until: live.tick + duration + 4 };
      live.engine.send({ type: 'attack', dev, kind: Number(data.kind), stealth: data.stealthy === '1', duration });
      drawPanel();
    } else if (kind === 'analyze') {
      csv.label = Number(data.label); csv.normal = data.normal; csv.stage = 'analyzing'; csv.progress = 0; csv.error = null;
      const cand = csv.parsed.candidates.find((c) => c.col === csv.label); csv.labelName = cand ? cand.name : '';
      csvEngine().send({ type: 'csvAnalyze', labelCol: csv.label, normalValue: csv.normal }); renderView();
    } else if (kind === 'settings') {
      const values = {};
      Object.keys(SITE_LABELS).forEach((k) => { values[k] = String(data[k] || '').trim().slice(0, 300); });
      const sharedOk = await saveSite(values);
      flash(sharedOk ? 'حُفظت معلومات المشروع في قاعدة بيانات الرابط.' : 'حُفظت معلومات المشروع في هذا المتصفح (الحفظ المشترك متاح لصاحب الرابط).', 'ok');
      renderFrame(); renderView();
    }
  });

  // On GitHub Pages (USER.github.io/REPO/) the note points at the repository instead of the zip file.
  function linkRepository() {
    const host = location.hostname.toLowerCase();
    const note = $('#code-note');
    if (!note || !host.endsWith('.github.io')) return;
    const user = host.slice(0, -'.github.io'.length);
    const first = location.pathname.split('/').filter(Boolean)[0];
    const repo = first && !/\.html?$/i.test(first) ? first : host;
    if (!/^[a-z0-9-]+$/.test(user) || !/^[\w.-]+$/.test(repo)) return;
    const a = document.createElement('a');
    a.href = `https://github.com/${user}/${repo}`;
    a.textContent = 'مستودع GitHub';
    a.target = '_blank'; a.rel = 'noopener';
    note.textContent = 'الكود الكامل بلغة بايثون في ';
    note.append(a, '.');
  }

  window.addEventListener('hashchange', show);
  linkRepository();
  renderStorageNote();
  show();
  connectDb();
}
