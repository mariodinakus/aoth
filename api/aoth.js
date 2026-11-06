// AOTH · λογαριασμοί μαθητών, πρόοδος, βαθμοί καθηγητή (Vercel Blob, private)
const { put, get, list, del } = require('@vercel/blob');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const A = { access: 'private' };
const CFG = 'config.json';
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function readJSON(p) {
  try {
    const r = await get(p, { ...A, useCache: false });
    if (!r || r.statusCode !== 200) return null;
    return JSON.parse(await new Response(r.stream).text());
  } catch (e) {
    if (/not.?found/i.test(String(e && (e.name || e.message)))) return null;
    throw e;
  }
}
const writeJSON = (p, o) => put(p, JSON.stringify(o), { ...A, allowOverwrite: true, addRandomSuffix: false, contentType: 'application/json' });

function hashPin(pin, salt) { return crypto.scryptSync(String(pin), salt, 32).toString('hex'); }
function okPin(pin, salt, h) {
  const a = Buffer.from(hashPin(pin, salt), 'hex'), b = Buffer.from(h || '', 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const b64 = s => Buffer.from(s).toString('base64url');
function sign(cfg, payload) {
  const p = b64(JSON.stringify({ ...payload, exp: Date.now() + 1000 * 3600 * 24 * 60 }));
  return p + '.' + crypto.createHmac('sha256', cfg.secret).update(p).digest('base64url');
}
function verify(cfg, tok) {
  if (!cfg || !tok || typeof tok !== 'string') return null;
  const [p, s] = tok.split('.');
  if (!p || !s) return null;
  const e = crypto.createHmac('sha256', cfg.secret).update(p).digest('base64url');
  if (e.length !== s.length || !crypto.timingSafeEqual(Buffer.from(e), Buffer.from(s))) return null;
  const o = JSON.parse(Buffer.from(p, 'base64url').toString());
  return o.exp > Date.now() ? o : null;
}
const norm = s => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/\s+/g, ' ').trim();
const clean = (s, n = 80) => String(s || '').replace(/[<>]/g, '').trim().slice(0, n);
function pub(st) { const { pinSalt, pinHash, ...rest } = st; return rest; }

async function allStudents() {
  const out = [];
  let cursor;
  do {
    const r = await list({ prefix: 'students/', cursor, limit: 1000 });
    out.push(...r.blobs);
    cursor = r.hasMore ? r.cursor : null;
  } while (cursor);
  return (await Promise.all(out.map(b => readJSON(b.pathname)))).filter(Boolean);
}
async function newStudent(cfg, b, by) {
  const name = clean(b.name), pin = String(b.pin || '');
  if (name.length < 3 || !/\s/.test(name)) throw new Error('Γράψε ονοματεπώνυμο (όνομα και επώνυμο).');
  if (pin.length < 4 || pin.length > 12) throw new Error('Το PIN θέλει 4 έως 12 χαρακτήρες.');
  const all = await allStudents();
  if (all.some(s => norm(s.name) === norm(name))) throw new Error('Υπάρχει ήδη μαθητής με αυτό το ονοματεπώνυμο.');
  const id = crypto.randomBytes(6).toString('hex'), salt = crypto.randomBytes(12).toString('hex');
  const st = { id, name, school: clean(b.school), cls: clean(b.cls, 40), phone: clean(b.phone, 30), created: Date.now(), lastSeen: by === 's' ? Date.now() : 0,
    pinSalt: salt, pinHash: hashPin(pin, salt), progress: by === 's' && b.progress && typeof b.progress === 'object' ? b.progress : {}, grades: [], notes: [], marks: {}, addedBy: by };
  await writeJSON(`students/${id}.json`, st);
  return st;
}
let SOL = null;
function sol() {
  if (!SOL) { try { SOL = JSON.parse(fs.readFileSync(path.join(__dirname, '_sol.json'), 'utf8')); } catch (e) { SOL = {}; } }
  return SOL;
}


// όριο προσπαθειών: 6 λάθη σε 15' ⇒ κλείδωμα 15'
const LOCK_N = 6, LOCK_MS = 15 * 60 * 1000;
const lkey = k => 'lock/' + crypto.createHash('sha256').update(k).digest('hex').slice(0, 24) + '.json';
async function lockedFor(keys) {
  let w = 0;
  for (const k of keys) { const o = await readJSON(lkey(k)); if (o && o.until > Date.now()) w = Math.max(w, o.until - Date.now()); }
  return w;
}
async function fail(keys) {
  for (const k of keys) {
    const o = (await readJSON(lkey(k))) || { n: 0, first: Date.now() };
    if (Date.now() - o.first > LOCK_MS) { o.n = 0; o.first = Date.now(); delete o.until; }
    o.n++; if (o.n >= LOCK_N) o.until = Date.now() + LOCK_MS;
    await writeJSON(lkey(k), o);
  }
}
async function clearFails(keys) { for (const k of keys) { const o = await readJSON(lkey(k)); if (o && o.n) await writeJSON(lkey(k), { n: 0, first: Date.now() }); } }

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const send = (code, o) => res.status(code).json(o);
  try {
    if (req.method !== 'POST') return send(405, { error: 'POST only' });
    const b = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const act = b.action;
    let cfg = await readJSON(CFG);
    const ip = String((req.headers['x-forwarded-for'] || '').split(',')[0] || 'ip').trim();
    const tooMany = async keys => { const w = await lockedFor(keys); if (w) { send(429, { error: 'Πολλές λάθος προσπάθειες. Δοκίμασε ξανά σε ' + Math.ceil(w / 60000) + ' λεπτά.' }); return true; } return false; };

    if (act === 'status') return send(200, { setup: !!cfg });
    if (act === 'setup') {
      if (cfg) return send(409, { error: 'Ο καθηγητής έχει ήδη οριστεί.' });
      if (String(b.pin || '').length < 6) return send(400, { error: 'Ο κωδικός καθηγητή θέλει τουλάχιστον 6 χαρακτήρες.' });
      const code = clean(b.classCode, 20);
      if (code.length < 3) return send(400, { error: 'Ο κωδικός τάξης θέλει τουλάχιστον 3 χαρακτήρες.' });
      const salt = crypto.randomBytes(12).toString('hex');
      cfg = { salt, hash: hashPin(b.pin, salt), secret: crypto.randomBytes(32).toString('hex'), classCode: code, created: Date.now() };
      await writeJSON(CFG, cfg);
      return send(200, { token: sign(cfg, { r: 't' }), classCode: code });
    }
    if (!cfg) return send(400, { error: 'Ο καθηγητής δεν έχει ορίσει ακόμα την τάξη.' });

    if (act === 'teacherLogin') {
      const K = ['T', 'I:' + ip];
      if (await tooMany(K)) return;
      if (!okPin(b.pin, cfg.salt, cfg.hash)) { await fail(K); await sleep(700); return send(401, { error: 'Λάθος κωδικός καθηγητή.' }); }
      await clearFails(K);
      return send(200, { token: sign(cfg, { r: 't' }), classCode: cfg.classCode });
    }
    if (act === 'register') {
      const K = ['R', 'I:' + ip];
      if (await tooMany(K)) return;
      if (norm(b.classCode) !== norm(cfg.classCode)) { await fail(K); await sleep(700); return send(401, { error: 'Λάθος κωδικός τάξης. Ζήτα τον από τον καθηγητή σου.' }); }
      const st = await newStudent(cfg, b, 's');
      return send(200, { token: sign(cfg, { r: 's', id: st.id }), student: pub(st) });
    }
    if (act === 'studentLogin') {
      const K = ['S:' + norm(b.name), 'I:' + ip];
      if (await tooMany(K)) return;
      const all = await allStudents(), st = all.find(s => norm(s.name) === norm(b.name));
      if (!st || !okPin(b.pin, st.pinSalt, st.pinHash)) { await fail(K); await sleep(700); return send(401, { error: 'Λάθος ονοματεπώνυμο ή PIN.' }); }
      await clearFails(K);
      st.lastSeen = Date.now(); await writeJSON(`students/${st.id}.json`, st);
      return send(200, { token: sign(cfg, { r: 's', id: st.id }), student: pub(st) });
    }

    const t = verify(cfg, b.token);
    if (!t) return send(401, { error: 'Η σύνδεση έληξε. Συνδέσου ξανά.' });

    if (t.r === 's') {
      const p = `students/${t.id}.json`, st = await readJSON(p);
      if (!st) return send(404, { error: 'Ο λογαριασμός δεν βρέθηκε.' });
      if (act === 'me') return send(200, { student: pub(st) });
      if (act === 'sync') {
        if (b.progress && typeof b.progress === 'object' && JSON.stringify(b.progress).length < 400000) st.progress = b.progress;
        st.lastSeen = Date.now(); await writeJSON(p, st);
        return send(200, { ok: true, grades: st.grades, notes: st.notes, marks: st.marks });
      }
      if (act === 'profile') {
        st.school = clean(b.school); st.cls = clean(b.cls, 40); st.phone = clean(b.phone, 30);
        await writeJSON(p, st); return send(200, { student: pub(st) });
      }
      return send(400, { error: 'unknown action' });
    }

    if (t.r !== 't') return send(403, { error: 'forbidden' });
    if (act === 'sol') return send(200, { sol: sol() });
    if (act === 'list') return send(200, { students: (await allStudents()).map(pub), classCode: cfg.classCode });
    if (act === 'classCode') {
      const code = clean(b.classCode, 20);
      if (code.length < 3) return send(400, { error: 'Τουλάχιστον 3 χαρακτήρες.' });
      cfg.classCode = code; await writeJSON(CFG, cfg); return send(200, { classCode: code });
    }
    if (act === 'teacherPin') {
      if (!okPin(b.old, cfg.salt, cfg.hash)) return send(401, { error: 'Λάθος τρέχων κωδικός.' });
      if (String(b.pin || '').length < 6) return send(400, { error: 'Τουλάχιστον 6 χαρακτήρες.' });
      cfg.salt = crypto.randomBytes(12).toString('hex'); cfg.hash = hashPin(b.pin, cfg.salt); await writeJSON(CFG, cfg);
      return send(200, { ok: true });
    }
    if (act === 'addStudent') { const st = await newStudent(cfg, b, 't'); return send(200, { student: pub(st) }); }
    const p = `students/${String(b.id || '').replace(/[^a-f0-9]/g, '')}.json`, st = await readJSON(p);
    if (!st) return send(404, { error: 'Ο μαθητής δεν βρέθηκε.' });
    if (act === 'update') {
      if (Array.isArray(b.grades)) st.grades = b.grades.slice(0, 200).map(g => ({ id: clean(g.id, 20), title: clean(g.title, 120), score: Number(g.score) || 0, max: Number(g.max) || 100, date: clean(g.date, 20), note: clean(g.note, 500) }));
      if (Array.isArray(b.notes)) st.notes = b.notes.slice(0, 200).map(n => ({ date: clean(n.date, 20), text: clean(n.text, 2000) }));
      if (b.marks && typeof b.marks === 'object') st.marks = b.marks;
      if (b.name) st.name = clean(b.name); if (b.school !== undefined) st.school = clean(b.school); if (b.cls !== undefined) st.cls = clean(b.cls, 40);
      await writeJSON(p, st); return send(200, { student: pub(st) });
    }
    if (act === 'resetPin') {
      if (String(b.pin || '').length < 4) return send(400, { error: 'Τουλάχιστον 4 χαρακτήρες.' });
      st.pinSalt = crypto.randomBytes(12).toString('hex'); st.pinHash = hashPin(b.pin, st.pinSalt); await writeJSON(p, st);
      return send(200, { ok: true });
    }
    if (act === 'delete') { await del(p); return send(200, { ok: true }); }
    return send(400, { error: 'unknown action' });
  } catch (e) {
    return send(400, { error: String(e && e.message || e) });
  }
};
