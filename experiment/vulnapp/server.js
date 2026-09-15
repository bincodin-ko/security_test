// Deliberately vulnerable test app. LOCAL ONLY - never deploy.
// Each vuln is tagged with the checklist ID it is meant to represent.
const express = require('express');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const app = express();
app.use(express.json());

// [H5] CORS wildcard + credentials
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  // [G6][G8][G9] no CSP / X-Frame-Options / nosniff
  // [M6] version disclosure
  res.setHeader('X-Powered-By', 'Express 4.18.2');
  next();
});

// [D1] hardcoded secret  [D11] weak JWT secret
const JWT_SECRET = 'secret';
const PAYMENT_API_KEY = 'FIXTURE-PAYMENT-KEY-DO-NOT-USE-0000'; // not a real provider format

const db = new Database(':memory:');
db.exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, role TEXT);
         CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT, body TEXT);
         CREATE TABLE cards (id INTEGER PRIMARY KEY, owner_id INTEGER, last4 TEXT);`);
const h = p => crypto.createHash('md5').update(p).digest('hex'); // [A11] md5, no salt
db.prepare("INSERT INTO users VALUES (1,'alice@test.com',?, 'user')").run(h('alice123'));
db.prepare("INSERT INTO users VALUES (2,'bob@test.com',?, 'user')").run(h('bob123'));
db.prepare("INSERT INTO users VALUES (3,'admin@test.com',?, 'admin')").run(h('admin123'));
db.prepare("INSERT INTO notes VALUES (1,1,'Alice private','alice secret content')").run();
db.prepare("INSERT INTO notes VALUES (2,2,'Bob private','bob secret content')").run();
db.prepare("INSERT INTO cards VALUES (1,1,'4242')").run();
db.prepare("INSERT INTO cards VALUES (2,2,'1881')").run();

const tokens = new Map();
function auth(req, res, next) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  const u = tokens.get(t);
  if (!u) return res.status(401).json({ error: 'unauthorized' });
  req.user = u;
  next();
}

// [N2] no rate limit  [A5] user enumeration via distinct messages
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!row) return res.status(404).json({ error: 'no such user' });
  if (row.password_hash !== h(password)) return res.status(401).json({ error: 'wrong password' });
  const t = crypto.randomBytes(8).toString('hex');
  tokens.set(t, { id: row.id, role: row.role });
  res.json({ token: t, user: row });   // [E2] returns password_hash
});

// [B1] IDOR read - no ownership check
app.get('/api/notes/:id', auth, (req, res) => {
  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
  if (!note) return res.status(404).json({ error: 'not found' });
  res.json(note);
});

// [B3] IDOR delete - no ownership check
app.delete('/api/notes/:id', auth, (req, res) => {
  db.prepare('DELETE FROM notes WHERE id = ?').run(req.params.id);
  res.json({ deleted: true });
});

// SAFE CONTROL - correct ownership check. Used to measure false positives.
app.get('/api/cards/:id', auth, (req, res) => {
  const card = db.prepare('SELECT * FROM cards WHERE id = ?').get(req.params.id);
  if (!card) return res.status(404).json({ error: 'not found' });
  if (card.owner_id !== req.user.id) return res.status(403).json({ error: 'forbidden' });
  res.json(card);
});

// [B10] mass assignment - role escalation
app.patch('/api/me', auth, (req, res) => {
  const fields = Object.keys(req.body);
  for (const f of fields) {
    db.prepare(`UPDATE users SET ${f} = ? WHERE id = ?`).run(req.body[f], req.user.id); // [F2] raw
  }
  res.json(db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id));
});

// [B6] BFLA - admin endpoint, authenticated but no role check
app.get('/api/admin/users', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM users').all());
});

// [E1] no auth at all on a data endpoint
app.get('/api/stats', (req, res) => {
  res.json({ users: db.prepare('SELECT COUNT(*) c FROM users').get().c,
             emails: db.prepare('SELECT email FROM users').all() });
});

// [F1] SQL injection
app.get('/api/search', auth, (req, res) => {
  const q = req.query.q || '';
  try {
    const rows = db.prepare(`SELECT * FROM notes WHERE title LIKE '%${q}%'`).all();
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message, stack: e.stack }); // [E9] stack trace
  }
});

// [E3] no pagination cap
app.get('/api/notes', auth, (req, res) => {
  const limit = req.query.limit || 10;
  res.json(db.prepare(`SELECT * FROM notes LIMIT ${limit}`).all());
});

// [E15] debug endpoint
app.get('/api/debug/config', (req, res) => {
  res.json({ jwt_secret: JWT_SECRET, payment_key: PAYMENT_API_KEY, env: 'production' });
});

module.exports = app;
if (require.main === module) app.listen(3000, '127.0.0.1', () => console.log('vulnapp on 3000'));
