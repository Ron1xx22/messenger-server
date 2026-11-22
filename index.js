const http = require('http');
const express = require('express');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// ---------- База данных ----------
const db = new Database(process.env.DB_PATH || 'messenger.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER NOT NULL,
    to_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_msg_from_to ON messages(from_id, to_id, id);
  CREATE INDEX IF NOT EXISTS idx_msg_to_from ON messages(to_id, from_id, id);
`);

const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  userById: db.prepare('SELECT id, username FROM users WHERE id = ?'),
  insertUser: db.prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)'),
  searchUsers: db.prepare(
    "SELECT id, username FROM users WHERE username LIKE ? AND id != ? ORDER BY username LIMIT 20"
  ),
  insertMsg: db.prepare('INSERT INTO messages (from_id, to_id, text, created_at) VALUES (?, ?, ?, ?)'),
  msgById: db.prepare('SELECT * FROM messages WHERE id = ?'),
  history: db.prepare(`
    SELECT * FROM messages
    WHERE ((from_id = @me AND to_id = @other) OR (from_id = @other AND to_id = @me)) AND id > @after
    ORDER BY id ASC LIMIT 200
  `),
  chats: db.prepare(`
    SELECT u.id, u.username, m.text AS last_text, m.created_at AS last_at, m.from_id AS last_from
    FROM users u
    JOIN messages m ON m.id = (
      SELECT MAX(id) FROM messages
      WHERE (from_id = @me AND to_id = u.id) OR (from_id = u.id AND to_id = @me)
    )
    WHERE u.id != @me
    ORDER BY m.id DESC
  `),
};

// ---------- Вспомогательное ----------
const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;

function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Требуется вход' });
  }
}

function toMessage(row) {
  return { id: row.id, from: row.from_id, to: row.to_id, text: row.text, createdAt: row.created_at };
}

// ---------- HTTP API ----------
const app = express();
app.use(express.json({ limit: '10kb' }));

app.post('/register', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    return res.status(400).json({ error: 'Имя: 3–20 символов, латиница, цифры и _' });
  }
  if (typeof password !== 'string' || password.length < 6 || password.length > 72) {
    return res.status(400).json({ error: 'Пароль: от 6 до 72 символов' });
  }
  if (q.userByName.get(username)) {
    return res.status(409).json({ error: 'Это имя уже занято' });
  }
  const hash = bcrypt.hashSync(password, 10);
  const info = q.insertUser.run(username, hash, Date.now());
  const user = { id: Number(info.lastInsertRowid), username };
  res.json({ token: signToken(user), user });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const row = typeof username === 'string' ? q.userByName.get(username) : null;
  if (!row || typeof password !== 'string' || !bcrypt.compareSync(password, row.password_hash)) {
    return res.status(401).json({ error: 'Неверное имя или пароль' });
  }
  const user = { id: row.id, username: row.username };
  res.json({ token: signToken(user), user });
});

app.get('/users', auth, (req, res) => {
  const term = String(req.query.q || '').trim().replace(/[%_]/g, '');
  if (!term) return res.json([]);
  res.json(q.searchUsers.all(`${term}%`, req.user.id));
});

app.get('/chats', auth, (req, res) => {
  const rows = q.chats.all({ me: req.user.id });
  res.json(
    rows.map((r) => ({
      id: r.id,
      username: r.username,
      lastText: r.last_text,
      lastAt: r.last_at,
      lastFromMe: r.last_from === req.user.id,
    }))
  );
});

app.get('/messages/:userId', auth, (req, res) => {
  const other = Number(req.params.userId);
  const after = Number(req.query.after || 0);
  if (!Number.isInteger(other) || !q.userById.get(other)) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }
  res.json(q.history.all({ me: req.user.id, other, after }).map(toMessage));
});

// ---------- WebSocket ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });
const online = new Map(); // userId -> Set<WebSocket>

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname !== '/ws') return socket.destroy();
  try {
    const user = jwt.verify(url.searchParams.get('token'), JWT_SECRET);
    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.user = user;
      wss.emit('connection', ws);
    });
  } catch {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
  }
});

function sendTo(userId, payload) {
  const set = online.get(userId);
  if (!set) return;
  const data = JSON.stringify(payload);
  for (const ws of set) if (ws.readyState === ws.OPEN) ws.send(data);
}

wss.on('connection', (ws) => {
  const me = ws.user.id;
  if (!online.has(me)) online.set(me, new Set());
  online.get(me).add(ws);

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    if (msg.type !== 'send') return;
    const to = Number(msg.to);
    const text = typeof msg.text === 'string' ? msg.text.trim() : '';
    if (!text || text.length > 4000 || !q.userById.get(to)) {
      return ws.send(JSON.stringify({ type: 'error', error: 'Некорректное сообщение' }));
    }
    const info = q.insertMsg.run(me, to, text, Date.now());
    const message = toMessage(q.msgById.get(info.lastInsertRowid));
    const payload = { type: 'message', message, clientId: msg.clientId || null };
    sendTo(to, { ...payload, clientId: null });
    sendTo(me, payload); // подтверждение отправителю (на всех его устройствах)
  });

  ws.on('close', () => {
    const set = online.get(me);
    if (set) {
      set.delete(ws);
      if (!set.size) online.delete(me);
    }
  });
});

server.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
