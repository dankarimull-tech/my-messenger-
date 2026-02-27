const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const SECRET = 'замени_на_свою_секретную_фразу_12345';
const DB_FILE = path.join(__dirname, 'database.json');
const UPLOADS = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOADS)) fs.mkdirSync(UPLOADS);

// ═══ База данных (файл) ═══
function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) {}
  return { users: {}, chats: {} };
}
function saveDB() { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
let db = loadDB();

// Кто онлайн
const onlineUsers = {};  // socketId → username
const userSockets = {};  // username → socketId

// ═══ Загрузка файлов ═══
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS),
  filename: (req, file, cb) => {
    const name = Date.now() + '_' + Math.random().toString(36).slice(2, 8) + path.extname(file.originalname);
    cb(null, name);
  }
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ═══ Миддлвары ═══
app.use(express.json());
app.use('/uploads', express.static(UPLOADS));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

function getChatId(u1, u2) { return [u1, u2].sort().join('__'); }

function verifyToken(token) {
  try { return jwt.verify(token, SECRET); } catch (e) { return null; }
}

function authMiddleware(req, res, next) {
  const decoded = verifyToken((req.headers.authorization || '').replace('Bearer ', ''));
  if (!decoded) return res.status(401).json({ error: 'Нет доступа' });
  req.username = decoded.username;
  next();
}

// ═══ HTTP: Регистрация / Вход ═══
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ ok: false, error: 'Заполни все поля' });
  if (username.length < 2) return res.json({ ok: false, error: 'Имя минимум 2 символа' });
  if (password.length < 4) return res.json({ ok: false, error: 'Пароль минимум 4 символа' });
  if (!/^[a-zA-Zа-яА-ЯёЁ0-9_]+$/.test(username)) return res.json({ ok: false, error: 'Имя: буквы, цифры, _' });
  if (db.users[username]) return res.json({ ok: false, error: 'Имя занято' });

  db.users[username] = { password: await bcrypt.hash(password, 10), created: Date.now() };
  saveDB();
  const token = jwt.sign({ username }, SECRET, { expiresIn: '30d' });
  res.json({ ok: true, token, username });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!db.users[username]) return res.json({ ok: false, error: 'Пользователь не найден' });
  if (!(await bcrypt.compare(password, db.users[username].password)))
    return res.json({ ok: false, error: 'Неверный пароль' });
  const token = jwt.sign({ username }, SECRET, { expiresIn: '30d' });
  res.json({ ok: true, token, username });
});

// ═══ HTTP: Поиск пользователей ═══
app.get('/api/users/search', authMiddleware, (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  if (!q) return res.json([]);
  const results = Object.keys(db.users)
    .filter(u => u !== req.username && u.toLowerCase().includes(q))
    .slice(0, 20)
    .map(u => ({ username: u, online: !!userSockets[u] }));
  res.json(results);
});

// ═══ HTTP: Загрузка файла ═══
app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Нет файла' });
  let type = 'file';
  if (req.file.mimetype.startsWith('image/')) type = 'image';
  else if (req.file.mimetype.startsWith('video/')) type = 'video';
  res.json({
    ok: true,
    filePath: '/uploads/' + req.file.filename,
    fileName: req.file.originalname,
    fileType: type,
    fileSize: req.file.size
  });
});

// ═══ Функции ═══
function sendConversations(socket, username) {
  const list = [];
  for (const [chatId, chat] of Object.entries(db.chats)) {
    if (!chat.participants.includes(username)) continue;
    const other = chat.participants.find(p => p !== username);
    const last = chat.messages[chat.messages.length - 1];
    const unread = chat.messages.filter(m => m.from !== username && !m.read).length;
    list.push({
      chatId, username: other,
      lastMessage: last || null,
      unreadCount: unread,
      online: !!userSockets[other]
    });
  }
  list.sort((a, b) => (b.lastMessage?.timestamp || 0) - (a.lastMessage?.timestamp || 0));
  socket.emit('conversations', list);
}

function markAsRead(chatId, username) {
  const chat = db.chats[chatId];
  if (!chat) return;
  let changed = false;
  chat.messages.forEach(m => { if (m.from !== username && !m.read) { m.read = true; changed = true; } });
  if (changed) saveDB();
}

function notifyStatus(username, online) {
  for (const [, chat] of Object.entries(db.chats)) {
    if (!chat.participants.includes(username)) continue;
    const other = chat.participants.find(p => p !== username);
    if (userSockets[other]) {
      io.to(userSockets[other]).emit('user_status', {
        username, online,
        lastSeen: db.users[username]?.lastSeen
      });
    }
  }
}

// ═══ СОКЕТЫ ═══
io.on('connection', (socket) => {

  socket.on('auth', (token) => {
    const d = verifyToken(token);
    if (!d) return socket.emit('auth_fail');
    onlineUsers[socket.id] = d.username;
    userSockets[d.username] = socket.id;
    socket.emit('auth_ok', { username: d.username });
    notifyStatus(d.username, true);
    sendConversations(socket, d.username);
  });

  socket.on('get_conversations', () => {
    const u = onlineUsers[socket.id];
    if (u) sendConversations(socket, u);
  });

  socket.on('get_messages', ({ withUser }) => {
    const u = onlineUsers[socket.id];
    if (!u) return;
    const chatId = getChatId(u, withUser);
    const chat = db.chats[chatId];
    socket.emit('messages', {
      chatId, withUser,
      messages: chat ? chat.messages.slice(-300) : [],
      online: !!userSockets[withUser],
      lastSeen: db.users[withUser]?.lastSeen
    });
    if (chat) {
      markAsRead(chatId, u);
      sendConversations(socket, u);
      if (userSockets[withUser]) {
        io.to(userSockets[withUser]).emit('messages_read', { chatId, by: u });
      }
    }
  });

  socket.on('send_message', (data) => {
    const u = onlineUsers[socket.id];
    if (!u || !data.to || !db.users[data.to]) return;

    const chatId = getChatId(u, data.to);
    if (!db.chats[chatId]) db.chats[chatId] = { participants: [u, data.to].sort(), messages: [] };

    const text = (data.text || '').replace(/</g, '&lt;').replace(/>/g, '&gt;').slice(0, 5000);

    const msg = {
      id: Date.now() + '_' + Math.random().toString(36).slice(2, 7),
      from: u, text,
      type: data.type || 'text',
      filePath: data.filePath || null,
      fileName: data.fileName || null,
      fileSize: data.fileSize || null,
      timestamp: Date.now(),
      time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
      read: false
    };

    db.chats[chatId].messages.push(msg);
    if (db.chats[chatId].messages.length > 500) db.chats[chatId].messages = db.chats[chatId].messages.slice(-500);
    saveDB();

    socket.emit('new_message', { chatId, message: msg });
    sendConversations(socket, u);

    if (userSockets[data.to]) {
      io.to(userSockets[data.to]).emit('new_message', { chatId, message: msg });
      const rs = io.sockets.sockets.get(userSockets[data.to]);
      if (rs) sendConversations(rs, data.to);
    }
  });

  socket.on('typing', ({ to }) => {
    const u = onlineUsers[socket.id];
    if (u && userSockets[to]) io.to(userSockets[to]).emit('typing', { from: u });
  });

  socket.on('read', ({ chatId }) => {
    const u = onlineUsers[socket.id];
    if (!u) return;
    markAsRead(chatId, u);
    const chat = db.chats[chatId];
    if (chat) {
      const other = chat.participants.find(p => p !== u);
      if (userSockets[other]) io.to(userSockets[other]).emit('messages_read', { chatId, by: u });
    }
    sendConversations(socket, u);
  });

  socket.on('disconnect', () => {
    const u = onlineUsers[socket.id];
    if (u) {
      delete onlineUsers[socket.id];
      delete userSockets[u];
      if (db.users[u]) { db.users[u].lastSeen = Date.now(); saveDB(); }
      notifyStatus(u, false);
    }
  });
});

server.listen(3000, () => {
  console.log('');
  console.log('══════════════════════════════════════');
  console.log('  💬 Мессенджер запущен!');
  console.log('  📍 http://localhost:3000');
  console.log('══════════════════════════════════════');
});