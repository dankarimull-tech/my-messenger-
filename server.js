const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { MongoClient } = require('mongodb');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const SECRET = 'my_super_secret_key_change_me_12345';
const UPLOADS = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS)) fs.mkdirSync(UPLOADS);

// ══════════════════════════════════════════
// БАЗА ДАННЫХ
// ══════════════════════════════════════════
const MONGO_URI = process.env.MONGODB_URI || 'mongodb+srv://messengeruser:MyPass1234@messenger.ikd9kcw.mongodb.net/?appName=messenger';

var db = { users: {}, chats: {}, friends: {} };
var mongoDb = null;

async function connectMongo() {
  try {
    var client = new MongoClient(MONGO_URI);
    await client.connect();
    mongoDb = client.db('messenger');
    console.log('  База данных подключена!');

    var data = await mongoDb.collection('data').findOne({ _id: 'main' });
    if (data) {
      db.users = data.users || {};
      db.chats = data.chats || {};
      db.friends = data.friends || {};
      console.log('  Данные загружены: ' + Object.keys(db.users).length + ' пользователей');
    } else {
      console.log('  База пустая, начинаем с нуля');
    }
  } catch (e) {
    console.log('  Ошибка MongoDB: ' + e.message);
    console.log('  Работаю без базы данных (данные будут теряться при перезапуске)');
  }
}

function saveDB() {
  if (mongoDb) {
    mongoDb.collection('data').replaceOne(
      { _id: 'main' },
      { _id: 'main', users: db.users, chats: db.chats, friends: db.friends },
      { upsert: true }
    ).catch(function(e) { console.log('Ошибка сохранения: ' + e.message); });
  }
}

// ══════════════════════════════════════════
// ОСТАЛЬНОЙ КОД
// ══════════════════════════════════════════
var onlineUsers = {};
var userSockets = {};

var storage = multer.diskStorage({
  destination: function(req, file, cb) { cb(null, UPLOADS); },
  filename: function(req, file, cb) { cb(null, Date.now() + '_' + Math.random().toString(36).slice(2,8) + path.extname(file.originalname)); }
});
var upload = multer({ storage: storage, limits: { fileSize: 50 * 1024 * 1024 } });

app.use(express.json());
app.use('/uploads', express.static(UPLOADS));
app.get('/', function(req, res) { res.sendFile(path.join(__dirname, 'index.html')); });

function getChatId(a, b) { return [a, b].sort().join('__'); }
function verifyToken(t) { try { return jwt.verify(t, SECRET); } catch(e) { return null; } }
function authMW(req, res, next) {
  var d = verifyToken((req.headers.authorization||'').replace('Bearer ',''));
  if (!d) return res.status(401).json({error:'Нет доступа'});
  req.username = d.username; next();
}
function ensureProfile(u) {
  if (!db.users[u]) return;
  if (!db.users[u].profile) db.users[u].profile = { avatar:null, bio:'', birthday:'', nametag:'@'+u.toLowerCase().replace(/[^a-z0-9_]/g,'') };
  if (!db.friends[u]) db.friends[u] = [];
}

app.post('/api/register', async function(req, res) {
  var username = req.body.username;
  var password = req.body.password;
  if (!username||!password) return res.json({ok:false,error:'Заполни все поля'});
  if (username.length<2) return res.json({ok:false,error:'Имя минимум 2 символа'});
  if (password.length<4) return res.json({ok:false,error:'Пароль минимум 4 символа'});
  if (!/^[a-zA-Zа-яА-ЯёЁ0-9_]+$/.test(username)) return res.json({ok:false,error:'Имя: буквы, цифры, _'});
  if (db.users[username]) return res.json({ok:false,error:'Имя занято'});
  db.users[username] = { password: await bcrypt.hash(password,10), created:Date.now(), profile:{avatar:null,bio:'',birthday:'',nametag:'@'+username.toLowerCase().replace(/[^a-z0-9_]/g,'')} };
  db.friends[username] = [];
  saveDB();
  res.json({ok:true, token:jwt.sign({username:username},SECRET,{expiresIn:'30d'}), username:username});
});

app.post('/api/login', async function(req, res) {
  var username = req.body.username;
  var password = req.body.password;
  if (!db.users[username]) return res.json({ok:false,error:'Пользователь не найден'});
  if (!(await bcrypt.compare(password, db.users[username].password))) return res.json({ok:false,error:'Неверный пароль'});
  ensureProfile(username);
  res.json({ok:true, token:jwt.sign({username:username},SECRET,{expiresIn:'30d'}), username:username});
});

app.get('/api/users/search', authMW, function(req, res) {
  var q = (req.query.q||'').toLowerCase();
  if (!q) return res.json([]);
  res.json(Object.keys(db.users).filter(function(u) {
    if (u===req.username) return false;
    ensureProfile(u);
    return u.toLowerCase().includes(q) || (db.users[u].profile.nametag||'').toLowerCase().includes(q);
  }).slice(0,20).map(function(u) { return { username:u, nametag:db.users[u].profile.nametag, avatar:db.users[u].profile.avatar, bio:db.users[u].profile.bio, online:!!userSockets[u] }; }));
});

app.get('/api/profile/:username', authMW, function(req, res) {
  var u = req.params.username;
  if (!db.users[u]) return res.status(404).json({error:'Not found'});
  ensureProfile(u);
  var media = [];
  var chatId = getChatId(req.username, u);
  if (db.chats[chatId]) media = db.chats[chatId].messages.filter(function(m){return m.type==='image'||m.type==='video';}).map(function(m){return{type:m.type,filePath:m.filePath,time:m.time};}).reverse().slice(0,50);
  res.json({ username:u, profile:db.users[u].profile, online:!!userSockets[u], lastSeen:db.users[u].lastSeen, created:db.users[u].created, media:media, isFriend:(db.friends[req.username]||[]).includes(u) });
});

app.post('/api/profile/update', authMW, function(req, res) {
  ensureProfile(req.username);
  var p = db.users[req.username].profile;
  if (req.body.bio!==undefined) p.bio = req.body.bio.slice(0,200);
  if (req.body.birthday!==undefined) p.birthday = req.body.birthday;
  if (req.body.nametag!==undefined) {
    var tag = (req.body.nametag.startsWith('@')?req.body.nametag:'@'+req.body.nametag).toLowerCase().replace(/[^a-z0-9_@]/g,'').slice(0,32);
    var taken = Object.entries(db.users).some(function(entry){ if(entry[0]===req.username)return false; ensureProfile(entry[0]); return entry[1].profile.nametag===tag; });
    if (taken) return res.json({ok:false,error:'Неймтег занят'});
    p.nametag = tag;
  }
  saveDB();
  res.json({ok:true, profile:p});
});

app.post('/api/avatar', authMW, upload.single('avatar'), function(req, res) {
  if (!req.file) return res.status(400).json({error:'Нет файла'});
  ensureProfile(req.username);
  db.users[req.username].profile.avatar = '/uploads/'+req.file.filename;
  saveDB();
  res.json({ok:true, avatar:db.users[req.username].profile.avatar});
});

app.post('/api/upload', authMW, upload.single('file'), function(req, res) {
  if (!req.file) return res.status(400).json({error:'Нет файла'});
  var type = 'file';
  if (req.file.mimetype.startsWith('image/')) type='image';
  else if (req.file.mimetype.startsWith('video/')) type='video';
  res.json({ok:true, filePath:'/uploads/'+req.file.filename, fileName:req.file.originalname, fileType:type, fileSize:req.file.size});
});

app.get('/api/friends', authMW, function(req, res) {
  var list = (db.friends[req.username]||[]).filter(function(f){return db.users[f];}).map(function(f) { ensureProfile(f); return {username:f, nametag:db.users[f].profile.nametag, avatar:db.users[f].profile.avatar, bio:db.users[f].profile.bio, online:!!userSockets[f]}; });
  res.json(list);
});

app.post('/api/friends/add', authMW, function(req, res) {
  var u = req.body.username;
  if (!db.users[u]) return res.json({ok:false,error:'Не найден'});
  if (u===req.username) return res.json({ok:false,error:'Нельзя добавить себя'});
  if (!db.friends[req.username]) db.friends[req.username]=[];
  if (!db.friends[req.username].includes(u)) db.friends[req.username].push(u);
  if (!db.friends[u]) db.friends[u]=[];
  if (!db.friends[u].includes(req.username)) db.friends[u].push(req.username);
  saveDB();
  res.json({ok:true});
});

app.post('/api/friends/remove', authMW, function(req, res) {
  var u = req.body.username;
  db.friends[req.username] = (db.friends[req.username]||[]).filter(function(f){return f!==u;});
  if (db.friends[u]) db.friends[u] = db.friends[u].filter(function(f){return f!==req.username;});
  saveDB();
  res.json({ok:true});
});

function sendConvos(socket, username) {
  var list = [];
  for (var cid in db.chats) {
    var c = db.chats[cid];
    if (!c.participants.includes(username)) continue;
    var other = c.participants.find(function(p){return p!==username;});
    if (!db.users[other]) continue;
    ensureProfile(other);
    var last = c.messages[c.messages.length-1];
    var unread = c.messages.filter(function(m){return m.from!==username && !m.read;}).length;
    list.push({chatId:cid, username:other, avatar:db.users[other].profile.avatar, nametag:db.users[other].profile.nametag, lastMessage:last||null, unreadCount:unread, online:!!userSockets[other]});
  }
  list.sort(function(a,b){return (b.lastMessage?b.lastMessage.timestamp:0)-(a.lastMessage?a.lastMessage.timestamp:0);});
  socket.emit('conversations', list);
}

function markRead(chatId, u) {
  var c = db.chats[chatId]; if (!c) return; var ch=false;
  c.messages.forEach(function(m){if(m.from!==u&&!m.read){m.read=true;ch=true;}});
  if(ch)saveDB();
}

io.on('connection', function(socket) {
  socket.on('auth', function(token) {
    var d = verifyToken(token);
    if (!d) return socket.emit('auth_fail');
    ensureProfile(d.username);
    onlineUsers[socket.id] = d.username;
    userSockets[d.username] = socket.id;
    socket.emit('auth_ok', {username:d.username, profile:db.users[d.username].profile});
    sendConvos(socket, d.username);
    for (var cid in db.chats) {
      if (!db.chats[cid].participants.includes(d.username)) continue;
      var ot = db.chats[cid].participants.find(function(p){return p!==d.username;});
      if (userSockets[ot]) io.to(userSockets[ot]).emit('user_status',{username:d.username,online:true});
    }
  });

  socket.on('get_conversations', function(){var u=onlineUsers[socket.id];if(u)sendConvos(socket,u);});

  socket.on('get_messages', function(data) {
    var u = onlineUsers[socket.id]; if(!u) return;
    var chatId = getChatId(u, data.withUser);
    var c = db.chats[chatId];
    ensureProfile(data.withUser);
    socket.emit('messages', {chatId:chatId, withUser:data.withUser, messages:c?c.messages.slice(-300):[], online:!!userSockets[data.withUser], lastSeen:db.users[data.withUser]?db.users[data.withUser].lastSeen:null, avatar:db.users[data.withUser]?db.users[data.withUser].profile.avatar:null, nametag:db.users[data.withUser]?db.users[data.withUser].profile.nametag:null});
    if(c){markRead(chatId,u);sendConvos(socket,u);if(userSockets[data.withUser])io.to(userSockets[data.withUser]).emit('messages_read',{chatId:chatId,by:u});}
  });

  socket.on('send_message', function(data) {
    var u = onlineUsers[socket.id];
    if(!u||!data.to||!db.users[data.to]) return;
    var chatId = getChatId(u, data.to);
    if(!db.chats[chatId]) db.chats[chatId]={participants:[u,data.to].sort(),messages:[]};
    var text = (data.text||'').replace(/</g,'&lt;').replace(/>/g,'&gt;').slice(0,5000);
    var msg = {id:Date.now()+'_'+Math.random().toString(36).slice(2,7), from:u, text:text, type:data.type||'text', filePath:data.filePath||null, fileName:data.fileName||null, fileSize:data.fileSize||null, timestamp:Date.now(), time:new Date().toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'}), read:false};
    db.chats[chatId].messages.push(msg);
    if(db.chats[chatId].messages.length>500) db.chats[chatId].messages=db.chats[chatId].messages.slice(-500);
    saveDB();
    socket.emit('new_message',{chatId:chatId,message:msg});
    sendConvos(socket,u);
    if(userSockets[data.to]){io.to(userSockets[data.to]).emit('new_message',{chatId:chatId,message:msg});var rs=io.sockets.sockets.get(userSockets[data.to]);if(rs)sendConvos(rs,data.to);}
  });

  socket.on('typing', function(data){var u=onlineUsers[socket.id];if(u&&data.to&&userSockets[data.to])io.to(userSockets[data.to]).emit('typing',{from:u});});

  socket.on('read', function(data){
    var u=onlineUsers[socket.id];if(!u)return;
    markRead(data.chatId,u);
    var c=db.chats[data.chatId];
    if(c){var ot=c.participants.find(function(p){return p!==u;});if(userSockets[ot])io.to(userSockets[ot]).emit('messages_read',{chatId:data.chatId,by:u});}
    sendConvos(socket,u);
  });

  socket.on('disconnect', function(){
    var u=onlineUsers[socket.id];
    if(u){delete onlineUsers[socket.id];delete userSockets[u];if(db.users[u]){db.users[u].lastSeen=Date.now();saveDB();}
    for(var cid in db.chats){if(!db.chats[cid].participants.includes(u))continue;var ot=db.chats[cid].participants.find(function(p){return p!==u;});if(userSockets[ot])io.to(userSockets[ot]).emit('user_status',{username:u,online:false,lastSeen:Date.now()});}}
  });
});

// ══════════════════════════════════════════
// ЗАПУСК
// ══════════════════════════════════════════
async function start() {
  await connectMongo();
  var port = process.env.PORT || 3000;
  server.listen(port, function() {
    console.log('');
    console.log('='.repeat(40));
    console.log('  Мессенджер запущен!');
    console.log('  http://localhost:' + port);
    console.log('='.repeat(40));
  });
}

start();