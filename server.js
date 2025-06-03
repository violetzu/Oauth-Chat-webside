/**
 * server.js
 * 全 Node.js 實作：HTTPS + OAuth 登入 + WebSocket + Ollama AI 指令
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const axios = require('axios');

// 讀取 .env 變數
const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  JWT_SECRET,
  SESSION_SECRET,
  CF_CERT_PATH,
  CF_KEY_PATH
} = process.env;

// 確認必填變數都有
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !JWT_SECRET || !SESSION_SECRET || !CF_CERT_PATH || !CF_KEY_PATH) {
  console.error('請確認 .env 裡面已設定 GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / JWT_SECRET / SESSION_SECRET / CF_CERT_PATH / CF_KEY_PATH');
  process.exit(1);
}

// 1. 建立 Express App、設定 Session + Passport
const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// 2. Passport Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => {
    const user = { id: profile.id, name: profile.displayName };
    return done(null, user);
  }
));

// 3. OAuth Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login.html' }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id, name: req.user.name }, JWT_SECRET, { expiresIn: '2h' });
    return res.redirect(`/chat.html?token=${token}`);
  }
);
app.get('/logout', (req, res) => {
  req.logout(err => {
    if (err) console.error(err);
    res.redirect('/login.html');
  });
});

// -----------------------------------------------------------------------------
// 4. 檔案儲存聊天紀錄的部分
// -----------------------------------------------------------------------------

// 4.1 chatlog 檔案路徑
const CHATLOG_PATH = path.join(__dirname, 'chatlog.json');

// 4.2 每次伺服器啟動時，確認 chatlog.json 存在且是有效的陣列
function ensureChatlogFile() {
  if (!fs.existsSync(CHATLOG_PATH)) {
    fs.writeFileSync(CHATLOG_PATH, '[]', 'utf8');
  } else {
    try {
      const data = fs.readFileSync(CHATLOG_PATH, 'utf8');
      JSON.parse(data); // 嘗試 parse，一旦錯誤就重置
    } catch (e) {
      fs.writeFileSync(CHATLOG_PATH, '[]', 'utf8');
    }
  }
}

// 4.3 把新的訊息「推」到 chatlog.json
function appendChatLog(messageObj) {
  try {
    const data = fs.readFileSync(CHATLOG_PATH, 'utf8');
    const arr = JSON.parse(data);
    arr.push(messageObj);
    fs.writeFileSync(CHATLOG_PATH, JSON.stringify(arr, null, 2), 'utf8');
  } catch (err) {
    console.error('寫入 chatlog.json 失敗：', err);
  }
}

// 確保檔案存在
ensureChatlogFile();

// -----------------------------------------------------------------------------
// 5. 設定 HTTPS + WebSocket
// -----------------------------------------------------------------------------

// 讀 Cloudflare 證書
const serverOptions = {
  cert: fs.readFileSync(CF_CERT_PATH, 'utf8'),
  key: fs.readFileSync(CF_KEY_PATH, 'utf8')
};
const server = https.createServer(serverOptions, app);
const wss = new WebSocket.Server({ noServer: true });

// 廣播給所有 client 的 function
function broadcastMessage(message) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// Ollama AI 回應函式
async function handleCommand(command, ws, username) {
  // 5.1 廣播使用者的原始 /ai 指令
  const userCmd = { type: 'chat', payload: { from: username, text: `${command}` } };
  broadcastMessage(JSON.stringify(userCmd));
  appendChatLog(userCmd); // 寫入檔案

  // 5.2 呼叫 Ollama
  try {
    const prompt = command.substring(1);
    const response = await axios.post('http://localhost:11434/api/generate', {
      model: 'llama2',
      prompt: prompt,
      stream: false
    });
    const aiReply = response.data.response || 'AI 沒有回應';
    const aiMsg = { type: 'chat', payload: { from: 'AI', text: aiReply } };
    broadcastMessage(JSON.stringify(aiMsg));
    appendChatLog(aiMsg); // 寫入檔案

  } catch (error) {
    console.error('Error connecting to Ollama:', error.message);
    const errMsg = { type: 'chat', payload: { from: 'AI', text: 'AI 無法回應，請稍後再試。' } };
    ws.send(JSON.stringify(errMsg));
    appendChatLog(errMsg); // 寫入檔案
  }
}

// WebSocket 握手驗證
server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const token = url.searchParams.get('token');
  if (!token) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }
    req.user = { id: decoded.id, name: decoded.name };
    wss.handleUpgrade(req, socket, head, ws => {
      wss.emit('connection', ws, req);
    });
  });
});

// WebSocket 連線後
wss.on('connection', (ws, req) => {
  const user = req.user; // { id, name }

  // 5.3 第一步：把歷史訊息一次讀出來，發給這個新連線的 client
  try {
    const data = fs.readFileSync(CHATLOG_PATH, 'utf8');
    const history = JSON.parse(data);
    // 把每一筆歷史訊息依序送過去
    history.forEach(item => {
      ws.send(JSON.stringify(item));
    });
  } catch (e) {
    console.error('讀取 chatlog.json 失敗：', e);
  }

  // 5.4 再把「歡迎訊息」寄給這位使用者
//   const welcomeMsg = { type: 'welcome', payload: { name: user.name } };
//   ws.send(JSON.stringify(welcomeMsg));
//   appendChatLog(welcomeMsg);

  // 5.5 廣播「加入通知」給其他人
  const joinNotice = { type: 'notification', payload: { message: `${user.name} 加入了聊天室！` } };
  broadcastMessage(JSON.stringify(joinNotice));
  appendChatLog(joinNotice);

  // 5.6 處理收到的 client 訊息
  ws.on('message', data => {
    let msgObj;
    try {
      msgObj = JSON.parse(data);
    } catch (e) {
      return;
    }
    if (msgObj.type === 'chat') {
      const text = msgObj.payload.text.trim();
      // 如果以 /ai 開頭，就觸發 AI
      if (text.startsWith('/ai')) {
        handleCommand(text, ws, user.name);
      } else {
        const chatMsg = { type: 'chat', payload: { from: user.name, text } };
        broadcastMessage(JSON.stringify(chatMsg));
        appendChatLog(chatMsg);
      }
    }
  });

  // 5.7 處理 client 關閉連線
  ws.on('close', () => {
    const leaveNotice = { type: 'notification', payload: { message: `${user.name} 離開了聊天室。` } };
    broadcastMessage(JSON.stringify(leaveNotice));
    appendChatLog(leaveNotice);
  });
});

// 啟動 HTTPS Server
const PORT = 443;
server.listen(PORT, () => {
  console.log(`HTTPS 伺服器啟動，請打開 https://marimo.idv.tw 測試`);
});
