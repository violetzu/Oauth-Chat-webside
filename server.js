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

// 讀 .env
const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  JWT_SECRET,
  SESSION_SECRET,
  CF_CERT_PATH,
  CF_KEY_PATH
} = process.env;

// 確認必填項
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !JWT_SECRET || !SESSION_SECRET || !CF_CERT_PATH || !CF_KEY_PATH) {
  console.error('請確認 .env 裡已設定 GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / JWT_SECRET / SESSION_SECRET / CF_CERT_PATH / CF_KEY_PATH');
  process.exit(1);
}

// 檔案路徑與資料夾
const CHATLOG_PATH = path.join(__dirname, 'chatlog.json');
const AVATAR_DIR = path.join(__dirname, 'public', 'avatars');

// 確保 chatlog.json 存在且為有效 JSON 陣列
function ensureChatlogFile() {
  if (!fs.existsSync(CHATLOG_PATH)) {
    fs.writeFileSync(CHATLOG_PATH, '[]', 'utf8');
  } else {
    try {
      JSON.parse(fs.readFileSync(CHATLOG_PATH, 'utf8'));
    } catch {
      fs.writeFileSync(CHATLOG_PATH, '[]', 'utf8');
    }
  }
}
ensureChatlogFile();

// 確保 avatars 資料夾存在
if (!fs.existsSync(AVATAR_DIR)) {
  fs.mkdirSync(AVATAR_DIR, { recursive: true });
}

// 把新的訊息加到 chatlog.json
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

// Express + Passport 設定
const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => {
    // 把 user.id、user.name、user.photo 交給 req.user
    const user = {
      id: profile.id,
      name: profile.displayName,
      photo: (profile.photos && profile.photos[0] && profile.photos[0].value) || null
    };
    return done(null, user);
  }
));

// OAuth 路由
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

// callback 加 async 以便下載頭像
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login.html' }),
  async (req, res) => {
    // 先建立或快取用戶頭像
    if (req.user.photo) {
      const avatarPath = path.join(AVATAR_DIR, `${req.user.id}.jpg`);
      if (!fs.existsSync(avatarPath)) {
        try {
          const response = await axios.get(req.user.photo, { responseType: 'stream' });
          const writer = fs.createWriteStream(avatarPath);
          response.data.pipe(writer);
          await new Promise((resolve, reject) => {
            writer.on('finish', resolve);
            writer.on('error', reject);
          });
        } catch (err) {
          console.error(`下載或寫入頭像失敗：${err.message}`);
        }
      }
    }

    // 簽發 JWT（只帶 id 和 name）
    const token = jwt.sign(
      { id: req.user.id, name: req.user.name },
      JWT_SECRET,
      { expiresIn: '2h' }
    );
    return res.redirect(`/chat.html?token=${token}`);
  }
);

app.get('/logout', (req, res) => {
  req.logout(err => {
    if (err) console.error(err);
    res.redirect('/login.html');
  });
});

// HTTPS Server 設定（Cloudflare 原點憑證）
const serverOptions = {
  cert: fs.readFileSync(CF_CERT_PATH, 'utf8'),
  key: fs.readFileSync(CF_KEY_PATH, 'utf8')
};
const server = https.createServer(serverOptions, app);

// WebSocket Server
const wss = new WebSocket.Server({ noServer: true });

// 廣播給所有 client
function broadcastMessage(message) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// 處理 /ai 指令
async function handleCommand(command, ws, user) {
  // 廣播使用者的 /ai 指令
  const userCmd = {
    type: 'chat',
    payload: {
      from: user.name,
      text: `${command}`,
      avatar: `/avatars/${user.id}.jpg`
    }
  };
  broadcastMessage(JSON.stringify(userCmd));
  appendChatLog(userCmd);

  // 呼叫 Ollama
  try {
    const prompt = command.substring(1);
    const response = await axios.post('http://localhost:11434/api/generate', {
      model: 'llama2',
      prompt: prompt,
      stream: false
    });
    const aiReply = response.data.response || 'AI 沒有回應';
    const aiMsg = {
      type: 'chat',
      payload: {
        from: 'AI',
        text: aiReply,
        avatar: null
      }
    };
    broadcastMessage(JSON.stringify(aiMsg));
    appendChatLog(aiMsg);
  } catch (error) {
    console.error('連線到 Ollama 失敗：', error.message);
    const errMsg = {
      type: 'chat',
      payload: {
        from: 'AI',
        text: 'AI 無法回應，請稍後再試。',
        avatar: null
      }
    };
    ws.send(JSON.stringify(errMsg));
    appendChatLog(errMsg);
  }
}

// WebSocket 握手階段：驗證 JWT
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
    // 把解碼後 user 綁到 request.user
    req.user = { id: decoded.id, name: decoded.name };
    wss.handleUpgrade(req, socket, head, ws => {
      wss.emit('connection', ws, req);
    });
  });
});

// WebSocket 連線建立後
wss.on('connection', (ws, req) => {
  const user = req.user; // { id, name }

  // 歷史訊息先發給新連線 client
  try {
    const data = fs.readFileSync(CHATLOG_PATH, 'utf8');
    const history = JSON.parse(data);
    history.forEach(item => {
      ws.send(JSON.stringify(item));
    });
  } catch (e) {
    console.error('讀取 chatlog.json 失敗：', e);
  }

  // 歡迎訊息（帶 avatar）
  const avatarUrl = fs.existsSync(path.join(AVATAR_DIR, `${user.id}.jpg`))
    ? `/avatars/${user.id}.jpg`
    : null;

  const joinNotice = {
    type: 'welcome',
    payload: {
      name: user.name,
      avatar: avatarUrl
    }
  };
  broadcastMessage(JSON.stringify(joinNotice));
  appendChatLog(joinNotice);

  // 收到客戶端訊息
  ws.on('message', (data) => {
    let msgObj;
    try {
      msgObj = JSON.parse(data);
    } catch {
      return;
    }
    if (msgObj.type === 'chat') {
      const text = msgObj.payload.text.trim();
      const avatarPath = fs.existsSync(path.join(AVATAR_DIR, `${user.id}.jpg`))
        ? `/avatars/${user.id}.jpg`
        : null;

      if (text.startsWith('/')) {
        handleCommand(text, ws, user);
      } else {
        const chatMsg = {
          type: 'chat',
          payload: {
            from: user.name,
            text,
            avatar: avatarPath
          }
        };
        broadcastMessage(JSON.stringify(chatMsg));
        appendChatLog(chatMsg);
      }
    }
  });

  // 客戶端關閉連線
  ws.on('close', () => {
    const leaveNotice = {
      type: 'notification',
      payload: {
        message: `${user.name} 離開了聊天室。`,
        avatar: null
      }
    };
    broadcastMessage(JSON.stringify(leaveNotice));
    appendChatLog(leaveNotice);
  });
});

// 啟動 HTTPS 伺服器
const PORT = 443;
server.listen(PORT, () => {
  console.log(`HTTPS 伺服器啟動，請打開 https://marimo.idv.tw 測試`);
});
