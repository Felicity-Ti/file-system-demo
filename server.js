const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const cors = require("cors");

const app = express();
const db = new sqlite3.Database("data.db");

// 创建 uploads 目录
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// 中间件
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(session({
  secret: "please-change-this-secret",
  resave: false,
  saveUninitialized: false
}));

// 静态文件（前端页面）
app.use(express.static("public"));

// 首页（默认打开 login.html）
app.get("/", function (req, res) {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// 初始化数据库
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    original_name TEXT,
    saved_name TEXT,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// 文件上传配置
const storage = multer.diskStorage({
  destination: "uploads/",
  filename: function (req, file, cb) {
    const safeName = Date.now() + "-" + file.originalname;
    cb(null, safeName);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 20 * 1024 * 1024
  }
});

// 登录校验
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "请先登录" });
  }
  next();
}

// 初始化账号
app.get("/init", async function (req, res) {
  const username = "admin";
  const password = "123456";
  const hash = await bcrypt.hash(password, 10);

  db.run(
    "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
    [username, hash],
    function (err) {
      if (err) {
        return res.status(500).send("初始化失败");
      }
      res.send("初始化完成，账号：admin，密码：123456");
    }
  );
});

// 登录
app.post("/api/login", function (req, res) {
  const username = req.body.username;
  const password = req.body.password;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async function (err, user) {
      if (err) return res.status(500).json({ error: "服务器错误" });
      if (!user) return res.status(401).json({ error: "账号或密码错误" });

      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).json({ error: "账号或密码错误" });

      req.session.userId = user.id;
      req.session.username = user.username;

      res.json({ message: "登录成功" });
    }
  );
});

// 上传文件
app.post("/api/upload", requireLogin, upload.single("file"), function (req, res) {
  if (!req.file) {
    return res.status(400).json({ error: "请选择文件" });
  }

  db.run(
    "INSERT INTO files (user_id, original_name, saved_name) VALUES (?, ?, ?)",
    [req.session.userId, req.file.originalname, req.file.filename],
    function (err) {
      if (err) {
        return res.status(500).json({ error: "保存文件信息失败" });
      }

      res.json({ message: "上传成功" });
    }
  );
});

// 文件列表
app.get("/api/files", requireLogin, function (req, res) {
  db.all(
    "SELECT id, original_name, uploaded_at FROM files WHERE user_id = ? ORDER BY id DESC",
    [req.session.userId],
    function (err, rows) {
      if (err) {
        return res.status(500).json({ error: "读取文件列表失败" });
      }
      res.json(rows);
    }
  );
});

// 下载文件
app.get("/api/download/:id", requireLogin, function (req, res) {
  db.get(
    "SELECT * FROM files WHERE id = ? AND user_id = ?",
    [req.params.id, req.session.userId],
    function (err, file) {
      if (err) return res.status(500).send("服务器错误");
      if (!file) return res.status(404).send("文件不存在");

      const filePath = path.join(__dirname, "uploads", file.saved_name);
      res.download(filePath, file.original_name);
    }
  );
});

// 退出登录
app.post("/api/logout", function (req, res) {
  req.session.destroy(function () {
    res.json({ message: "已退出登录" });
  });
});

// 启动服务器
const PORT = process.env.PORT || 3000;

app.listen(PORT, function () {
  console.log("服务器已启动，端口：" + PORT);
});
