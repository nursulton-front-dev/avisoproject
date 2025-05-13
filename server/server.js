const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_very_long_and_random_secret_key_1234567890';

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));
app.use(express.static(path.join(__dirname, '../public')));

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Ограниченное логирование
app.use((req, res, next) => {
  if (req.path.startsWith('/api/') && req.method === 'POST') {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - IP: ${req.ip}`);
  }
  next();
});

// Middleware для ограничения по IP
const rateLimit = {};
const RATE_LIMIT = 10; // Максимум 10 запросов
const RATE_WINDOW = 60 * 1000; // За 1 минуту

function rateLimitMiddleware(req, res, next) {
  const ip = req.ip;
  const now = Date.now();

  if (!rateLimit[ip]) {
    rateLimit[ip] = [];
  }

  rateLimit[ip] = rateLimit[ip].filter(timestamp => now - timestamp < RATE_WINDOW);

  if (rateLimit[ip].length >= RATE_LIMIT) {
    return res.status(429).json({ error: 'Слишком много запросов. Попробуйте позже.' });
  }

  rateLimit[ip].push(now);
  next();
}

// Тайм-аут для запросов
app.use((req, res, next) => {
  req.setTimeout(10000, () => {
    res.status(408).json({ error: 'Запрос превысил время ожидания' });
  });
  next();
});

const dbPath = path.join(__dirname, 'database.db');

// Инициализация базы данных
if (!fs.existsSync(dbPath)) {
  const newDb = new sqlite3.Database(dbPath, (err) => {
    if (err) {
      console.error('Failed to create database:', err.message);
      process.exit(1);
    }
    console.log('Database created successfully');
  });
  newDb.serialize(() => {
    newDb.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT NOT NULL,
        role TEXT CHECK(role IN ('buyer', 'seller', NULL)) DEFAULT NULL,
        bio TEXT,
        balance REAL DEFAULT 0.0,
        ip_address TEXT DEFAULT NULL
      );
    `, (err) => {
      if (err) {
        console.error('Failed to create users table:', err.message);
      } else {
        console.log('Users table created successfully');
      }
    });
    newDb.run(`
      CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        userId INTEGER
      );
    `, (err) => {
      if (err) {
        console.error('Failed to create items table:', err.message);
      }
    });
    newDb.run(`
      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER,
        itemId INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `, (err) => {
      if (err) {
        console.error('Failed to create orders table:', err.message);
      }
    });
  });
  newDb.close();
}

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Failed to connect to database:', err.message);
    process.exit(1);
  }
  console.log('Connected to database');
  // Проверка и миграция схемы
  db.all("PRAGMA table_info(users)", (err, rows) => {
    if (err) {
      console.error('Failed to check users table schema:', err.message);
      return;
    }
    if (!rows || rows.length === 0) {
      console.error('No columns found for users table');
      return;
    }
    const columns = rows.map(row => row.name);
    console.log('Columns in users table:', columns);
    if (!columns.includes('email')) {
      console.log('Adding email column to users table');
      db.run('ALTER TABLE users ADD COLUMN email TEXT UNIQUE', (err) => {
        if (err) {
          console.error('Failed to add email column:', err.message);
        } else {
          console.log('Email column added successfully');
        }
      });
    }
  });
});

// Middleware для проверки токена
function authMiddleware(req, res, next) {
  const tokenFromCookies = req.cookies.token || null;
  const tokenFromHeaders = req.headers.authorization ? req.headers.authorization.split(' ')[1] : null;
  const finalToken = tokenFromCookies || tokenFromHeaders;

  if (!finalToken) {
    return res.status(401).json({ error: 'Нет токена' });
  }

  jwt.verify(finalToken, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Неверный токен' });
    }
    req.user = decoded;
    next();
  });
}

// Регистрация с проверкой капчи
app.get('/register', (req, res) => {
  const captchaNum1 = Math.floor(Math.random() * 10) + 1;
  const captchaNum2 = Math.floor(Math.random() * 10) + 1;
  res.render('register', { error: null, user: null, captcha: { num1: captchaNum1, num2: captchaNum2 } });
});

app.post('/api/register', rateLimitMiddleware, (req, res) => {
  const { username, email, password, confirmPassword, captchaAnswer } = req.body;
  const expectedCaptcha = parseInt(req.body.captchaNum1) + parseInt(req.body.captchaNum2);

  if (parseInt(captchaAnswer) !== expectedCaptcha) {
    return res.status(400).json({ error: 'Неверный ответ капчи' });
  }

  if (!username || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: 'Все поля должны быть заполнены' });
  }
  if (typeof username !== 'string' || username.length < 3) {
    return res.status(400).json({ error: 'Имя пользователя должно быть строкой и не менее 3 символов' });
  }
  if (typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'Неверный формат email' });
  }
  if (typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ error: 'Пароль должен быть строкой и не менее 6 символов' });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Пароли не совпадают' });
  }

  db.get('SELECT username, email FROM users WHERE username = ? OR email = ?', [username, email], (err, row) => {
    if (err) {
      console.error('Register - DB check error:', err.message);
      return res.status(500).json({ error: 'Ошибка проверки пользователя' });
    }
    if (row) {
      if (row.username === username) {
        return res.status(400).json({ error: 'Пользователь с таким именем уже существует' });
      }
      if (row.email === email) {
        return res.status(400).json({ error: 'Email уже зарегистрирован' });
      }
    }

    const ipAddress = req.ip;
    if (typeof ipAddress !== 'string') {
      console.warn('Register - Invalid IP Address:', ipAddress);
      return res.status(500).json({ error: 'Неверный формат IP-адреса' });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error('Register - Hashing error:', err.message);
        return res.status(500).json({ error: 'Ошибка хеширования пароля' });
      }
      db.run('INSERT INTO users (username, email, password, ip_address) VALUES (?, ?, ?, ?)', [username, email, hashedPassword, ipAddress], function (err) {
        if (err) {
          console.error('Register - DB error:', err.message);
          return res.status(500).json({ error: 'Внутренняя ошибка базы данных: ' + err.message });
        }
        const token = jwt.sign({ userId: this.lastID }, SECRET_KEY, { expiresIn: '1h' });
        res.cookie('token', token, { maxAge: 3600000, secure: false, sameSite: 'Lax' });
        res.status(200).json({ success: true, redirect: '/dashboard' });
      });
    });
  });
});

// Логин
app.post('/api/login', rateLimitMiddleware, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Поля не должны быть пустыми' });
  }
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      console.error('Login DB error:', err);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    if (!user) {
      return res.status(401).json({ error: 'Пользователь не найден' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Неверный пароль' });
    }
    const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.cookie('token', token, { maxAge: 3600000, secure: false, sameSite: 'Lax' });
    res.status(200).json({ success: true, redirect: '/dashboard' });
  });
});

// Выход
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// Обновление роли
app.post('/api/update-role', authMiddleware, rateLimitMiddleware, (req, res) => {
  const { role } = req.body;
  if (!['buyer', 'seller'].includes(role)) {
    return res.status(400).json({ error: 'Неверная роль' });
  }
  db.run('UPDATE users SET role = ? WHERE id = ?', [role, req.user.userId], function (err) {
    if (err) {
      console.error('Update role error:', err);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    res.json({ success: true });
  });
});

// Обновление описания
app.post('/api/update-bio', authMiddleware, rateLimitMiddleware, (req, res) => {
  const { bio } = req.body;
  db.run('UPDATE users SET bio = ? WHERE id = ?', [bio, req.user.userId], function (err) {
    if (err) {
      console.error('Update bio error:', err);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    res.json({ success: true });
  });
});

// Получение задач
app.get('/api/items', (req, res) => {
  db.all('SELECT * FROM items', (err, rows) => {
    if (err) {
      console.error('Get items error:', err);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    res.json(rows);
  });
});

// Создание задания
app.post('/api/items', authMiddleware, rateLimitMiddleware, (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Имя обязательно' });
  db.run('INSERT INTO items (name, description, userId) VALUES (?, ?, ?)', [name, description, req.user.userId], function (err) {
    if (err) {
      console.error('Create item error:', err.message);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    res.json({ id: this.lastID, name, description });
  });
});

// Поиск пользователя по IP
app.get('/api/find-by-ip', authMiddleware, rateLimitMiddleware, (req, res) => {
  const ipToFind = req.query.ip;
  if (!ipToFind) {
    return res.status(400).json({ error: 'IP-адрес не указан' });
  }
  db.all('SELECT id, username, ip_address FROM users WHERE ip_address = ?', [ipToFind], (err, rows) => {
    if (err) {
      console.error('Find by IP error:', err);
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Пользователь с таким IP не найден' });
    }
    res.json(rows);
  });
});

// Страницы
app.get('/', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.render('index', { user: null });
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      console.error('Index JWT error:', err);
      return res.render('index', { user: null });
    }
    db.get('SELECT username FROM users WHERE id = ?', [decoded.userId], (err, user) => {
      if (err) {
        console.error('Index DB error:', err);
        return res.status(500).send('Ошибка сервера');
      }
      res.render('index', { user: user ? user.username : null });
    });
  });
});

app.get('/login', (req, res) => res.render('login', { error: null, user: null }));
app.get('/how', (req, res) => res.render('how', { user: null }));
app.get('/create-task', authMiddleware, (req, res) => {
  db.get('SELECT username FROM users WHERE id = ?', [req.user.userId], (err, user) => {
    if (err) {
      console.error('Create-task DB error:', err);
      return res.status(500).send('Ошибка сервера');
    }
    res.render('create-task', { user: user ? user.username : null });
  });
});

// Профиль
app.get('/profile', (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.render('profile', { isAuthenticated: false, username: null, email: null, role: null, bio: null, balance: null, items: [] });
  }
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      console.error('Profile JWT error:', err.message);
      return res.render('profile', { isAuthenticated: false, username: null, email: null, role: null, bio: null, balance: null, items: [] });
    }
    console.log('Profile - Decoded userId:', decoded.userId);
    db.get('SELECT username, email, role, bio, balance FROM users WHERE id = ?', [decoded.userId], (err, user) => {
      if (err) {
        console.error('Profile DB error:', err.message);
        return res.status(500).send('Ошибка сервера');
      }
      if (!user) {
        console.error('Profile - User not found for ID:', decoded.userId);
        return res.render('profile', { isAuthenticated: false, username: null, email: null, role: null, bio: null, balance: null, items: [] });
      }
      console.log('Profile - User found:', user);
      if (user.role === 'seller') {
        db.all('SELECT * FROM items WHERE userId = ?', [decoded.userId], (err, items) => {
          if (err) {
            console.error('Profile Items query error:', err.message);
            return res.status(500).send('Ошибка сервера');
          }
          res.render('profile', { 
            isAuthenticated: true, 
            username: user.username, 
            email: user.email || 'Не указан', 
            role: user.role, 
            bio: user.bio, 
            balance: user.balance,
            items: items || []
          });
        });
      } else {
        res.render('profile', { 
          isAuthenticated: true, 
          username: user.username, 
          email: user.email || 'Не указан', 
          role: user.role, 
          bio: user.bio, 
          balance: user.balance,
          items: []
        });
      }
    });
  });
});

// Защищённый dashboard
app.get('/dashboard', (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.render('dashboard', { isAuthenticated: false, items: [], user: null });
  }
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      console.error('Dashboard JWT error:', err);
      return res.render('dashboard', { isAuthenticated: false, items: [], user: null });
    }
    db.get('SELECT username FROM users WHERE id = ?', [decoded.userId], (err, user) => {
      if (err) {
        console.error('Dashboard DB error:', err);
        return res.status(500).send('Ошибка сервера');
      }
      db.all('SELECT * FROM items ORDER BY id DESC', (err, items) => {
        if (err) {
          console.error('Dashboard Items error:', err);
          return res.status(500).send('Ошибка сервера');
        }
        res.render('dashboard', { isAuthenticated: true, items, user: user ? user.username : null });
      });
    });
  });
});

// 404
app.use((req, res) => {
  res.status(404).render('404', { user: null });
});

// Старт сервера
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен: http://localhost:${PORT}`);
});