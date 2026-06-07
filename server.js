const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = 'my_secret_key_for_diplom_2024';

// Подключаемся к файлу базы данных
const db = new sqlite3.Database('./budgetshare.db', (err) => {
  if (err) {
    console.error('Ошибка подключения к БД:', err.message);
  } else {
    console.log('Подключено к SQLite базе данных');
    createTables();
  }
});

function createTables() {
  // Таблица Users (пользователи)
  db.run(`
    CREATE TABLE IF NOT EXISTS Users (
      Id INTEGER PRIMARY KEY AUTOINCREMENT,
      FullName TEXT NOT NULL,
      Email TEXT NOT NULL UNIQUE,
      PasswordHash TEXT NOT NULL,
      CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Таблица Projects (проекты)
  db.run(`
    CREATE TABLE IF NOT EXISTS Projects (
      Id INTEGER PRIMARY KEY AUTOINCREMENT,
      OwnerId INTEGER NOT NULL,
      Name TEXT NOT NULL,
      Budget REAL NOT NULL,
      MembersJson TEXT NOT NULL,
      Description TEXT,
      CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (OwnerId) REFERENCES Users(Id) ON DELETE CASCADE
    )
  `);

  // Таблица Expenses (расходы)
  db.run(`
    CREATE TABLE IF NOT EXISTS Expenses (
      Id INTEGER PRIMARY KEY AUTOINCREMENT,
      ProjectId INTEGER NOT NULL,
      Category TEXT NOT NULL,
      Amount REAL NOT NULL,
      Description TEXT NOT NULL,
      MemberName TEXT NOT NULL,
      ExpenseDate DATE NOT NULL DEFAULT CURRENT_DATE,
      FOREIGN KEY (ProjectId) REFERENCES Projects(Id) ON DELETE CASCADE
    )
  `);

  console.log('Таблицы созданы');
}

// Функции для работы с БД
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// ============= АУТЕНТИФИКАЦИЯ =============

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'Нет токена' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Нет токена' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Неверный токен' });
  }
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// РЕГИСТРАЦИЯ
app.post('/api/register', async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({ message: 'Заполни все поля' });
    }

    const existing = await dbGet('SELECT Id FROM Users WHERE Email = ?', [email]);
    if (existing) {
      return res.status(400).json({ message: 'Пользователь с таким email уже существует' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await dbRun(
      'INSERT INTO Users (FullName, Email, PasswordHash) VALUES (?, ?, ?)',
      [fullName, email, passwordHash]
    );

    const token = jwt.sign(
      { id: result.lastID, fullName: fullName, email: email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: result.lastID,
        fullName: fullName,
        email: email,
        createdAt: new Date().toISOString()
      }
    });
  } catch (err) {
    res.status(500).json({ message: 'Ошибка регистрации', error: err.message });
  }
});

// ВХОД
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Заполни email и пароль' });
    }

    const user = await dbGet('SELECT * FROM Users WHERE Email = ?', [email]);

    if (!user) {
      return res.status(400).json({ message: 'Неверный email или пароль' });
    }

    const ok = await bcrypt.compare(password, user.PasswordHash);

    if (!ok) {
      return res.status(400).json({ message: 'Неверный email или пароль' });
    }

    const token = jwt.sign(
      { id: user.Id, fullName: user.FullName, email: user.Email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.Id,
        fullName: user.FullName,
        email: user.Email,
        createdAt: user.CreatedAt
      }
    });
  } catch (err) {
    res.status(500).json({ message: 'Ошибка входа', error: err.message });
  }
});

// ПОЛУЧИТЬ ВСЕ ПРОЕКТЫ
app.get('/api/projects', authMiddleware, async (req, res) => {
  try {
    const projects = await dbAll(
      'SELECT * FROM Projects WHERE OwnerId = ? ORDER BY CreatedAt DESC',
      [req.user.id]
    );

    const formattedProjects = projects.map(p => ({
      id: p.Id,
      ownerId: p.OwnerId,
      name: p.Name,
      budget: p.Budget,
      members: JSON.parse(p.MembersJson),
      description: p.Description,
      createdAt: p.CreatedAt
    }));

    res.json(formattedProjects);
  } catch (err) {
    res.status(500).json({ message: 'Ошибка загрузки проектов', error: err.message });
  }
});

// СОЗДАТЬ ПРОЕКТ
app.post('/api/projects', authMiddleware, async (req, res) => {
  try {
    const { name, budget, members, description } = req.body;

    if (!name || budget === undefined || !members || !Array.isArray(members)) {
      return res.status(400).json({ message: 'Заполни название, бюджет и участников' });
    }

    const result = await dbRun(
      `INSERT INTO Projects (OwnerId, Name, Budget, MembersJson, Description)
       VALUES (?, ?, ?, ?, ?)`,
      [req.user.id, name, budget, JSON.stringify(members), description || '']
    );

    res.json({
      id: result.lastID,
      ownerId: req.user.id,
      name: name,
      budget: budget,
      members: members,
      description: description || '',
      createdAt: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ message: 'Ошибка создания проекта', error: err.message });
  }
});

// УДАЛИТЬ ПРОЕКТ
app.delete('/api/projects/:id', authMiddleware, async (req, res) => {
  try {
    const projectId = req.params.id;

    const project = await dbGet(
      'SELECT Id FROM Projects WHERE Id = ? AND OwnerId = ?',
      [projectId, req.user.id]
    );

    if (!project) {
      return res.status(404).json({ message: 'Проект не найден' });
    }

    await dbRun('DELETE FROM Projects WHERE Id = ? AND OwnerId = ?', [projectId, req.user.id]);

    res.json({ message: 'Проект удалён' });
  } catch (err) {
    res.status(500).json({ message: 'Ошибка удаления проекта', error: err.message });
  }
});

// ПОЛУЧИТЬ РАСХОДЫ ПРОЕКТА
app.get('/api/projects/:id/expenses', authMiddleware, async (req, res) => {
  try {
    const project = await dbGet(
      'SELECT Id FROM Projects WHERE Id = ? AND OwnerId = ?',
      [req.params.id, req.user.id]
    );

    if (!project) {
      return res.status(404).json({ message: 'Проект не найден' });
    }

    const expenses = await dbAll(
      'SELECT * FROM Expenses WHERE ProjectId = ? ORDER BY ExpenseDate DESC, Id DESC',
      [req.params.id]
    );

    res.json(expenses);
  } catch (err) {
    res.status(500).json({ message: 'Ошибка загрузки расходов', error: err.message });
  }
});

// ДОБАВИТЬ РАСХОД
app.post('/api/projects/:id/expenses', authMiddleware, async (req, res) => {
  try {
    const { category, amount, description, memberName } = req.body;

    if (!category || amount === undefined || !description || !memberName) {
      return res.status(400).json({ message: 'Заполни все поля расхода' });
    }

    const project = await dbGet(
      'SELECT Id FROM Projects WHERE Id = ? AND OwnerId = ?',
      [req.params.id, req.user.id]
    );

    if (!project) {
      return res.status(404).json({ message: 'Проект не найден' });
    }

    const result = await dbRun(
      `INSERT INTO Expenses (ProjectId, Category, Amount, Description, MemberName)
       VALUES (?, ?, ?, ?, ?)`,
      [req.params.id, category, amount, description, memberName]
    );

    const newExpense = await dbGet('SELECT * FROM Expenses WHERE Id = ?', [result.lastID]);

    res.json(newExpense);
  } catch (err) {
    res.status(500).json({ message: 'Ошибка добавления расхода', error: err.message });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`);
  console.log(`Файл базы данных: budgetshare.db`);
});