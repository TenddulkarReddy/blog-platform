const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_change_this_in_production';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));


// Hardcoded database engine configuration to bypass system environment variables
const db = mysql.createPool({
  host: 'mysql-2fef98f0-tenddulkarreddy-361b.j.aivencloud.com',
  user: 'avnadmin',
  password: 'AVNS_GIS5VHGHIN0rhZCkRre',
  database: 'defaultdb',
  port: 15403,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: {
    rejectUnauthorized: false
  }
});




const initDB = async () => {
  try {
    const conn = await db.getConnection();
    console.log('Successfully connected to Aiven MySQL Instance. Verifying tables...');
    
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL
      )
    `);
    await conn.query(`
      CREATE TABLE IF NOT EXISTS posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        authorId INT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (authorId) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    await conn.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        content TEXT NOT NULL,
        postId INT NOT NULL,
        authorId INT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (postId) REFERENCES posts(id) ON DELETE CASCADE,
        FOREIGN KEY (authorId) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    conn.release();
    console.log('All MySQL Database tables initialized successfully.');
  } catch (err) {
    console.error('Critical Error initializing database tables:', err.message);
  }
};
initDB();

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token missing.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });
    req.user = user;
    next();
  });
};

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const [existing] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (existing.length > 0) return res.status(400).json({ message: 'Username taken.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const [users] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length === 0) return res.status(400).json({ message: 'User not found.' });
    
    const user = users[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(400).json({ message: 'Invalid credentials.' });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ token, username: user.username, userId: user.id });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/posts', async (req, res) => {
  try {
    const [posts] = await db.execute(`
      SELECT p.*, u.username AS authorName FROM posts p 
      JOIN users u ON p.authorId = u.id ORDER BY p.createdAt DESC
    `);
    res.json(posts);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    const [result] = await db.execute('INSERT INTO posts (title, content, authorId) VALUES (?, ?, ?)', [title, content, req.user.id]);
    res.status(201).json({ id: result.insertId, title, content, authorId: req.user.id });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/posts/:postId/comments', async (req, res) => {
  try {
    const [comments] = await db.execute(`
      SELECT c.*, u.username AS authorName FROM comments c 
      JOIN users u ON c.authorId = u.id WHERE c.postId = ? ORDER BY c.createdAt DESC
    `, [req.params.postId]);
    res.json(comments);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/posts/:postId/comments', authenticateToken, async (req, res) => {
  try {
    const { content } = req.body;
    await db.execute('INSERT INTO comments (content, postId, authorId) VALUES (?, ?, ?)', [content, req.params.postId, req.user.id]);
    res.status(201).json({ message: 'Comment published.' });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Server executing seamlessly on port ${PORT}`));
