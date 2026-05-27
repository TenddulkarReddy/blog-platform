const express = require('express');
const { Pool } = require('pg');
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

// Enforcing strict SSL configuration required by Render PostgreSQL Core
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const initDB = async () => {
  try {
    const client = await db.connect();
    console.log('Successfully connected to Render PostgreSQL Database. Verifying tables...');
    
    // Create Users Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL
      )
    `);

    // Create Posts Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS posts (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        "authorId" INT NOT NULL,
        "createdAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY ("authorId") REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Create Comments Table
    await client.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        content TEXT NOT NULL,
        "postId" INT NOT NULL,
        "authorId" INT NOT NULL,
        "createdAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY ("postId") REFERENCES posts(id) ON DELETE CASCADE,
        FOREIGN KEY ("authorId") REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    client.release();
    console.log('All PostgreSQL Database tables initialized successfully.');
  } catch (err) {
    // Printing full error stack trace to the terminal logs so nothing is blank
    console.error('Critical Error initializing database tables:', err);
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
    const existing = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) return res.status(400).json({ message: 'Username taken.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const users = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (users.rows.length === 0) return res.status(400).json({ message: 'User not found.' });
    
    const user = users.rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(400).json({ message: 'Invalid credentials.' });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ token, username: user.username, userId: user.id });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/posts', async (req, res) => {
  try {
    const posts = await db.query(`
      SELECT p.*, u.username AS "authorName" FROM posts p 
      JOIN users u ON p."authorId" = u.id ORDER BY p.createdAt DESC
    `);
    res.json(posts.rows);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    const result = await db.query('INSERT INTO posts (title, content, "authorId") VALUES ($1, $2, $3) RETURNING id', [title, content, req.user.id]);
    res.status(201).json({ id: result.rows[0].id, title, content, authorId: req.user.id });
  } catch (error) { res.status(500).json({ error: error.message }); }
 });

app.get('/api/posts/:postId/comments', async (req, res) => {
  try {
    const comments = await db.query(`
      SELECT c.*, u.username AS "authorName" FROM comments c 
      JOIN users u ON c."authorId" = u.id WHERE c."postId" = $1 ORDER BY c.createdAt DESC
    `, [req.params.postId]);
    res.json(comments.rows);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/posts/:postId/comments', authenticateToken, async (req, res) => {
  try {
    const { content } = req.body;
    await db.query('INSERT INTO comments (content, "postId", "authorId") VALUES ($1, $2, $3)', [content, req.params.postId, req.user.id]);
    res.status(201).json({ message: 'Comment published.' });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
