const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'super_secret_key_change_this_in_production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 1. MySQL Database Connection Pool
const db = mysql.createPool({
  host: 'localhost',
  user: 'root',          // Your MySQL username
  password: '2007',  // Your MySQL password
  database: 'blogdb',
  waitForConnections: true,
  connectionLimit: 10
});

// Test connection
db.getConnection()
  .then(() => console.log('Connected to MySQL Database successfully.'))
  .catch(err => console.error('MySQL Connection Error:', err));

// 2. Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
};

// 3. RESTful API Endpoints via SQL Queries

// AUTHENTICATION ROUTES
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const [existing] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (existing.length > 0) return res.status(400).json({ message: 'Username already exists.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
    
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
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
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// BLOG POST ROUTES
app.get('/api/posts', async (req, res) => {
  try {
    // JOIN query to dynamically include author information
    const [posts] = await db.execute(`
      SELECT p.*, u.username AS authorName 
      FROM posts p 
      JOIN users u ON p.authorId = u.id 
      ORDER BY p.createdAt DESC
    `);
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    const [result] = await db.execute(
      'INSERT INTO posts (title, content, authorId) VALUES (?, ?, ?)',
      [title, content, req.user.id]
    );
    res.status(201).json({ id: result.insertId, title, content, authorId: req.user.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    const [posts] = await db.execute('SELECT * FROM posts WHERE id = ?', [req.params.id]);
    
    if (posts.length === 0) return res.status(404).json({ message: 'Post not found.' });
    if (posts[0].authorId !== req.user.id) return res.status(403).json({ message: 'Unauthorized action.' });

    await db.execute('UPDATE posts SET title = ?, content = ? WHERE id = ?', [title, content, req.params.id]);
    res.json({ message: 'Post updated successfully.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const [posts] = await db.execute('SELECT * FROM posts WHERE id = ?', [req.params.id]);
    
    if (posts.length === 0) return res.status(404).json({ message: 'Post not found.' });
    if (posts[0].authorId !== req.user.id) return res.status(403).json({ message: 'Unauthorized action.' });

    // Note: Foreign keys will handle automated ON DELETE CASCADE cascading operations if configured 
    await db.execute('DELETE FROM posts WHERE id = ?', [req.params.id]);
    res.json({ message: 'Post deleted successfully.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// COMMENT ROUTES
app.get('/api/posts/:postId/comments', async (req, res) => {
  try {
    const [comments] = await db.execute(`
      SELECT c.*, u.username AS authorName 
      FROM comments c 
      JOIN users u ON c.authorId = u.id 
      WHERE c.postId = ? 
      ORDER BY c.createdAt DESC
    `, [req.params.postId]);
    res.json(comments);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/posts/:postId/comments', authenticateToken, async (req, res) => {
  try {
    const { content } = req.body;
    await db.execute(
      'INSERT INTO comments (content, postId, authorId) VALUES (?, ?, ?)',
      [content, req.params.postId, req.user.id]
    );
    res.status(201).json({ message: 'Comment posted.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Fallback routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Server executing seamlessly on port ${PORT}`));
