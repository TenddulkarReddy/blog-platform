const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_change_this_in_production';

// Middleware Setup
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Connection Pool using explicit properties to prevent parsing bugs
const db = mysql.createPool({
  host: 'mysql-2fef98f0-tenddulkarreddy-361b.j.aivencloud.com',
  user: 'avnadmin',
  password: 'AVNS_GIS5VHGHINorhZCkRre',
  database: 'defaultdb',
  port: 15403,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: {
    rejectUnauthorized: false
  }
});

// Database Initialization Helper
async function initDB() {
  try {
    // Users Table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Posts Table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        authorId INT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (authorId) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Comments Table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS comments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        postId INT NOT NULL,
        content TEXT NOT NULL,
        authorId INT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (postId) REFERENCES posts(id) ON DELETE CASCADE,
        FOREIGN KEY (authorId) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    console.log("All MySQL Database tables initialized successfully.");
  } catch (error) {
    console.error("Critical Error initializing database tables:", error);
  }
}

// Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access token required.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
}

// --- API ROUTES ---

// Auth: Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password required.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);

    res.status(201).json({ message: 'User registered successfully.' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'Username already taken.' });
    }
    res.status(500).json({ error: error.message });
  }
});

// Auth: Login (Sends complete authorization credentials back to user dashboard)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const [users] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);

    if (users.length === 0) return res.status(400).json({ message: 'Invalid credentials.' });

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: 'Invalid credentials.' });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    
    // Explicitly returning userId helps your index frontend match authorId conditions
    res.json({ 
      token, 
      username: user.username,
      userId: user.id 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Posts: Get All Posts
app.get('/api/posts', async (req, res) => {
  try {
    const [posts] = await db.execute(`
      SELECT posts.*, users.username AS author 
      FROM posts 
      JOIN users ON posts.authorId = users.id 
      ORDER BY posts.createdAt DESC
    `);
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Posts: Create Post
app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!title || !content) return res.status(400).json({ message: 'Title and content required.' });

    await db.execute('INSERT INTO posts (title, content, authorId) VALUES (?, ?, ?)', [title, content, req.user.id]);
    res.status(201).json({ message: 'Post created successfully.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Posts: Delete Post
app.delete('/api/posts/:postId', authenticateToken, async (req, res) => {
  try {
    const { postId } = req.params;
    const [post] = await db.execute('SELECT authorId FROM posts WHERE id = ?', [postId]);
    
    if (post.length === 0) return res.status(404).json({ message: 'Post not found.' });
    if (post[0].authorId !== req.user.id) return res.status(403).json({ message: 'Unauthorized action.' });

    await db.execute('DELETE FROM posts WHERE id = ?', [postId]);
    res.json({ message: 'Post deleted successfully.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Comments: Get Comments for a Post
app.get('/api/posts/:postId/comments', async (req, res) => {
  try {
    const { postId } = req.params;
    const [comments] = await db.execute(`
      SELECT comments.*, users.username AS author 
      FROM comments 
      JOIN users ON comments.authorId = users.id 
      WHERE comments.postId = ? 
      ORDER BY comments.createdAt ASC
    `, [postId]);
    res.json(comments);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Comments: Add Comment
app.post('/api/posts/:postId/comments', authenticateToken, async (req, res) => {
  try {
    const { postId } = req.params;
    const { content } = req.body;
    if (!content) return res.status(400).json({ message: 'Comment content required.' });

    await db.execute('INSERT INTO comments (postId, content, authorId) VALUES (?, ?, ?)', [postId, content, req.user.id]);
    res.status(201).json({ message: 'Comment added successfully.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Comments: Delete Comment
app.delete('/api/comments/:commentId', authenticateToken, async (req, res) => {
  try {
    const { commentId } = req.params;
    const [comment] = await db.execute('SELECT authorId FROM comments WHERE id = ?', [commentId]);

    if (comment.length === 0) return res.status(404).json({ message: 'Comment not found.' });
    if (comment[0].authorId !== req.user.id) return res.status(403).json({ message: 'Unauthorized action.' });

    await db.execute('DELETE FROM comments WHERE id = ?', [commentId]);
    res.json({ message: 'Comment deleted successfully.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Serve Frontend SPA routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Boot Server sequence
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  await initDB();
});
