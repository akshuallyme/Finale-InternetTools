const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-jwt-key-change-in-production';
const uploadsDir = path.join(__dirname, 'uploads');
const dbPath = path.join(__dirname, 'database.db');


// Create uploads directory
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Database setup with better-sqlite3
const db = new Database(dbPath);
console.log('Connected to SQLite database');

// Create tables (synchronous with better-sqlite3)
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

db.exec(`CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  filename TEXT NOT NULL,
  original_name TEXT NOT NULL,
  file_type TEXT NOT NULL,
  file_size INTEGER NOT NULL,
  privacy TEXT NOT NULL CHECK(privacy IN ('public', 'private')),
  share_token TEXT UNIQUE,
  upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);

// Multer configuration
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../frontend')));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /pdf|mp4/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = file.mimetype === 'application/pdf' || file.mimetype === 'video/mp4';

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF and MP4 files are allowed.'));
    }
  }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Register
app.post('/api/register', async (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password) {
    return res.status(400).json({ error: 'Email, username, and password are required' });
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const stmt = db.prepare('INSERT INTO users (email, username, password) VALUES (?, ?, ?)');
    
    try {
      const info = stmt.run(email, username, hashedPassword);
      res.json({ message: 'Registration successful', userId: info.lastInsertRowid });
    } catch (err) {
      if (err.message.includes('UNIQUE constraint failed: users.email')) {
        return res.status(400).json({ error: 'Email already exists. Please use a different email.' });
      } else if (err.message.includes('UNIQUE constraint failed: users.username')) {
        return res.status(400).json({ error: 'Username already exists. Please choose a different username.' });
      }
      return res.status(500).json({ error: 'Registration failed' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password, username } = req.body;

  // Accept either email or username for login
  const loginIdentifier = email || username;

  if (!loginIdentifier || !password) {
    return res.status(400).json({ error: 'Email/Username and password are required' });
  }

  try {
    // Check if user exists by email or username
    const stmt = db.prepare('SELECT * FROM users WHERE email = ? OR username = ?');
    const user = stmt.get(loginIdentifier, loginIdentifier);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify token
app.get('/api/verify-token', authenticateToken, (req, res) => {
  res.json({
    valid: true,
    user: {
      id: req.user.id,
      username: req.user.username,
      email: req.user.email
    }
  });
});

// Upload file
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const { privacy } = req.body;

  if (!privacy || (privacy !== 'public' && privacy !== 'private')) {
    // Delete uploaded file if privacy is invalid
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'Privacy setting must be either "public" or "private"' });
  }

  const { filename, originalname, mimetype, size } = req.file;
  const shareToken = privacy === 'private' ? crypto.randomBytes(32).toString('hex') : null;

  try {
    const stmt = db.prepare(
      'INSERT INTO files (user_id, filename, original_name, file_type, file_size, privacy, share_token) VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    
    const info = stmt.run(req.user.id, filename, originalname, mimetype, size, privacy, shareToken);
    
    res.json({
      message: 'File uploaded successfully',
      fileId: info.lastInsertRowid,
      filename: originalname,
      privacy: privacy,
      shareLink: shareToken ? `/share/${shareToken}` : null
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save file metadata' });
  }
});

// Get public files (for Downloads page)
app.get('/api/public-files', (req, res) => {
  try {
    const stmt = db.prepare(`
      SELECT f.id, f.original_name, f.file_type, f.file_size, f.upload_date, f.filename, u.username
      FROM files f
      JOIN users u ON f.user_id = u.id
      WHERE f.privacy = 'public'
      ORDER BY f.upload_date DESC
    `);
    
    const files = stmt.all();
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch public files' });
  }
});

// Get user's own files (for My Files dashboard)
app.get('/api/my-files', authenticateToken, (req, res) => {
  try {
    const stmt = db.prepare(`
      SELECT id, original_name, file_type, file_size, upload_date, filename, privacy, share_token
      FROM files
      WHERE user_id = ?
      ORDER BY upload_date DESC
    `);
    
    const files = stmt.all(req.user.id);
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch files' });
  }
});

// Download file by filename (for public files and own files)
app.get('/api/download/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(uploadsDir, filename);

  try {
    // Check if file exists in database
    const stmt = db.prepare('SELECT * FROM files WHERE filename = ?');
    const file = stmt.get(filename);

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Check if file exists on disk
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found on server' });
    }

    res.download(filePath, file.original_name);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Access file via share token (for private files)
app.get('/share/:token', (req, res) => {
  const token = req.params.token;

  try {
    const stmt = db.prepare('SELECT * FROM files WHERE share_token = ?');
    const file = stmt.get(token);

    if (!file) {
      return res.status(404).send('<h1>File not found or link is invalid</h1>');
    }

    const filePath = path.join(uploadsDir, file.filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).send('<h1>File not found on server</h1>');
    }

    res.download(filePath, file.original_name);
  } catch (err) {
    res.status(500).send('<h1>Server error</h1>');
  }
});

// Delete file (only own files)
app.delete('/api/files/:id', authenticateToken, (req, res) => {
  const fileId = req.params.id;

  try {
    const getStmt = db.prepare('SELECT * FROM files WHERE id = ? AND user_id = ?');
    const file = getStmt.get(fileId, req.user.id);

    if (!file) {
      return res.status(403).json({ error: 'Unauthorized: You can only delete your own files' });
    }

    // Delete from filesystem
    const filePath = path.join(uploadsDir, file.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Delete from database
    const deleteStmt = db.prepare('DELETE FROM files WHERE id = ?');
    deleteStmt.run(fileId);

    res.json({ message: 'File deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down gracefully...');
  db.close();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\nShutting down gracefully...');
  db.close();
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Database: ${dbPath}`);
  console.log(`Uploads directory: ${uploadsDir}`);
});