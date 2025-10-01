const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(cors());
app.use(express.json());

// Health check
app.get('/health', (req, res) => {
  res.json({ success: true, message: 'EasyHomework API is running!' });
});

// Register user
app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password, children } = req.body;
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Generate teacher code
    const teacherCode = Math.random().toString(36).substr(2, 9).toUpperCase();
    
    // Save user to database
    const result = await pool.query(
      'INSERT INTO users (name, email, phone, password_hash, children, teacher_code) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, phone, children, teacher_code, subscription_status, trial_start_date',
      [name, email, phone, hashedPassword, JSON.stringify(children), teacherCode]
    );
    
    const user = result.rows[0];
    
    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        children: user.children,
        teacher_code: user.teacher_code,
        subscription_status: user.subscription_status,
        trial_start_date: user.trial_start_date
      },
      access_token: token
    });
  } catch (error) {
    if (error.code === '23505') {
      res.status(400).json({ success: false, message: 'Email already exists' });
    } else {
      res.status(400).json({ success: false, message: error.message });
    }
  }
});

// Login user
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }
    
    const user = result.rows[0];
    
    // Verify password
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }
    
    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        children: user.children,
        teacher_code: user.teacher_code,
        subscription_status: user.subscription_status,
        trial_start_date: user.trial_start_date
      },
      access_token: token
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Get tasks
app.get('/tasks', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM tasks WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.userId]
    );
    
    const tasks = result.rows.map(task => ({
      id: task.id,
      title: task.title,
      child_name: task.child_name,
      category: task.category,
      due_date: task.due_date,
      completed: task.completed,
      completed_at: task.completed_at,
      points: task.points,
      created_at: task.created_at
    }));
    
    res.json({
      success: true,
      tasks: tasks
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Create task
app.post('/tasks', authenticateToken, async (req, res) => {
  try {
    const { title, child_name, category, due_date } = req.body;
    
    const result = await pool.query(
      'INSERT INTO tasks (user_id, title, child_name, category, due_date) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.userId, title, child_name, category, due_date]
    );
    
    const task = result.rows[0];
    
    res.json({
      success: true,
      task: {
        id: task.id,
        title: task.title,
        child_name: task.child_name,
        category: task.category,
        due_date: task.due_date,
        completed: task.completed,
        points: task.points,
        created_at: task.created_at
      }
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Complete task
app.patch('/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { completed } = req.body;
    
    const result = await pool.query(
      'UPDATE tasks SET completed = $1, completed_at = $2 WHERE id = $3 AND user_id = $4 RETURNING *',
      [completed, completed ? new Date() : null, id, req.user.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Task not found' });
    }
    
    res.json({
      success: true,
      task: result.rows[0]
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Delete task
app.delete('/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(
      'DELETE FROM tasks WHERE id = $1 AND user_id = $2',
      [id, req.user.userId]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Task not found' });
    }
    
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Teacher login
app.post('/teacher/login', async (req, res) => {
  try {
    const { name, phone, teacher_code } = req.body;
    
    // Find parent with teacher code
    const result = await pool.query(
      'SELECT * FROM users WHERE teacher_code = $1',
      [teacher_code.toUpperCase()]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Invalid teacher code' });
    }
    
    const parent = result.rows[0];
    
    // Generate JWT for teacher
    const token = jwt.sign(
      { userId: parent.id, email: parent.email, userType: 'teacher', teacherName: name, teacherPhone: phone },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.json({
      success: true,
      user: {
        id: `teacher_${parent.id}`,
        name: name,
        phone: phone,
        teacher_code: teacher_code,
        parent_id: parent.id,
        parent_name: parent.name,
        parent_email: parent.email,
        children: parent.children
      },
      access_token: token
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

app.listen(PORT, () => {
  console.log(`EasyHomework API running on port ${PORT}`);
});
