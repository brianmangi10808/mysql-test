require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// MySQL connection setup
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: 3306,
});

// Middleware to parse JSON requests
app.use(express.json());

// User Registration Route
app.post('/register', async (req, res) => {
  const { name, email, password, role, branch_id } = req.body;

  // Check if user already exists
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (results.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database
    const query = 'INSERT INTO users (name, email, password, role, branch_id) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [name, email, hashedPassword, role, branch_id], (error, result) => {
      if (error) {
        return res.status(500).json({ message: 'Error registering user', error });
      }
      res.status(201).json({ message: 'User registered successfully' });
    });
  });
});

// User Login Route
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Check if user exists
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (results.length === 0) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const user = results[0];

    // Compare hashed passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
