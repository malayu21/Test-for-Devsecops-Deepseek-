/**
 * Vulnerable Calculator Backend (Node.js/Express)
 */

const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.urlencoded({ extended: true }));

// --- Dummy Hardcoded Secrets to Trigger Secret Detection ---
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";             // AWS access key ID pattern
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const TWILIO_API_KEY = "5ABCDEF1234567890ABCDEF1234567890";
const FACEBOOK_TOKEN = "FacebookXyzab1234567890abcdef123456";
const JWT_SECRET = "hardcoded-super-secret-key-for-jwt";

// Exporting secrets (unused but detectable):
module.exports = {
  AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY,
  TWILIO_API_KEY,
  FACEBOOK_TOKEN,
  JWT_SECRET
};

// --- Reflected XSS via Refused Output ---
app.get('/', (req, res) => {
  res.send('Welcome to the vulnerable calculator backend.');
});

// Unsafe redirect to trigger Open Redirect (dependency scanning)
app.get('/go', (req, res) => {
  const target = req.query.target;
  res.redirect(target);
});

// SQL Injection example
app.get('/user', (req, res) => {
  const id = req.query.id;
  const query = `SELECT * FROM users WHERE id = ${id}`;
  res.send(`Query executed: ${query}`);
});

// Directory traversal example
app.get('/file', (req, res) => {
  const name = req.query.name;
  const filepath = path.join(__dirname, 'docs', name);
  res.sendFile(filepath);
});

// Token generation using hardcoded JWT secret (CWE‑798)
app.get('/token', (req, res) => {
  const token = jwt.sign({ user: "test" }, JWT_SECRET, { expiresIn: '1h' });
  res.send({ token });
});

// Simulated CSRF form submission endpoint
app.post('/transfer', (req, res) => {
  res.send('Transfer executed');
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running at http://localhost:${port}`));
