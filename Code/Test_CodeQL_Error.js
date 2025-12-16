
/**
 * sample-vulnerable.js
 *
 * This file intentionally contains insecure patterns that CodeQL is designed to detect.
 * DO NOT use in production. It is here purely to trigger code scanning alerts.
 */

const express = require('express');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql'); // If not installed, comment out SQL parts or install mysql

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- 1) Command Injection via child_process.exec with tainted input ---
app.get('/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1';
  // ❌ Vulnerable: user-controlled data concatenated into shell command
  cp.exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) return res.status(500).send('Ping failed');
    res.send(stdout);
  });
});

// --- 2) XSS via unsanitized HTML injection ---
app.get('/greet', (req, res) => {
  const name = req.query.name || 'world';
  // ❌ Vulnerable: unescaped user input in HTML
  res.send(`<html><body><h1>Hello, ${name}</h1></body></html>`);
});

// --- 3) Unsafe eval (Remote Code Execution) ---
app.post('/eval', (req, res) => {
  const code = req.body.code;
  // ❌ Vulnerable: executing untrusted code
  try {
    const result = eval(code); // CodeQL flags usage of eval with tainted data
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- 4) SQL Injection via string-concatenated query ---
app.get('/user', (req, res) => {
  const id = req.query.id || '1';
  // ❌ Vulnerable: SQL query built by concatenation (no parameterization)
  const query = `SELECT * FROM users WHERE id = ${id}`;
  // Simulated DB call (commented if mysql isn’t installed)
  try {
    const connection = mysql.createConnection({ host: 'localhost', user: 'root', password: 'root', database: 'test' });
    connection.query(query, (err, results) => {
      if (err) return res.status(500).send('DB error');
      res.json(results);
      connection.end();
    });
  } catch {
    res.status(200).send(`Would run: ${query}`);
  }
});

// --- 5) Path Traversal writing to user-specified file path ---
app.post('/save', (req, res) => {
  const filename = req.body.filename || 'note.txt';
  const content = req.body.content || 'hello';
  // ❌ Vulnerable: attacker can use '../' to escape intended directory
  const filePath = path.join(__dirname, 'uploads', filename);
  fs.writeFile(filePath, content, (err) => {
    if (err) return res.status(500).send('Write failed');
    res.send(`Saved to ${filePath}`);
  });
});

// --- 6) Prototype Pollution via merge of JSON body into global object ---
let defaults = { theme: 'light', safe: true };
app.post('/config', (req, res) => {
  const userConfig = req.body || {};
  // ❌ Vulnerable: naive merge allows setting __proto__ and polluting Object.prototype
  Object.assign(defaults, userConfig);
  res.json({ ok: true, defaults });
});

// --- 7) Insecure cryptography (weak hash + predictable key) ---
app.get('/hash', (req, res) => {
  const data = req.query.data || 'secret';
  // ❌ Vulnerable: MD5 is insecure
  const h = crypto.createHash('md5').update(data).digest('hex');

  // ❌ Vulnerable: predictable encryption key and ECB mode-like misuse
  const key = Buffer.from('00000000000000000000000000000000', 'hex'); // hardcoded weak key
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null); // ECB has no IV and is insecure
  let enc = cipher.update(data, 'utf8', 'hex');
  enc += cipher.final('hex');

  res.json({ md5: h, enc });
});

// --- 8) Regular expression DoS (ReDoS) with user input ---
app.get('/search', (req, res) => {
  const q = req.query.q || 'a';
  // ❌ Vulnerable: catastrophic backtracking on patterns like (a+)+$
  const regex = new RegExp(q);
  // Simulate matching on a large input
  const big = 'a'.repeat(50000);
  const matched = regex.test(big);
  res.json({ matched });
});

// --- 9) Hardcoded credentials / secrets in source ---
const HARDCODED_API_KEY = 'sk_test_1234567890abcdef'; // ❌ Vulnerable: secret in source
app.get('/apikey', (_req, res) => {
  res.send(`Using API key: ${HARDCODED_API_KEY}`);
});

// --- 10) Insecure deserialization (JSON.parse on untrusted input with prototype pollution) ---
app.post('/parse', (req, res) => {
  const payload = req.body.payload;
  try {
    // ❌ Vulnerable: blindly parsing attacker-controlled JSON
    const obj = JSON.parse(payload);
    res.json({ parsed: obj });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable app listening on http://localhost:${PORT}`);

