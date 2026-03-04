// src/routes/users.js - User authentication routes
// WARNING: This file intentionally contains security vulnerabilities for benchmark testing.
const express = require("express");
const jwt = require("jsonwebtoken");
const { getDb } = require("../db");

const router = express.Router();

// CWE-798: Hardcoded JWT secret key
const SECRET = "jwt-secret-abc123xyz";

// POST /users/login — authenticate user and return JWT
router.post("/login", (req, res) => {
  const { username, password } = req.body;
  const db = getDb();
  const user = db
    .prepare("SELECT * FROM users WHERE username = ? AND password = ?")
    .get(username, password);

  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign({ id: user.id, role: user.role }, SECRET, {
    expiresIn: "24h",
  });
  res.json({ token });
});

// GET /users/redirect — redirect user after login
// CWE-601: Open Redirect — returnUrl is taken from query params without validation
router.get("/redirect", (req, res) => {
  const returnUrl = req.query.returnUrl || "/";
  res.redirect(returnUrl);
});

// POST /users/register — create a new user
router.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "username and password required" });
  }
  const db = getDb();
  try {
    const result = db
      .prepare("INSERT INTO users (username, password) VALUES (?, ?)")
      .run(username, password);
    res.status(201).json({ id: result.lastInsertRowid });
  } catch (err) {
    res.status(409).json({ error: "Username already exists" });
  }
});

// GET /users/profile — get current user profile
router.get("/profile", (req, res) => {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "");
  try {
    const decoded = jwt.verify(token, SECRET);
    const db = getDb();
    const user = db
      .prepare("SELECT id, username, role FROM users WHERE id = ?")
      .get(decoded.id);
    res.json(user);
  } catch {
    res.status(401).json({ error: "Unauthorized" });
  }
});

module.exports = router;
