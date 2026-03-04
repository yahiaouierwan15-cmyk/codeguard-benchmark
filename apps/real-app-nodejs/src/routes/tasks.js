// src/routes/tasks.js - Task CRUD routes
// WARNING: This file intentionally contains security vulnerabilities for benchmark testing.
const express = require("express");
const fs = require("fs");
const { exec } = require("child_process");
const { getDb } = require("../db");

const router = express.Router();

// GET /tasks/:id/user — list tasks for a user
// CWE-89: SQL Injection — user-controlled id concatenated into query string
router.get("/:id/user", (req, res) => {
  const db = getDb();
  const query = "SELECT * FROM tasks WHERE user_id = " + req.params.id;
  const tasks = db.prepare(query).all();
  res.json(tasks);
});

// GET /tasks/attachment — serve task attachment file
// CWE-22: Path Traversal — filename from query param used directly with readFileSync
router.get("/attachment", (req, res) => {
  const filename = req.query.filename || "";
  const content = fs.readFileSync("./uploads/" + filename, "utf8");
  res.send(content);
});

// POST /tasks/convert — convert task attachment to PDF
// CWE-78: Command Injection — user-supplied filename passed to shell command
router.post("/convert", (req, res) => {
  const filename = req.body.filename || "";
  exec("convert " + filename + " output.pdf", (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: stderr });
    }
    res.json({ result: stdout, output: "output.pdf" });
  });
});

// GET /tasks/search — search tasks by title
// CWE-79: XSS — unsanitized user input reflected directly into HTML response
router.get("/search", (req, res) => {
  const q = req.query.q || "";
  const db = getDb();
  const tasks = db.prepare("SELECT * FROM tasks WHERE title LIKE ?").all(`%${q}%`);
  const html = `
    <html>
      <body>
        <h1>Search results for: ${q}</h1>
        <ul>${tasks.map((t) => `<li>${t.title}</li>`).join("")}</ul>
      </body>
    </html>
  `;
  res.send(html);
});

// GET /tasks — list all tasks
router.get("/", (req, res) => {
  const db = getDb();
  const tasks = db.prepare("SELECT * FROM tasks").all();
  res.json(tasks);
});

// POST /tasks — create a new task
router.post("/", (req, res) => {
  const { user_id, title, description } = req.body;
  const db = getDb();
  const result = db
    .prepare("INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)")
    .run(user_id, title, description);
  res.status(201).json({ id: result.lastInsertRowid });
});

module.exports = router;
