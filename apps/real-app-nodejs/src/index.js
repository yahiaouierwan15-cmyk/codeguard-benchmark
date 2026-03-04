// src/index.js - Task Manager API entry point
const express = require("express");
const tasksRouter = require("./routes/tasks");
const usersRouter = require("./routes/users");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "task-manager-api" });
});

app.use("/tasks", tasksRouter);
app.use("/users", usersRouter);

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`Task Manager API running on port ${PORT}`);
});

module.exports = app;
