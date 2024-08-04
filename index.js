const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors"); // CORS 패키지 추가
const bcrypt = require("bcrypt"); // bcrypt 패키지 추가
const db = require("./db");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT;
const saltRounds = Number(process.env.SALT_ROUNDS);

app.use(bodyParser.json());
app.use(cors()); // CORS 미들웨어 사용

// Create a message
app.post("/messages", async (req, res) => {
  const { name, password, message } = req.body;
  const author_ip = req.ip;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  try {
    const [result] = await db.execute(
      "INSERT INTO Messages (name, password, message, author_ip) VALUES (?, ?, ?, ?)",
      [name, hashedPassword, message, author_ip]
    );
    res.status(201).json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Read all messages
app.get("/messages", async (req, res) => {
  try {
    const [rows] = await db.execute(
      "SELECT * FROM Messages WHERE deleted_at IS NULL"
    );
    res.status(200).json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Read a single message by id
app.get("/messages/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await db.execute(
      "SELECT * FROM Messages WHERE id = ? AND deleted_at IS NULL",
      [id]
    );
    if (rows.length === 0) {
      res.status(404).json({ error: "Message not found" });
    } else {
      res.status(200).json(rows[0]);
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update a message
app.put("/messages/:id", async (req, res) => {
  const { id } = req.params;
  const { name, password, message } = req.body;
  const author_ip = req.ip;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  try {
    const [result] = await db.execute(
      "UPDATE Messages SET name = ?, message = ?, author_ip = ? WHERE id = ? AND password = ? AND deleted_at IS NULL",
      [name, message, author_ip, id, hashedPassword]
    );
    if (result.affectedRows === 0) {
      res.status(404).json({ error: "Message not found or already deleted" });
    } else {
      res.status(200).json({ message: "Message updated successfully" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a message (soft delete)
app.delete("/messages/:id", async (req, res) => {
  const { id } = req.params;
  const { password } = req.body;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  try {
    const [result] = await db.execute(
      "UPDATE Messages SET deleted_at = NOW() WHERE id = ? AND password = ? AND deleted_at IS NULL",
      [id, hashedPassword]
    );
    if (result.affectedRows === 0) {
      res.status(404).json({ error: "Message not found or already deleted" });
    } else {
      res.status(200).json({ message: "Message deleted successfully" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
