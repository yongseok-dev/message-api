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

// Helper function to convert Buffer to string safely
const convertBufferToString = (buffer) => {
  if (buffer && buffer.data) {
    return Buffer.from(buffer.data).toString("utf8");
  }
  return ""; // Return an empty string if buffer is undefined or empty
};

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
    const readableMessages = rows.map((row) => ({
      id: row.id,
      name: convertBufferToString(row.name),
      message: convertBufferToString(row.message),
      author_ip: convertBufferToString(row.author_ip),
      created_at: row.created_at,
    }));
    res.status(200).json(readableMessages);
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
