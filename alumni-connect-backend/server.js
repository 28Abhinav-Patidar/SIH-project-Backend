// server.js
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const PORT = 8000;

// PostgreSQL pool
const pool = new Pool({
  user: "postgres",          // your DB user
  host: "127.0.0.1",
  database: "alumni_db",     // your DB name
  password: "0000",          // your DB password
  port: 5432,
});

// Middleware
app.use(cors({ origin: "http://localhost:3000" })); // allow frontend
app.use(express.json());

// Secret key for JWT
const JWT_SECRET = "supersecretkey";

// ===== REGISTER =====
app.post("/auth/register", async (req, res) => {
  try {
    const {
      name,
      email,
      college,
      pass_out_year,
      passOutYear,
      password,
    } = req.body;

    const year = pass_out_year || passOutYear;

    if (!name || !email || !password || !year) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Check if email exists
    const existingUser = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const result = await pool.query(
      `INSERT INTO users (name, email, college, pass_out_year, password)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, college, pass_out_year`,
      [name, email, college, year, hashedPassword]
    );

    res.json({ message: "User registered successfully", user: result.rows[0] });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: err.message || "Registration failed" });
  }
});

// ===== LOGIN =====
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Missing email or password" });

    const userResult = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    const user = userResult.rows[0];
    if (!user) return res.status(400).json({ error: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Incorrect password" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "1h" });

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, college: user.college, pass_out_year: user.pass_out_year } });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: err.message || "Login failed" });
  }
});

// ===== TEST =====
app.get("/", (req, res) => {
  res.send("Alumni Connect Backend is running!");
});

// ===== START SERVER =====
app.listen(PORT, () => {
  console.log(`Server running at http://127.0.0.1:${PORT}`);
});
