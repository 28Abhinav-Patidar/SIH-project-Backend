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
  user: "postgres",          // your DB username
  host: "127.0.0.1",
  database: "alumni_db",     // your DB name
  password: "0000",          // your DB password
  port: 5432,
});

// Middleware
app.use(cors({ origin: "http://localhost:3000" })); // allow frontend
app.use(express.json());

// JWT secret
const JWT_SECRET = "supersecretkey";

// ===== CREATE TABLES IF NOT EXISTS =====
(async () => {
  try {
    await pool.query(
      `CREATE TABLE IF NOT EXISTS profile (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        college VARCHAR(100),
        pass_out_year INT,
        password VARCHAR(255)
      )`
    );
    console.log("✅ Profile table ready");

    await pool.query(
      `CREATE TABLE IF NOT EXISTS communities (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) UNIQUE NOT NULL,
        description TEXT
      )`
    );
    console.log("✅ Communities table ready");
  } catch (err) {
    console.error("❌ Error creating tables:", err);
  }
})();

// ===== REGISTER =====
app.post("/auth/register", async (req, res) => {
  try {
    const { name, email, college, pass_out_year, password } = req.body;
    if (!name || !email || !password || !pass_out_year) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const existingUser = await pool.query("SELECT * FROM profile WHERE email=$1", [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO profile (name, email, college, pass_out_year, password)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, email, college, pass_out_year`,
      [name, email, college, pass_out_year, hashedPassword]
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

    const userResult = await pool.query("SELECT * FROM profile WHERE email=$1", [email]);
    const user = userResult.rows[0];
    if (!user) return res.status(400).json({ error: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Incorrect password" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "1h" });

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        college: user.college,
        pass_out_year: user.pass_out_year,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: err.message || "Login failed" });
  }
});

// ===== FETCH PROFILE =====
app.get("/profile/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query("SELECT id, name, email, college, pass_out_year FROM profile WHERE id=$1", [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Profile not found" });

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Profile fetch error:", err);
    res.status(500).json({ error: err.message || "Failed to fetch profile" });
  }
});

// ===== COMMUNITIES =====
// Get all communities
app.get("/communities", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM communities ORDER BY id ASC");
    res.json(result.rows);
  } catch (err) {
    console.error("Fetch communities error:", err);
    res.status(500).json({ error: err.message || "Failed to fetch communities" });
  }
});

// Create a new community
app.post("/communities", async (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: "Community name is required" });

    const existing = await pool.query("SELECT * FROM communities WHERE name=$1", [name]);
    if (existing.rows.length > 0) return res.status(400).json({ error: "Community already exists" });

    const result = await pool.query(
      "INSERT INTO communities (name, description) VALUES ($1, $2) RETURNING id, name, description",
      [name, description || ""]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Create community error:", err);
    res.status(500).json({ error: err.message || "Failed to create community" });
  }
});

// ===== TEST ROUTE =====
app.get("/", (req, res) => {
  res.send("Alumni Connect Backend is running!");
});

// ===== START SERVER =====
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://127.0.0.1:${PORT}`);
});
