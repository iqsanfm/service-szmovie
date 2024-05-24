require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./db"); // Import connection
const { check, validationResult } = require("express-validator");

const app = express();
app.use(bodyParser.json());

const secret = process.env.SECRET_KEY;

// Middleware untuk autentikasi
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.sendStatus(403);

  jwt.verify(token, secret, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Route untuk pendaftaran
app.post(
  "/register",
  [
    check("username")
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters long"),
    check("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters long"),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    const query = "INSERT INTO users (username, password) VALUES (?, ?)";
    db.query(query, [username, hashedPassword], (err, results) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Error registering user", error: err });
      }
      res.status(201).json({ message: "User registered successfully" });
    });
  }
);

// Route untuk login
app.post(
  "/login",
  [
    check("username").not().isEmpty().withMessage("Username is required"),
    check("password").not().isEmpty().withMessage("Password is required"),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    const query = "SELECT * FROM users WHERE username = ?";
    db.query(query, [username], (err, results) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Error logging in", error: err });
      }

      if (results.length === 0) {
        return res.status(400).json({ message: "User not found" });
      }

      const user = results[0];
      const passwordIsValid = bcrypt.compareSync(password, user.password);
      if (!passwordIsValid) {
        return res.status(401).json({ message: "Invalid password" });
      }

      const token = jwt.sign({ username: user.username }, secret, {
        expiresIn: "1h",
      });
      res.status(200).json({ message: "Login successful", token });
    });
  }
);

// Protected route
app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "This is a protected route", user: req.user });
});

// Jalankan server di port 3000
app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
