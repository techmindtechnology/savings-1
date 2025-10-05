require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cron = require("node-cron");
const axios = require("axios");

const app = express();
app.use(cors());
app.use(express.json());

// ✅ MySQL connection
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

db.getConnection((err, connection) => {
  if (err) throw err;
  console.log("✅ Connected to MySQL database!");
  connection.release();
});

// ✅ Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// ✅ Home route
app.get("/", (req, res) => {
  res.send("Savings system backend is running successfully on Render!");
});

// ✅ Login
app.post("/login", (req, res) => {
  const { phone_number, password } = req.body;
  if (!phone_number || !password)
    return res.status(400).json({ message: "Phone and password required" });

  db.query(
    "SELECT * FROM users WHERE phone_number = ?",
    [phone_number],
    async (err, results) => {
      if (err)
        return res.status(500).json({ message: "Database error", error: err });
      if (results.length === 0)
        return res.status(404).json({ message: "User not found" });

      const user = results[0];
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) return res.status(401).json({ message: "Invalid password" });

      const token = jwt.sign(
        { user_id: user.user_id },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
      );
      res.json({ message: "Login successful", token });
    }
  );
});

// ✅ Deposit (Paystack)
app.post("/deposit", authenticateToken, async (req, res) => {
  const { amount } = req.body;
  const user_id = req.user.user_id;

  if (!amount)
    return res.status(400).json({ message: "Amount is required" });

  db.query(
    "SELECT email, phone_number FROM users WHERE user_id = ?",
    [user_id],
    async (err, results) => {
      if (err)
        return res.status(500).json({ message: "Database error", error: err });
      if (results.length === 0)
        return res.status(404).json({ message: "User not found" });

      const email = results[0].email || `${results[0].phone_number}@example.com`;

      try {
        const response = await axios.post(
          "https://api.paystack.co/transaction/initialize",
          {
            amount: parseFloat(amount) * 100, // convert to kobo
            email,
            callback_url: `${process.env.RENDER_URL}/callback`, // Paystack callback to Render
          },
          {
            headers: {
              Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
              "Content-Type": "application/json",
            },
          }
        );

        res.json({
          authorization_url: response.data.data.authorization_url,
        });
      } catch (error) {
        console.error(
          "Paystack error:",
          error.response ? error.response.data : error.message
        );
        res.status(500).json({
          message: "Payment initialization failed",
          error: error.response ? error.response.data : error.message,
        });
      }
    }
  );
});

// ✅ Paystack callback
app.get("/callback", async (req, res) => {
  const reference = req.query.reference;
  if (!reference) return res.status(400).send("No reference provided");

  try {
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      }
    );

    const data = response.data.data;

    if (data.status === "success") {
      const email = data.customer.email;
      const amount = data.amount / 100;

      const phone_number = email.split("@")[0];
      db.query(
        "SELECT u.user_id, a.account_id, a.balance FROM users u JOIN accounts a ON u.user_id = a.user_id WHERE u.phone_number = ?",
        [phone_number],
        (err, results) => {
          if (err) return res.status(500).send("Database error");
          if (results.length === 0) return res.status(404).send("User not found");

          const account = results[0];
          const newBalance = parseFloat(account.balance) + parseFloat(amount);

          db.query(
            "UPDATE accounts SET balance = ? WHERE account_id = ?",
            [newBalance, account.account_id],
            (err2) => {
              if (err2) return res.status(500).send("Failed to update balance");

              db.query(
                "INSERT INTO transactions (account_id, type, amount, status) VALUES (?, ?, ?, ?)",
                [account.account_id, "deposit", amount, "completed"]
              );

              res.send("Payment successful! You can now close this tab.");
            }
          );
        }
      );
    } else {
      res.send("Payment not successful");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Error verifying payment");
  }
});

// ✅ Cron Job: daily update
cron.schedule("0 0 * * *", () => {
  console.log("Running daily balance update...");
  db.query("SELECT * FROM accounts", (err, accounts) => {
    if (err) return console.error("Error fetching accounts:", err);
    accounts.forEach((acc) => {
      const newBalance = parseFloat(acc.balance) + parseFloat(acc.daily_deduction || 0);
      db.query("UPDATE accounts SET balance = ? WHERE account_id = ?", [
        newBalance,
        acc.account_id,
      ]);
    });
  });
});

// ✅ Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
