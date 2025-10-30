// server.js
import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());

// ======================
// Sample Hardcoded Users
// ======================
const users = [
  { id: 1, username: "adminUser", password: "admin123", role: "Admin" },
  { id: 2, username: "modUser", password: "mod123", role: "Moderator" },
  { id: 3, username: "normalUser", password: "user123", role: "User" },
];

// ======================
// LOGIN ROUTE
// ======================
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ message: "Invalid username or password" });
  }

  // Create token payload with role
  const payload = { id: user.id, username: user.username, role: user.role };

  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.json({ message: "Login successful", token });
});

// ======================
// VERIFY TOKEN MIDDLEWARE
// ======================
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token)
    return res.status(403).json({ message: "Access denied: No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err)
      return res.status(401).json({ message: "Invalid or expired token" });
    req.user = decoded;
    next();
  });
}

// ======================
// ROLE-BASED AUTHORIZATION MIDDLEWARE
// ======================
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        message: `Access denied: Requires role(s) [${allowedRoles.join(", ")}]`,
      });
    }
    next();
  };
}

// ======================
// PROTECTED ROUTES
// ======================

// Admin-only route
app.get("/admin/dashboard", verifyToken, authorizeRoles("Admin"), (req, res) => {
  res.json({
    message: "Welcome to the Admin Dashboard!",
    user: req.user,
  });
});

// Moderator-only route
app.get(
  "/moderator/manage",
  verifyToken,
  authorizeRoles("Moderator", "Admin"),
  (req, res) => {
    res.json({
      message: "Moderator Management Access Granted!",
      user: req.user,
    });
  }
);

// General User route
app.get(
  "/user/profile",
  verifyToken,
  authorizeRoles("User", "Moderator", "Admin"),
  (req, res) => {
    res.json({
      message: "Welcome to your user profile!",
      user: req.user,
    });
  }
);

// ======================
// SERVER START
// ======================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
