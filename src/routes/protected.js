const express = require("express");
const router = express.Router();
const { Pool } = require("pg");
const authMiddleware = require("../middleware/auth");

// ✅ Postgres pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

// ---------------- GET USER PROFILE ----------------
router.get("/profile", authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, first_name, last_name, email, address, phone, profile_image, has_business, created_at, updated_at
             FROM users
             WHERE id=$1`,
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const user = result.rows[0];
        res.json({ user });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// ---------------- UPDATE USER PROFILE ----------------
router.put("/update-profile", authMiddleware, async (req, res) => {
    try {
        const updates = { ...req.body };

        // Restrict sensitive updates
        delete updates.role;
        delete updates.refresh_token;
        delete updates.password;
        delete updates.is_verified;

        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ message: "No valid fields to update" });
        }

        // Build dynamic SET query
        const setQuery = Object.keys(updates)
            .map((key, index) => `"${key}"=$${index + 1}`)
            .join(", ");
        const values = Object.values(updates);

        const result = await pool.query(
            `UPDATE users
             SET ${setQuery}, updated_at=NOW()
             WHERE id=$${values.length + 1}
             RETURNING id, first_name, last_name, email, address, phone, profile_image, has_business, created_at, updated_at`,
            [...values, req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({
            message: "Profile updated successfully",
            user: result.rows[0],
        });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

module.exports = router;
