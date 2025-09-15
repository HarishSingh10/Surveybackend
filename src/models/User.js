const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const { Pool } = require("pg");
const authMiddleware = require("../middleware/auth");

// ✅ Postgres pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

// ======================================================
// ✅ CREATE TABLES ON STARTUP
// ======================================================
const initTables = async () => {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            first_name VARCHAR(100) NOT NULL,
            last_name VARCHAR(100) NOT NULL,
            email VARCHAR(150) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            address VARCHAR(255),
            phone VARCHAR(15) UNIQUE,
            refresh_token TEXT,
            is_verified BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS businesses (
            id SERIAL PRIMARY KEY,
            user_id INT REFERENCES users(id) ON DELETE CASCADE,
            owner_name VARCHAR(100) NOT NULL,
            shop_name VARCHAR(150) NOT NULL,
            business_type VARCHAR(100),
            phone VARCHAR(15),
            address VARCHAR(255),
            latitude DECIMAL(10,8),
            longitude DECIMAL(11,8),
           
            created_at TIMESTAMP DEFAULT NOW()
        );
    `);


    await pool.query(`
        CREATE TABLE IF NOT EXISTS branches (
            id SERIAL PRIMARY KEY,
            business_id INT REFERENCES businesses(id) ON DELETE CASCADE,
            branch_name VARCHAR(150) NOT NULL,
            branch_address VARCHAR(255),
            phone VARCHAR(15),
            language_preference VARCHAR(50),
            latitude DECIMAL(10,8),
            longitude DECIMAL(11,8),
            upiid VARCHAR(100),
            created_at TIMESTAMP DEFAULT NOW(),
            qr_code VARCHAR(255)
        );
    `);
    await pool.query(`
    CREATE TABLE IF NOT EXISTS feedback_forms (
        id SERIAL PRIMARY KEY,
        branch_id INT REFERENCES branches(id) ON DELETE CASCADE,
        form_title VARCHAR(150) NOT NULL,
        questions JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
    );
`);
    await pool.query(`
    CREATE TABLE IF NOT EXISTS feedback_responses (
        id SERIAL PRIMARY KEY,
        form_id INT REFERENCES feedback_forms(id) ON DELETE CASCADE,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        answers JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
    );
`);


};

initTables(); // 👈 ensures tables exist before queries

// ======================================================
// ✅ Nodemailer transporter
// ======================================================
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

// Temporary OTP stores
const otpStore = {};
const passwordResetOTP = {};

// ----------------- Helper: Send OTP -----------------
const sendOTP = async (email, otp) => {
    await transporter.sendMail({
        from: `"Surveyy" <${process.env.SMTP_USER}>`,
        to: email,
        subject: "Your OTP Code",
        html: `<h3>Your OTP is: <b>${otp}</b></h3>`,
    });
};

// ----------------- Helper: Generate Tokens -----------------
const generateAccessToken = (user) =>
    jwt.sign({ id: user.id, email: user.email, phone: user.phone }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "15m",
    });

const generateRefreshToken = (user) =>
    jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "7d" });

// ======================================================
// 🔹 USER ROUTES (signup, login, reset password, etc.)
// ======================================================
// ✅ your existing signup, verify-otp, login, login-verify-otp,
// forgot-password, reset-password, refresh, logout go here
// (unchanged from your last version)

// ======================================================
// 🔹 BUSINESS ROUTES
// ======================================================
router.post("/businesses", authMiddleware, async (req, res) => {
    try {
        const { owner_name, shop_name, business_type, phone, address, latitude, longitude } = req.body;
        const result = await pool.query(
            `INSERT INTO businesses (user_id, owner_name, shop_name, business_type, phone, address, latitude, longitude)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
            [req.user.id, owner_name, shop_name, business_type, phone, address, latitude, longitude]
        );
        res.json({ success: true, business: result.rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.get("/businesses", authMiddleware, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM businesses WHERE user_id=$1", [req.user.id]);
        res.json({ success: true, businesses: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ======================================================
// 🔹 BRANCH ROUTES
// ======================================================
router.post("/branches", authMiddleware, async (req, res) => {
    try {
        const { business_id, branch_name, branch_address, phone, language_preference, latitude, longitude, upiid, qr_code } = req.body;
        const result = await pool.query(
            `INSERT INTO branches (business_id, branch_name, branch_address, phone, language_preference, latitude, longitude, upiid, qr_code)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
            [business_id, branch_name, branch_address, phone, language_preference, latitude, longitude, upiid, qr_code]
        );
        res.json({ success: true, branch: result.rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

router.get("/branches/:business_id", authMiddleware, async (req, res) => {
    try {
        const { business_id } = req.params;
        const result = await pool.query("SELECT * FROM branches WHERE business_id=$1", [business_id]);
        res.json({ success: true, branches: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

module.exports = router;
