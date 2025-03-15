const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
require('dotenv').config();

const router = express.Router();

// ✅ Health Check Route (Add this before other routes)
router.get('/health-check', (req, res) => {
    res.json({ message: "Auth API is working" });
});

// ✅ Signup Route with Improved Error Handling
router.post('/signup', [
    body('name').notEmpty().withMessage("Full Name is required").isLength({ min: 3 }).withMessage("Full Name must be at least 3 characters long"),
    body('identifier').notEmpty().withMessage("Email or Mobile is required"),
    body('password').isLength({ min: 6 }).withMessage("Password must be at least 6 characters long")
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, identifier, password } = req.body;

    let email = null;
    let mobile = null;
    if (identifier.includes("@")) {
        email = identifier;
    } else if (/^\d{10}$/.test(identifier)) { // Improved validation
        mobile = identifier;
    } else {
        return res.status(400).json({ error: "Invalid email or mobile number format" });
    }

    try {
        const query = {};
        if (email) query.email = email;
        if (mobile) query.mobile = mobile;

        const existingUser = await User.findOne(query);
        if (existingUser) {
            return res.status(400).json({ error: "An account with this email or mobile already exists. Please log in or use a different email/mobile." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });

        // ✅ Only add `mobile` if it's provided
        if (mobile) {
            user.mobile = mobile;
        }

        await user.save();

        res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        console.error("Signup Error:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

// ✅ Login Route
router.post('/login', [
    body('identifier').notEmpty().withMessage("Email or Mobile is required"),
    body('password').notEmpty().withMessage("Password is required")
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { identifier, password } = req.body;

    try {
        const user = await User.findOne({ $or: [{ email: identifier }, { mobile: identifier }] });
        if (!user) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        console.log("Entered Password:", password);
        console.log("Stored Hash:", user.password);
        console.log("Password Match:", isMatch); // ✅ Should be true

        if (!isMatch) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const JWT_SECRET = process.env.JWT_SECRET || "default_secret_key"; // ✅ Fallback in case JWT_SECRET is missing
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

        res.cookie('authToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production' ? true : false, // ✅ Secure only in production
            sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax' // Fix for localhost
        });
        res.json({ message: "Login successful" });
    } catch (err) {
        console.error("Login Error:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

// ✅ Logout Route
router.post('/logout', (req, res) => {
    res.clearCookie('authToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'None'  // 🔥 Important for cross-origin requests
    }); // ✅ Clears authentication token
    res.json({ message: "Logout successful" });
});

// ✅ Forgot Password Route
router.post('/forgot-password', async (req, res) => {
    const { identifier } = req.body;

    if (!identifier) {
        return res.status(400).json({ error: "Email or Mobile is required" });
    }

    try {
        const user = await User.findOne({ $or: [{ email: identifier }, { mobile: identifier }] });

        if (!user) {
            return res.status(400).json({ error: "User not found" });
        }

        // Generate a random OTP
        const otp = (Math.floor(100000 + Math.random() * 900000)).toString(); // Ensuring OTP is stored as string
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes

        // ✅ Update OTP in MongoDB
        await User.updateOne({ _id: user._id }, { $set: { otp: otp, otpExpires: otpExpires } });

        console.log(`✅ OTP Sent: ${otp} for ${identifier}`);

        res.json({ message: "OTP sent successfully" });
    } catch (err) {
        console.error("Forgot Password Error:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

// ✅ Reset Password Route
router.post('/reset-password', async (req, res) => {
    const { identifier, otp, newPassword } = req.body;

    if (!identifier || !otp || !newPassword) {
        return res.status(400).json({ error: "All fields are required" });
    }

    try {
        const user = await User.findOne({ $or: [{ email: identifier }, { mobile: identifier }] });

        if (!user) {
            return res.status(400).json({ error: "User not found" });
        }

        if (!user.otp || String(user.otp) !== otp.toString()) { // Ensure OTP is checked as a string
            return res.status(400).json({ error: "Invalid OTP" });
        }

        // ✅ Fix: Ensure OTP Expiry is checked properly
        if (new Date(user.otpExpires).getTime() < Date.now()) {
            return res.status(400).json({ error: "OTP expired" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // ✅ Clear OTP after password reset
        await User.updateOne(
            { _id: user._id },
            { $set: { password: hashedPassword, otp: null, otpExpires: null } }
        );

        res.json({ message: "Password reset successfully" });
    } catch (err) {
        console.error("Reset Password Error:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

// ✅ Fetch User Details Route (Requires Authentication)
router.get('/user', async (req, res) => {
    console.log("🔍 Cookies Received:", req.cookies); // 🔥 Debugging

        const token = req.cookies.authToken; // Get token from cookies
        if (!token) {
            return res.status(401).json({ error: "Unauthorized: No token provided" });
      }

    const JWT_SECRET = process.env.JWT_SECRET || "default_secret_key";
    try {
        const decoded = jwt.verify(token, JWT_SECRET); // Verify token

        const user = await User.findById(decoded.userId).select('-password'); // Exclude password
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json(user); // ✅ Send user details
    } catch (err) {
        console.error("User Fetch Error:", err);
        res.status(401).json({ error: "Invalid or expired token" });
    }
});

module.exports = router;