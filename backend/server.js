const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser'); // ✅ Correct way
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');  // ✅ Import cookie-parser
const authRoutes = require('./routes/auth'); 
require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');

const app = express(); // ✅ Initialize Express first

// ✅ Use cookie-parser BEFORE routes
app.use(cookieParser());  // 🔥 Fix for req.cookies being undefined



// ✅ Fix CORS: Explicitly allow frontend domain
app.use(cors({
    origin: "http://localhost:3000", // ✅ Matches frontend URL
    credentials: true, // ✅ Allows authentication cookies
    allowedHeaders: ["Content-Type", "Authorization"], // ✅ Ensure necessary headers are allowed
    methods: ["GET", "POST", "PUT", "DELETE"] // ✅ Explicitly allows HTTP methods
}));

app.use(bodyParser.json()); // ✅ Ensures proper request body parsing before routes

// ✅ MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err));

// ✅ Authentication Routes
app.use('/api/auth', authRoutes); // ✅ Register auth routes under /api/auth

// ✅ Webhook Signature Verification Middleware
function verifyGitHubSignature(req, res, next) {
    const signature = req.headers['x-hub-signature-256'];
    const secret = process.env.GITHUB_SECRET || "your-secret-key"; // Use a real secret key
    const payload = JSON.stringify(req.body);
    const hmac = crypto.createHmac('sha256', secret).update(payload).digest('hex');
    const expectedSignature = `sha256=${hmac}`;

    if (signature !== expectedSignature) {
        console.warn("⚠️ Webhook signature verification failed!");
        return res.status(403).send("Forbidden: Invalid signature");
    }

    next(); // Signature is valid, proceed
}

// ✅ Webhook Route
app.post('/webhook', verifyGitHubSignature, (req, res) => {
    console.log('✅ Valid Webhook Received:', req.body);

    // Save webhook logs (optional)
    fs.appendFileSync('webhook_log.json', JSON.stringify(req.body, null, 2) + '\n');

    res.status(200).send('Webhook received successfully');
});

console.log("✅ Webhook route added at /webhook");

// ✅ Default Route
app.get("/", (req, res) => res.send("Backend is running!"));

app.get('/test-db', async (req, res) => {
    try {
        const collections = await mongoose.connection.db.listCollections().toArray();
        res.status(200).json({ success: true, collections });
    } catch (error) {
        console.error('❌ Database Query Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ✅ Start Server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));