const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
require('dotenv').config();

const authRoutes = require('./routes/auth');

const app = express();

// ✅ Use cookie-parser BEFORE routes
app.use(cookieParser());

// ✅ Preserve Raw Request Body for Webhook Signature Verification
app.use(bodyParser.json({
    verify: (req, res, buf) => {
        req.rawBody = buf; // Preserve raw request body
    }
}));

// ✅ Fix CORS
app.use(cors({
    origin: ["http://localhost:3000", "https://your-frontend-domain.com"],  // Allow both local & deployed frontend
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
    methods: ["GET", "POST", "PUT", "DELETE"]
}));

// ✅ MongoDB Connection with Error Handling
mongoose.connect(process.env.MONGO_URI || "mongodb://localhost:27017/peetham_web", {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err));

mongoose.connection.on('error', (err) => {
    console.error('❌ MongoDB Connection Error:', err);
});
mongoose.connection.on('disconnected', () => {
    console.warn('⚠️ MongoDB Disconnected! Retrying...');
});

// ✅ Authentication Routes
app.use('/api/auth', authRoutes);

// ✅ Webhook Signature Verification Middleware
function verifyGitHubSignature(req, res, next) {
    const signature = req.headers['x-hub-signature-256'];
    if (!signature) {
        console.warn("⚠️ Missing signature");
        return res.status(400).send("Bad Request: Missing signature");
    }

    const secret = process.env.GITHUB_SECRET || "your-secret-key";
    const hmac = crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex');
    const expectedSignature = `sha256=${hmac}`;

    // Debugging: Log received and expected signatures
    console.log(`🔍 Received Signature: ${signature}`);
    console.log(`🔍 Expected Signature: ${expectedSignature}`);

    // Securely compare signatures
    const receivedSignatureBuffer = Buffer.from(signature, 'utf8');
    const expectedSignatureBuffer = Buffer.from(expectedSignature, 'utf8');

    if (receivedSignatureBuffer.length !== expectedSignatureBuffer.length ||
        !crypto.timingSafeEqual(receivedSignatureBuffer, expectedSignatureBuffer)) {
        console.warn("⚠️ Webhook signature verification failed!");
        return res.status(403).send("Forbidden: Invalid signature");
    }

    next(); // Signature is valid, proceed
}

// ✅ Webhook Route
app.post('/webhook', verifyGitHubSignature, (req, res) => {
    console.log('✅ Valid Webhook Received:', req.body);

    // Save webhook logs asynchronously
    fs.appendFile('webhook_log.json', JSON.stringify(req.body, null, 2) + '\n', (err) => {
        if (err) console.error("❌ Failed to write webhook log:", err);
    });

    res.status(200).send('Webhook received successfully');
});

console.log("✅ Webhook route added at /webhook");

// ✅ Default Route
app.get("/", (req, res) => res.send("Backend is running!"));

// ✅ Test MongoDB Query Route
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