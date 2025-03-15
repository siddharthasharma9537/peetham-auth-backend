const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, unique: true, sparse: true },
    mobile: { type: String, unique: true, sparse: true },
    password: { type: String, required: true },
    otp: { type: String, default: null },  // ✅ Fix: Ensure comma is correctly placed
    otpExpires: { type: Date, default: null }  // ✅ Fix: Ensure syntax is correct
});

module.exports = mongoose.model('User', UserSchema);