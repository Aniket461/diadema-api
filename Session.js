const mongoose = require("mongoose");

const sessionSchema = new mongoose.Schema({
    emailHash: {
        type: String,
        required: true,
        unique: true,
    },
    lastActivity: {
        type: Date,
        required: true,
        default: Date.now,
    },
    accessToken: {
        type: String,
        required: true,
    },
    refreshToken: {
        type: String, // Optional
    },
    userId: {
        type: String, // Assuming you have a User model
        required: true,
    },
    expiresAt: {
        type: Date,
        required: true,
        default: Date.now,
        expires: 1800, // Automatically remove document after 30 minutes
    },
    currentState:{
        type:String,
        required:true
    }
});

sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL index for automatic expiration

const Session = mongoose.model('Session', sessionSchema);

module.exports = Session;
