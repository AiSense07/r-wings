const mongoose = require('mongoose');

const Enquiry = mongoose.Schema({
    "name": { type: String, default: null },
    "email": { type: String, default: null },
    "subject": { type: String, default: null },
    "message": { type: String, default: null },
    "user_id": { type: String, default: null },
    "user_type": { type: String, default: null }
});

module.exports = mongoose.model("enquiry" , Enquiry);