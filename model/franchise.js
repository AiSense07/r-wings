const mongoose = require('mongoose');

const Franchise = mongoose.Schema({
    "franchise_name": { type: String },
    "email": { type: String },
    "mobile": { type: String },
    "address": { type: String, default: null },
    "city": { type: String, default: null },
    "state": { type: String, default: null },
})

module.exports = mongoose.model("Franchise", Franchise);