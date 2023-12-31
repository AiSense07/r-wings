const mongoose = require('mongoose');

const userModel = new mongoose.Schema({
    "fName": { type: String, default: null },
    "lName": { type: String, default: null },
    "email": { type: String, unique: true },
    "pass": { type: String },
    "image" : { type : String},
    "token": { type: String }
})

module.exports = mongoose.model("user", userModel);