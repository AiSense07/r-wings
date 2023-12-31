const mongoose = require('mongoose');

const SubFranchise = mongoose.Schema({
    "sub_franchise_name": { type: String },
    "franchise_name_id": { type: String, default: null },
    "email": { type: String },
    "mobile": { type: String },
    "address": { type: String, default: null },
    "city": { type: String, default: null },
    "state": { type: String, default: null },
})

module.exports = mongoose.model("SubFranchise", SubFranchise);