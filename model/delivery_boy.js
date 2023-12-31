const mongoose = require('mongoose');

const DeliveryBoy = mongoose.Schema({
    "delivery_boy_name": { type: String },
    "fr_id": { type: String, default: null },
    "sub_fr_id": { type: String, default: null },
    "email": { type: String },
    "mobile": { type: String },
    "address": { type: String, default: null },
    "city": { type: String, default: null },
    "state": { type: String, default: null },
})

module.exports = mongoose.model("DeliveryBoy", DeliveryBoy);