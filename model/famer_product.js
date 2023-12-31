const mongoose = require("mongoose");

const FarmerProduct = mongoose.Schema({
    "productImg" : { type: String, default: null },
    "productName" : { type: String, default: null },
    "productCatId" : { type: String, default: null },
    "productSubCatId" : { type: String, default: null },
    "productPrice" : { type: String, default: null },
    "productQty" : { type: String, default: null },
    "productDesc" : { type: String, default: null },
    "productHSTime" : { type: String, default: null },
    "productHETime" : { type: String, default: null },
    "paymentStatus" : { type: String, default: "0" },
    "productStatus" : { type: String, default: "0" },
});

module.exports = mongoose.model("FarmerProduct",FarmerProduct);