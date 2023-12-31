const express = require('express');
const router = express.Router();
const addDeliveryBoy = require("../controller/con_delivery_boy");

router.post("/addDeliveryBoy", addDeliveryBoy.addDeliveryBoy);

router.post("/editDeliveryBoy", addDeliveryBoy.editDeliveryBoy);

router.post("/deleteDeliveryBoy", addDeliveryBoy.deleteDeliveryBoy);

router.get("/getDeliveryBoy", addDeliveryBoy.getDeliveryBoy);

module.exports = router;