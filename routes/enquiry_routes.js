const express =  require('express');
const router = express.Router();
const enquiry = require("../controller/con_enquiry");

router.post("/addEnquiry", enquiry.addEnquiry);
router.get("/getEnquiry", enquiry.getEnquiry);

module.exports = router;
