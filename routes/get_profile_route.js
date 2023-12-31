const express = require('express');
const router = express.Router();
const get_profile = require("../controller/get_profile");

router.post("/getProfile", get_profile.getProfile);

module.exports = router;