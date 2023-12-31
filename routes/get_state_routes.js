const express = require('express');
const router = express.Router();
const getState = require("../controller/get_state");

router.get("/getState", getState.getState);
router.get("/getCity", getState.getCity);

module.exports = router;