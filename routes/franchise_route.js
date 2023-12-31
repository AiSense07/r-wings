const express = require('express');
const router = express.Router();
const addFranchise = require("../controller/con_frachise");

router.post("/addFrenchise", addFranchise.addFranchise);

router.post("/editFranchise", addFranchise.editFranchise);

router.post("/deleteFranchise", addFranchise.deleteFranchise);

router.get("/getFranchise", addFranchise.getFranchise);

module.exports = router;