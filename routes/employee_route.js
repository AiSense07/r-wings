const express = require('express');
const router = express.Router();
const addEmployee = require("../controller/con_employee");
const verifyToken = require("../middleware/verifyToken")

router.post("/addEmployee",verifyToken, addEmployee.addEmployee);

router.post("/editEmployee", addEmployee.editEmployee);

router.post("/deleteEmployee", addEmployee.deleteEmployee);

router.get("/getEmployee", addEmployee.getEmployee);

module.exports = router;