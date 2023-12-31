const Employee = require("../model/employee");

const addEmployee = async (req, res) => {

    try {

        const { employee_name, email, mobile, address, state, city } = req.body;

        if (!(employee_name, email, mobile)) {
            res.status(400).send({ "status": 400, "message": "fill all required field" });
            return;
        }

        const isEmail = await Employee.findOne({ email });
        const isMobile = await Employee.findOne({ mobile });

        if (isEmail || isMobile) {
            res.status(400).send({ "status": 400, "message": "Email & Mobile is already registered" });
            return;
        }

        const employee = await Employee.create({
            employee_name,
            email: email.toLowerCase(),
            mobile,
            address,
            state,
            city,
        })

        res.status(200).send({ "status": 200, "message": "New Employee added successfully", "data": employee })
        return;

    } catch (err) {
        res.status(500).send("Internaml Server error");
        return;
    }

}

const editEmployee = async (req, res) => {

    try {

        const { employee_name, email, mobile, address, state, city, id } = req.body;

        if (!(id)) {
            res.status(400).send({ "status": 400, "message": "User ID is requuired" });
            return;
        }

        const user = await Employee.findById(id);
        if (!user) {
            res.status(400).send({ "status": 400, "message": "User not found" });
            return;
        }
        user.employee_name = employee_name === undefined ? user.employee_name : employee_name;
        user.email = email === undefined ? user.email : email.toLowerCase().trim();
        user.mobile = mobile === undefined ? user.mobile : mobile;
        user.address = address === undefined ? user.address : address;
        user.state = state === undefined ? user.state : state;
        user.city = city === undefined ? user.city : city;

        user.save();

        res.status(200).send({ "status": 200, "message": "New Employee added successfully", "data": user })
        return;



    } catch (err) {
        console.log(err);
        res.status(500).send("Internal Server error");
        return;
    }

}

const deleteEmployee = async (req, res) => {

    try {

        const { id } = req.body;

        if (!(id)) {
            res.status(400).send({ "status": 400, "message": "User ID is requuired" });
            return;
        }

        const user = await Employee.deleteOne({ '_id': id });
        if (!user) {
            res.status(400).send({ "status": 400, "message": "User not found" });
            return;
        }

        if (user.deletedCount === 0) {
            res.status(400).send({ "status": 400, "message": "User not found" });
            return;
        }

        res.status(200).send({ "status": 200, "message": "Employee deleted successfully" })
        return;



    } catch (err) {
        console.log(err);
        res.status(500).send("Internal Server error");
        return;
    }

}

const getEmployee = async (req, res) => {

    try {

        const user = await Employee.find();
        if (!user) {
            res.status(400).send({ "status": 400, "message": "Users not found" });
            return;
        }

        res.status(200).send({ "status": 200, "message": "Employee fetched successfully", "data": user })
        return;

    } catch (err) {
        console.log(err);
        res.status(500).send("Internal Server error");
        return;
    }

}

module.exports = { addEmployee, editEmployee, deleteEmployee, getEmployee };