const Franchise = require("../model/franchise");

const addFranchise = async (req, res) => {

    try {

        const { franchise_name, email, mobile, address, state, city } = req.body;

        if (!(franchise_name, email, mobile)) {
            res.status(400).send({ "status": 400, "message": "fill all required field" });
            return;
        }

        const isEmail = await Franchise.findOne({ email });
        const isMobile = await Franchise.findOne({ mobile });

        if (isEmail || isMobile) {
            res.status(400).send({ "status": 400, "message": "Email & Mobile is already registered" });
            return;
        }

        const franchise = await Franchise.create({
            franchise_name,
            email: email.toLowerCase(),
            mobile,
            address,
            state,
            city,
        })

        res.status(200).send({ "status": 200, "message": "New Franchise added successfully", "data": franchise })
        return;

    } catch (err) {
        res.status(500).send("Internaml Server error");
        return;
    }

}

const editFranchise = async (req, res) => {

    try {

        const { franchise_name, email, mobile, address, state, city, id } = req.body;

        if (!(id)) {
            res.status(400).send({ "status": 400, "message": "User ID is requuired" });
            return;
        }

        const user = await Franchise.findById(id);
        if (!user) {
            res.status(400).send({ "status": 400, "message": "User not found" });
            return;
        }
        user.franchise_name = franchise_name === undefined ? user.franchise_name : franchise_name;
        user.email = email === undefined ? user.email : email.toLowerCase().trim();
        user.mobile = mobile === undefined ? user.mobile : mobile;
        user.address = address === undefined ? user.address : address;
        user.state = state === undefined ? user.state : state;
        user.city = city === undefined ? user.city : city;

        user.save();

        res.status(200).send({ "status": 200, "message": "New Franchise added successfully", "data": user })
        return;



    } catch (err) {
        console.log(err);
        res.status(500).send("Internal Server error");
        return;
    }

}

const deleteFranchise = async (req, res) => {

    try {

        const { id } = req.body;

        if (!(id)) {
            res.status(400).send({ "status": 400, "message": "User ID is requuired" });
            return;
        }

        const user = await Franchise.deleteOne({ '_id': id });
        if (!user) {
            res.status(400).send({ "status": 400, "message": "User not found" });
            return;
        }

        if (user.deletedCount === 0) {
            res.status(400).send({ "status": 400, "message": "User not found" });
            return;
        }

        res.status(200).send({ "status": 200, "message": "Franchise deleted successfully" })
        return;



    } catch (err) {
        console.log(err);
        res.status(500).send("Internal Server error");
        return;
    }

}

const getFranchise = async (req, res) => {

    try {

        const user = await Franchise.find();
        if (!user) {
            res.status(400).send({ "status": 400, "message": "Users not found" });
            return;
        }

        res.status(200).send({ "status": 200, "message": "Franchise fetched successfully", "data": user })
        return;

    } catch (err) {
        console.log(err);
        res.status(500).send("Internal Server error");
        return;
    }

}

module.exports = { addFranchise, editFranchise, deleteFranchise, getFranchise };