const SubFranchise = require("../model/sub_franchise");

const addSubFranchise = async (req, res) => {

    try {

        const { sub_franchise_name, email, mobile, address, state, city, franchise_name_id } = req.body;

        if (!(sub_franchise_name, email, mobile)) {
            res.status(400).send({ "status": 400, "message": "fill all required field" });
            return;
        }

        const isEmail = await SubFranchise.findOne({ email });
        const isMobile = await SubFranchise.findOne({ mobile });

        if (isEmail || isMobile) {
            res.status(400).send({ "status": 400, "message": "Email & Mobile is already registered" });
            return;
        }

        const subFranchise = await SubFranchise.create({
            sub_franchise_name,
            email: email.toLowerCase(),
            mobile,
            address,
            state,
            city,
        })

        res.status(200).send({ "status": 200, "message": "New Sub Franchise added successfully", "data": subFranchise })
        return;

    } catch (err) {
        res.status(500).send("Internaml Server error");
        return;
    }

}

const editSubFranchise = async (req, res) => {

    try {

        const { sub_franchise_name, email, mobile, address, state, city, id } = req.body;

        if (!(id)) {
            res.status(400).send({ "status": 400, "message": "User ID is requuired" });
            return;
        }

        const user = await SubFranchise.findById(id);
        if (!user) {
            res.status(400).send({ "status": 400, "message": "User not found" });
            return;
        }
        user.sub_franchise_name = sub_franchise_name === undefined ? user.sub_franchise_name : sub_franchise_name;
        user.email = email === undefined ? user.email : email.toLowerCase().trim();
        user.mobile = mobile === undefined ? user.mobile : mobile;
        user.address = address === undefined ? user.address : address;
        user.state = state === undefined ? user.state : state;
        user.city = city === undefined ? user.city : city;

        user.save();

        res.status(200).send({ "status": 200, "message": "New Sub Franchise added successfully", "data": user })
        return;



    } catch (err) {
        console.log(err);
        res.status(500).send("Internal Server error");
        return;
    }

}

const deleteSubFranchise = async (req, res) => {

    try {

        const { id } = req.body;

        if (!(id)) {
            res.status(400).send({ "status": 400, "message": "User ID is requuired" });
            return;
        }

        const user = await SubFranchise.deleteOne({ '_id': id });
        if (!user && user.deletedCount) {
            res.status(400).send({ "status": 400, "message": "User not found" });
            return;
        }
        if (user.deletedCount === 0) {
            res.status(400).send({ "status": 400, "message": "User not found" });
            return;
        }
        console.log(user.deletedCount);

        res.status(200).send({ "status": 200, "message": "Sub Franchise deleted successfully" })
        return;



    } catch (err) {
        console.log(err);
        res.status(500).send("Internal Server error");
        return;
    }

}

const getSubFranchise = async (req, res) => {

    try {

        const user = await SubFranchise.find();
        if (!user) {
            res.status(400).send({ "status": 400, "message": "Users not found" });
            return;
        }

        res.status(200).send({ "status": 200, "message": "Sub Franchise fetched successfully", "data": user })
        return;

    } catch (err) {
        console.log(err);
        res.status(500).send("Internal Server error");
        return;
    }

}

module.exports = { addSubFranchise, editSubFranchise, deleteSubFranchise, getSubFranchise };