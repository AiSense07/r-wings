const DeliveryBoy = require("../model/delivery_boy");

const addDeliveryBoy = async (req, res) => {

    try {

        const { delivery_boy_name, email, mobile, address, state, city, fr_id, sub_fr_id } = req.body;

        if (!(delivery_boy_name, email, mobile)) {
            res.status(400).send({ "status": 400, "message": "fill all required field" });
            return;
        }

        const isEmail = await DeliveryBoy.findOne({ email });
        const isMobile = await DeliveryBoy.findOne({ mobile });

        if (isEmail || isMobile) {
            res.status(400).send({ "status": 400, "message": "Email & Mobile is already registered" });
            return;
        }

        const delivery = await DeliveryBoy.create({
            fr_id,
            sub_fr_id,
            delivery_boy_name,
            email: email.toLowerCase(),
            mobile,
            address,
            state,
            city,
        })

        res.status(200).send({ "status": 200, "message": "New DeliveryBoy added successfully", "data": delivery })
        return;

    } catch (err) {
        res.status(500).send("Internal Server error");
        return;
    }

}

const editDeliveryBoy = async (req, res) => {

    try {

        const { delivery_boy_name, email, mobile, address, state, city, fr_id, sub_fr_id } = req.body;

        if (!(id)) {
            res.status(400).send({ "status": 400, "message": "User ID is requuired" });
            return;
        }

        const user = await DeliveryBoy.findById(id);
        if (!user) {
            res.status(400).send({ "status": 400, "message": "User not found" });
            return;
        }
        user.delivery_boy_name = delivery_boy_name === undefined ? user.delivery_boy_name : delivery_boy_name;
        user.email = email === undefined ? user.email : email.toLowerCase().trim();
        user.mobile = mobile === undefined ? user.mobile : mobile;
        user.fr_id = fr_id === undefined ? user.fr_id : fr_id;
        user.mobile = sub_fr_id === undefined ? user.sub_fr_id : sub_fr_id;
        user.address = address === undefined ? user.address : address;
        user.state = state === undefined ? user.state : state;
        user.city = city === undefined ? user.city : city;

        user.save();

        res.status(200).send({ "status": 200, "message": "New DeliveryBoy added successfully", "data": user })
        return;



    } catch (err) {
        console.log(err);
        res.status(500).send("Internal Server error");
        return;
    }

}

const deleteDeliveryBoy = async (req, res) => {

    try {

        const { id } = req.body;

        if (!(id)) {
            res.status(400).send({ "status": 400, "message": "User ID is requuired" });
            return;
        }

        const user = await DeliveryBoy.deleteOne({ '_id': id });
        if (!user) {
            res.status(400).send({ "status": 400, "message": "User not found" });
            return;
        }

        if (user.deletedCount === 0) {
            res.status(400).send({ "status": 400, "message": "User not found" });
            return;
        }

        res.status(200).send({ "status": 200, "message": "DeliveryBoy deleted successfully" })
        return;



    } catch (err) {
        console.log(err);
        res.status(500).send("Internal Server error");
        return;
    }

}

const getDeliveryBoy = async (req, res) => {

    try {

        const user = await DeliveryBoy.find();
        if (!user) {
            res.status(400).send({ "status": 400, "message": "Users not found" });
            return;
        }

        res.status(200).send({ "status": 200, "message": "DeliveryBoy fetched successfully", "data": user })
        return;

    } catch (err) {
        console.log(err);
        res.status(500).send("Internal Server error");
        return;
    }

}

module.exports = { addDeliveryBoy, editDeliveryBoy, deleteDeliveryBoy, getDeliveryBoy };