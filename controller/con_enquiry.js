const Enquiry = require('../model/enquiry');
// const SubFranchise = require('../model/sub_franchise');
// const Franchise = require('../model/franchise');

const addEnquiry = async (req, res) => {
    try {

        const { name, email, subject, message, user_id, user_type } = req.body;

        if (!(name, email, subject, message, user_id, user_type)) {
            res.status(400).send({ "status": 400, "message": "fill all required field" });
            return;
        }

        const data = await Enquiry.create({
            name,
            email: email.toLowerCase(),
            subject,
            message,
            user_id,
            user_type,
        });

        res.status(200).send({ "status": 200, "message": "Successfully sent your Enquiry", "data": data });
        return;

    } catch (err) {
        console.log(err);
        res.status(500).send("Internal Server error");
        return;
    }
}

const getEnquiry = async (req, res) => {
    try {

        const user_type = req.query.userType;
        // console.log(req.p)

        if (!user_type) {
            res.status(400).send({ "status": 400, "message": "User type is required" });
            return;
        }

        if (user_type === "Sub Franchise") {

            const delivery = await Enquiry.find({ user_type: "Delivery Boy" });
            const user = await Enquiry.find({ user_type: "User" });
            const data = [...delivery, ...user]
            res.status(200).send({ "status": 200, "message": "Enquiry fetch successfully", "data": data });
            return;

        } else if (user_type === "Franchise") {

            const data = await Enquiry.find({ user_type: "Sub Franchise" });
            res.status(200).send({ "status": 200, "message": "Enquiry fetch successfully", "data": data });
            return;

        } else if (user_type === "Employee") {

            const employee = await Enquiry.find({ user_type });
            const allData = await Enquiry.find();
            const data = allData.filter(item1 => !employee.some(item2 => item2.id === item1.id));
            res.status(200).send({ "status": 200, "message": "Enquiry fetch successfully", "data": data });
            return;

        } else if (user_type === "Admin") {
            const allData = await Enquiry.find();
            res.status(200).send({ "status": 200, "message": "Enquiry fetch successfully", "data": allData });
            return;
        } else {
            res.status(400).send({ "status": 400, "message": "Please enter valid User type" });
            return;
        }

    } catch (err) {
        console.log(err);
        res.status(500).send("Internal server error");
        return;
    }
}

module.exports = { addEnquiry, getEnquiry }