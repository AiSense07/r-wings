const jwt = require('jsonwebtoken');

const TOKEN_KEY = process.env.TOKEN_KEY;

const verifyToken = (req, res, next) => {

    const token = req.headers['authorization'];
     console.log(token);

    if(!token){
        return res.status(400).send({ "status": 400, "message": "A token is required for authentication"});
    }

    try{
        const decode = jwt.verify(token, TOKEN_KEY);
        console.log(decode);
    } catch (err) {
        console.log(err);
        return res.status(400).send({ "status": 400, "message": "Invalid token"});
    }

}

module.exports = verifyToken;