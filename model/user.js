const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

var validateEmail = function(email) {
    var re = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    return re.test(email)
};

const UserModel = new mongoose.Schema({
    "fName": { 
        type: String, 
        default: null,
        trim: true, 
        required: [true, "First name is required."]
    },
    "lName": { 
        type: String, 
        default: null,
        trim: true, 
        required: [true, "Last name is required."]
    },
    "email": {
        type: String,
        unique: [true, "Email Id is already used."], 
        lowercase: true, 
        trim: true, 
        required: [true, "Email address is required."],
        validate: [validateEmail, "Please enter valid email address."]
    },
    "pass": { 
        type: String, 
        default: null,
        required: [true, "Password is required."]
    },
    "companyName": { 
        type: String, 
        default: null,
        trim: true, 
        required: [true, "Company name is required."]
    },
    "companyAddress": { 
        type: String, 
        default: null,
        trim: true, 
        required: [true, "Company address is required."]
    },
    "pinCode": { 
        type: Number, 
        default: null,
        trim: true, 
        required: [true, "Pincode is required."],
        maxlength: [6, "Please enter valid Pincode."]
    },
    "state": { 
        type: Number, 
        default: null,
        trim: true, 
        required: [true, "Please select State."]
    },
    "city": { 
        type: String, 
        default: null,
        trim: true, 
        lowercase: true,
        required: [true, "Please enter you town/city."]
    },
    "mobile": { 
        type: Number, 
        default: null,
        trim: true, 
        required: [true, "Mobile number is required."],
        maxlength: [10, "Please enter at least 10 digit Mobile number."]
    },
    "agentName": { 
        type: Number, 
        default: null,
        trim: true, 
        required: [true, "Please select Agent name."]
    },
    "transportName": { 
        type: Number, 
        default: null,
        trim: true, 
        required: [true, "Please select Transport name."]
    },
    "gstNumber": { 
        type: String, 
        default: null,
        trim: true, 
        required: [true, "GST number is required."],
        maxlength: [15, "Please enter valid GST number."]
    },
});

UserModel.pre('save', function(next) {
    var user = this;

    // only hash the password if it has been modified (or is new)
    if (!user.isModified('password')) return next();

    // generate a salt
    bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
        if (err) return next(err);

        // hash the password using our new salt
        bcrypt.hash(user.password, salt, function(err, hash) {
            if (err) return next(err);
            // override the cleartext password with the hashed one
            user.password = hash;
            next();
        });
    });
});
     
UserModel.methods.comparePassword = function(candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};

module.exports = mongoose.model("user", UserModel);