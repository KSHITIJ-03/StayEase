const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const passportLocalMongoose=require('passport-local-mongoose');
const validator = require("validator")
const bcrypt = require("bcrypt")

const UserSchema = new Schema({
    email:{
        type:String,
        required:[true, "email is required"],
        unique:[true, "user already exists"],
        validate : [validator.isEmail, "email should of correct format"]
    },
    username : {
        type : String,
        required : [true, "username is required"],
        unique : [true, "username already taken"]
    },
    password : {
        type : String,
        min : [8, "password length must be larger than 8"],
        required : [true, "password is required"],
        select : false
    },
    confirmPassword : {
        type : String,
        required : [true, "confirm password is required"],
        validate : {
            validator : function(val) {
                return this.password == val
            },
            message : "both the passwords should be same"
        }
    },
    role : {
        type : String,
        enum : ["admin", "seller", "user"],
        default : "user"
    },
    changePassword : Date  // latest password change time
});

// pre save hook to encrypt password and to set confirmPassword undefined

UserSchema.pre("save", async function(next) {
    this.confirmPassword = undefined

    if(!this.isModified("password")) return next()

    this.password = await bcrypt.hash(this.password, 12)
    next()
})

// instance method to check if the password is correct or not

UserSchema.methods.correctPassword = async (candidatePassword, userPassword) => {
    return await bcrypt.compare(candidatePassword, userPassword)
}

// instance method to check if user have changed its password after a sign in

UserSchema.methods.changePasswordAfter = function(JWT_TIMESTAMP) {

    if(this.changePassword) {
        const changeTimeStamp = parseInt(this.passwordChange.getTime()/1000, 10)
        return JWT_TIMESTAMP < changeTimeStamp
    }
    return false
}

// it will autometically add username and password field in UserSchema
//UserSchema.plugin(passportLocalMongoose);

module.exports = mongoose.model('User',UserSchema);