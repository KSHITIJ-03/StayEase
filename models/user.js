const mongoose = require("mongoose")
const validator = require("validator")
const bcrypt = require("bcrypt")
const crypto = require("crypto")

const userSchema = new mongoose.Schema({
    name : {
        type : String,
        required : [true, "name is required"]
    },
    email : {
        type : String,
        required : [true, "email is required"],
        unique : [true, "account with this email already exists"],
        lowercase : true,
        validate : [validator.isEmail, "email should be of proper format"]
    },
    password : {
        type : String,
        required : [true, "password is required"],
        minLength : 8
        //select : false
    },
    confirmPassword : {
        type : String,
        required : [true, "password is required to be confirmed"],
        validate : {
            validator : function(val) {
                return val === this.password
            },
            message : "both the passwords should match"
        }
    },
    passwordChange : Date,
    passwordResetToken : String,
    passwordResetExpire : Date,
},
{
    toJSON : {virttuals : true},
    toObject : {virtuals : true}
})

userSchema.pre("save", async function(next) {
    this.confirmPassword = undefined
    this.password = await bcrypt.hash(this.password, 12)
    next()
})

userSchema.pre("save", function(next){
    if(!this.isModified("password") || this.isNew) return next()
    this.passwordChange = Date.now() - 1000
    next()
})

userSchema.methods.correctPassword = async(candidatePassword, password) => {
    return bcrypt.compare(candidatePassword, password)
}

userSchema.methods.changePassword = function(JWTTimeStamp) {
    if(this.passwordChange) {
        const changeTimeStamp = parseInt(this.passwordChange.getTime()/1000, 10)
        return JWTTimeStamp < changeTimeStamp
    }

    return false
}

userSchema.methods.createPasswordResetToken = function() {
    const resetToken = crypto.randomBytes(32).toString("hex")
    this.passwordResetToken = crypto.createHash("sha256").update(resetToken).digest("hex")
    this.passwordResetExpire = Date.now() + 10*60*1000
    //console.log({resetToken}, this.passwordResetToken);
    return resetToken
}



const User = new mongoose.model("User", userSchema)

module.exports = User