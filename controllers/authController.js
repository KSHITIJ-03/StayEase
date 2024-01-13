const jwt = require("jsonwebtoken")
const User = require("./../models/user")
const sendEmail = require("./../utilities/email")
const crypto = require("crypto")

exports.signup = async (req, res) => {
    try {
        //console.log("hi")
        const user = await User.create({
            name : req.body.name,
            email : req.body.email,
            password :req.body.password,
            confirmPassword : req.body.confirmPassword
        })

        const token = jwt.sign({id : user._id}, "secretIDDDDD", {expiresIn : "90d"})

        res.status(201).json({
            status : "success",
            message : "user signed up",
            token
        })
    } catch(err) {
        res.status(404).json({
            status : "fail",
            message : err
        })
    }
}

exports.login = async (req, res) => {
    try {
        const email = req.body.email
        const password = req.body.password

        if(!email || !password) {
            return res.status(400).json({
                status : "fail",
                message : "email and passowrd both are required"
            })
        }

        const user = await User.findOne({email})

        if(!user || !await user.correctPassword(password, user.password)) {
            return res.status(401).json({
                status : "fail",
                message : "incorrect email or password"
            })
        }

        const token = jwt.sign({id : user._id}, "secretIDDDDD", {expiresIn : "90d"})

        res.status(200).json({
            status : "success",
            token
        })
    } catch(err) {
        res.status(404).json({
            status : "fail",
            message : err
        })
    } 
}

exports.protect = async(req, res, next) => {
    try{
        let token;

        if(req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
            token = req.headers.authorization.split(" ")[1]
        }

        if(!token) {
            return res.status(401).json({
                status : "fail",
                message : "you are logged out"
            })
        }

        const decoded = jwt.verify(token, "secretIDDDDD")
        
        if(!decoded || !await User.findById(decoded.id)) {
            return res.status(401).json({
                status : "fail",
                message : "the token do not belong to this user"
            })
        }

        const freshUser = await User.findById(decoded.id)

        if(freshUser.changePassword(decoded.iat)) {
            return res.status(401).json({
                status : "fail",
                message : "user changed password recently please login again"
            })
        }

        req.user = freshUser
        next()
    }catch(err) {
        res.status(404).json({
            status : "fail",
            message : err
        })
    }
}

exports.updatePassword = async(req, res) => {
    try {
        const password = req.body.password
        const newPassword = req.body.newPassword
        const confirmPassword = req.body.confirmPassword

        if(! await req.user.correctPassword(password, req.user.password)){
            return res.status(401).json({
                status : "fail",
                message : "old password is in correct"
            })
        }

        const user = await User.findById(req.user.id)//.select("password")

        user.password = newPassword
        user.confirmPassword = confirmPassword
        user.save()

        const token = jwt.sign({id : user._id}, "secretIDDDDD", {expiresIn : "90d"})

        res.status(200).json({
            status : "success",
            message : "user password updated",
            token
        })

    } catch(err) {
        res.status(404).json({
            status : "fail",
            message : err
        })
    }
}

exports.forgotPassword = async(req, res, next) => {
    try {
        const user = await User.findOne({email : req.body.email})
        if(!user) {
            return res.status(404).json({
                status : "fail",
                message : "no user with this email address"
            })
        }
        const resetToken = user.createPasswordResetToken()
        await user.save({validateBeforeSave : false})

        const resetURL = req.protocol+"://"+req.get("host")+"/resetPassword/"+resetToken

        //console.log(resetURL); console.log(resetToken); console.log(user);

        const message = "forgot your password ? submit a patch request with a new password and confirm password to url :- " + resetURL + " ." + " if not forgot then please ignore this message"

        try {
            await sendEmail({
            email : user.email,
            subject : "your password reset token valid for 10 minutes",
            message
            })

            return res.status(200).json({
                status : "success",
                message : "Token sent to email"
            })
            next()
        } catch(err) {
            user.passwordResetToken = undefined
            user.passwordResetExpire = undefined
            await user.save({validateBeforeSave : false})

            return res.status(500).json({
                status : "fail",
                message : "email can't be sent! please try again later"
            })
        }
        //next()

    } catch(err) {
        res.status(404).json({
            status : "fail",
            message : err
        })
    }
}

exports.resetPassword = async (req, res) =>{
    try {
        //1) get the token from url
        const hashedToken = crypto.createHash("sha256").update(req.params.token).digest("hex")

        const user = await User.findOne({
            passwordResetToken : hashedToken, 
            passwordResetExpire : {$gt : Date.now()}
        })

        if(!user) {
            return res.status(400).json({
                status : "fail",
                message : "token is invalid or expired"
            })
        }

        user.password = req.body.password
        user.confirmPassword = req.body.confirmPassword
        user.passwordResetToken = undefined
        user.passwordResetExpire = undefined
        await user.save()

        const token = jwt.sign({id : user._id}, "secretIDDDDD", {expiresIn : "90d"})

        // res.cookie("jwt", token, {
        //     expire : new Date(Date.now()+process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000), secure : true
        //     // httpOnly : true this part should only be sent on production
        // })

        res.status(200).json({
            status : "success",
            message : "password updated",
            token
        })
        //2) verify the token if it is not expired and check if user exists and set the new password
        //3) update the passwordChange for user
        //4) log in user and send back jwt token
    } catch(err) {
        res.status(404).json({
            status : "fail",
            message : err
        })
    }
}