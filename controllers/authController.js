const jwt = require("jsonwebtoken")
const User = require("./../models/user")

exports.signUp = async (req, res, next) => {
    try {
        const user = await User.create({
            username : req.body.username,
            email : req.body.email,
            password : req.body.password,
            confirmPassword : req.body.confirmPassword,
            role : req.body.role
        })

        const token = jwt.sign({id : user._id}, "secretIDDDDD", {
            expiresIn : "90d"
        })

        res.status(201).json({
            status : "success",
            user,
            token
        })
    } catch(err) {
        res.status(404).json({
            status : "fail",
            message : err
        })
    }
}

exports.signIn = async (req, res ,next) => {
    try {
        const email = req.body.email
        const password = req.body.password

        if(!email || !password) {
            return res.status(400).json({
                status : "fail",
                message : "please provide email and password both"
            })
        }

        const user = await User.findOne({email}).select("password")

        const correct = await correctPassword(password, user.password)

        if(!user || !correct) {
            return res.status(401).json({
                status : "fail",
                message : "invalid email or password"
            })
        }

        const token = jwt.sign({id : user._id}, "secretIDDDDD", {expiresIn : "90d"})

        res.status(200).json({
            status : "success",
            message : "user signed in",
            token
        })

    } catch(err) {
        res.status(404).json({
            status : "fail",
            message : err
        })
    }
}

exports.protect = async (req, res, next) => {
    try {
        let token;

        if(req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
            token = req.headers.authorization.split(" ")[1]
        }

        if(!token) {
            return res.status(401).json({
                status : "fail",
                message : "you are logged out"
            })
            //next()
        }

        const decoded = jwt.verify(token, "secretIDDDDD")

        const user = await User.findById(decoded.id)

        if(!user) {
            return res.status(401).json({
                status : "fail",
                message : "the token do not belong to this user"
            })
        }

        if(user.changePasswordAfter(decoded.iat)) {
            return res.status(401).json({
                status : "fail",
                message : "user have changed the password! please login again"
            })
        }

        // res.status(200).json({
        //     status : "success",
        //     message : "user verified for protected routes"
        // })

        req.user = user

    } catch(err) {
        res.staus(404).json({
            status : "fail",
            message : err
        })
    }
    next()
}