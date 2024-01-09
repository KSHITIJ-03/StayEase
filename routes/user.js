const express = require('express');
const router = express.Router();
const User = require('../models/user');
const passport = require('passport');
const {storeReturnTo} = require('../middlewares');

const authController = require("./../controllers/authController")

const jwt = require("jsonwebtoken")

//----------------------------------SignUp------------------------------------
router.get('/register',(req,res)=>{
    res.render('user/loginRegister');

})
router.post('/register',async(req,res)=>{
    try{
        const {email, username, password} = req.body;
        const user =  new User({email,username})
        const registeredUser =  await User.register(user,password);

        //without this You have to logIn again after signUp
        req.login(registeredUser,err=>{
            if(err) return next(err);
            req.flash('success','Welcome to yelp-camp!');
            res.redirect('/houses');
        })
    }catch(e){
        req.flash('error',e.message);
        res.redirect('/register');
    }
})



//------------------------------------------------------------------------------




//-------------------------------Login------------------------------------------
router.get('/login',(req,res)=>{
    res.render('user/loginRegister');
})

router.post('/login',storeReturnTo,passport.authenticate('local', { failureRedirect: '/login', failureFlash: true }),(req,res)=>{
    req.flash('success','Welcome Back!');

    const redirectUrl = res.locals.returnTo||'/houses';
    
    res.redirect(redirectUrl);
})

//----------------------------------------------------------------------------------




//--------------------------------Logout------------------------------------------
router.get('/logout', (req, res, next) => {

    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        req.flash('success', 'Goodbye!');
        res.redirect('/login');
    });
});
//------------------------------------------------------------------------------


module.exports = router;