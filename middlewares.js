const {houseSchemaValidation} = require('./ValidationSchemas');
const ExpressError = require('./utilities/expressError');
const House = require('./models/house');
const Review = require('./models/review');

//-------------------------------schema Validation---------------------------------------------------
module.exports.validateHouse = (req,res,next)=>{
    
    const { error } = houseSchemaValidation.validate(req.body);
    if (error) {
        const msg = error.details.map(el => el.message).join(',');
        throw new ExpressError(msg, 400);
    }
    else{
        next()
    }
}

//----------------------to check user is loggedIn or Not (authorization)------------------------

// for this i am using authenticate.protect route

module.exports.isLoggedIn = (req,res,next)=>{

    if(!req.isAuthenticated()){
        req.session.returnTo = req.originalUrl;
        req.flash('error','You must be signed in')
        return res.redirect('/login');
    }
    next();
}

//---------------to store return to url because session gets cleared after login--------------
module.exports.storeReturnTo = (req, res, next) => {
    if (req.session.returnTo) {
        res.locals.returnTo = req.session.returnTo;
    }
    next();
}

//-------------to authorize current user have permission or not for house-----------------------
module.exports.isAuthor = async(req,res,next) => {
    const {id} = req.params;
    const house = await House.findById(id);


    if(!house.author.equals(req.user._id)){
        req.flash('error','You dont have permission to do that.');
       return res.redirect(`/houses/${id}`);
    }

    next();
}

//----------------to authorize current user have permission or not for review-----------------------
module.exports.isReviewAuthor = async(req,res,next) => {
    const {id,reviewId} = req.params;
    const review = await Review.findById(reviewId);

    if(!review.author.equals(req.user._id)){
        req.flash('error','You dont have permission to do that.');
       return res.redirect(`/houses/${id}`);
    }

    next();
}
