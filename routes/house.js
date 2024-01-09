const express = require('express');
const router = express.Router({mergeParams:true});
const House = require('../models/house');
const catchAsync=require('../utilities/catchAsync');
const Joi = require('joi');
const ExpressError = require('../utilities/expressError');
const multer  = require('multer')
const storage = require('../cloudinary/index');
const { validateHouse, isLoggedIn, isAuthor } = require('../middlewares');
const upload = multer(storage);

//const {cloudinary} = require('../cloudinary');
//const mbxGeocoding= require('@mapbox/mapbox-sdk/services/geocoding');

//const mapboxToken = process.env.MAPBOX_TOKEN;

//const geocoder = mbxGeocoding({accessToken:mapboxToken});



//-----------------index----------------------------------
router.get('/',catchAsync(async(req,res)=>{
    const houses = await House.find({});
    res.render('house/index',{houses});

}))

//---------------------Create-------------------------------
router.get('/new',isLoggedIn,(req,res)=>{
    
    res.render('house/new');
})

router.post('/',isLoggedIn,upload.array('house[images]'),validateHouse,catchAsync(async(req,res)=>{
    
    //forward geocoding the location the user entered and convert it into geojson
   const geodata =  await geocoder.forwardGeocode({
        query:req.body.house.address,
        limit:1
    }).send();
    const house = new House(req.body.house);
    house.author = req.user._id;
    house.geometry = geodata.body.features[0].geometry;
    house.images = req.files.map(f=>({url: f.path, filename: f.filename}));
    // console.log(house);
    // console.log(req.files);

    await house.save();
    req.flash('success','Successfully Created New House!');
    res.redirect('/houses');
}));

//-----------------------Read-------------------------------

router.get('/:id',catchAsync(async(req,res)=>{

    const house = await House.findById(req.params.id).populate({
        path: 'reviews',
        populate:{
            path: 'author'
        }
    }).populate('author');

    // console.log(house);
    res.render("house/show",{house});
}))


//-----------------------Update-------------------------------

router.get('/:id/edit',isLoggedIn,isAuthor,catchAsync(async(req,res)=>{
    const house = await House.findById(req.params.id);
    
    console.log(house);
    res.render('house/edit',{house});
}))


router.put('/:id',isLoggedIn,isAuthor,catchAsync(async(req,res)=>{
    const {id} = req.params;
    console.log(req.body);
    
    const houseEdit =  await House.findByIdAndUpdate(id,{...req.body.house});
    houseEdit.save();
    req.flash('success',`Successfully Updated!`)
    res.redirect(`/houses/${id}`);
}))


//---------------------Delete-----------------------------------

router.delete('/:id',isLoggedIn,isAuthor,catchAsync(async(req,res)=>{

    const {id} = req.params;
    const house = await House.findById(id);
    for (let itr of house.images) {
        await cloudinary.uploader.destroy (itr.filename);
     //    console.log(filename);
    }
    await House.findByIdAndDelete(id);
    req.flash('success','Sussessfully Deleted House!');
    res.redirect('/houses',);
}))


//------------------------addimages-----------------------------

router.put('/:id/addImages',isLoggedIn,isAuthor,upload.array('images'),catchAsync(async(req,res)=>{
    // console.log(req.body);
    const {id} = req.params;
    const house =await House.findById(id);
    const imgs = req.files.map(f=>({url: f.path, filename: f.filename}));
    house.images.push(...imgs);
    house.save();
    // console.log(house);
    // console.log(req.body);
    res.redirect(`/houses/${id}`);
    
}))
//------------------------deleteImages-----------------------------

router.delete('/:id/deleteImages',isLoggedIn,isAuthor,catchAsync(async(req,res)=>{
    const {id} = req.params;
    const house = await House.findById(id);
    if(req.body.deleteImages){
        
        // console.log(req.body.deleteImages);
        for (let filename of req.body.deleteImages) {
           await cloudinary.uploader.destroy (filename);
        //    console.log(filename);
        }
       await house.updateOne({$pull:{images:{filename:{$in: req.body.deleteImages}}}});
    }

    await house.save(); 


    res.redirect(`/houses/${id}`);
    
}));

//------------------------------Finding houses by its location---------------------------
router.post('/findbylocation',catchAsync(async(req,res)=>{

    const geodata =  await geocoder.forwardGeocode({
        query:req.body.location,
        limit:1
    }).send();

    // console.log( geodata.body.features[0].geometry.coordinates[0]);

   const longitude =  geodata.body.features[0].geometry.coordinates[0];
   const latitude = geodata.body.features[0].geometry.coordinates[1];
    
    console.log(geodata.body.features[0].geometry.coordinates);
    const houses = await House.aggregate([
        {
          $geoNear: {
            near: { type: "Point", coordinates: [parseFloat(longitude),parseInt(latitude)] },
            key: "geometry",
            maxDistance: parseInt(50)*1609, // Max distance in meters (assuming the distance is in miles)
            distanceField: "dist.calculated",
            spherical: true
          }
        }
      ]);
    
    // console.log(houses);
    res.render('house/index',{houses});
    // res.redirect('/houses');
}));



module.exports = router;