const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');
const User = require('./Models/User');
const imageDownloader = require('image-downloader');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const Booking = require('./Models/Booking');
const multer = require('multer');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, './.env') });
const fs = require('fs');
const Place = require('./Models/Place');
app.use(cookieParser());

app.use(cors({
  origin:true,
  credentials:true
}));

app.use(express.json());
app.use('/uploads',express.static(__dirname+'/uploads'));

const salt = bcrypt.genSaltSync(8);
const jwtSecret = process.env.jwtSecret;

mongoose.connect(process.env.mongoURL)

app.get('/test',(req,res)=>{
  res.json('test ok');
});

app.post('/register',async (req,res)=>{
  const {name,email,password} = req.body;
  try{
    const userDoc = await User.create({
      name,
      email,
      password:bcrypt.hashSync(password,salt)
    });
    res.json(userDoc);
  }catch(e){
    res.status(422).json(e);
  }
})

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }
    const userDoc = await User.findOne({ email });
    if (!userDoc) {
      return res.status(404).json({ error: 'User not found.' });
    }
    const passOk = bcrypt.compareSync(password, userDoc.password);
    if (!passOk) {
      return res.status(401).json({ error: 'Incorrect password.' });
    }
    jwt.sign({email: userDoc.email,id: userDoc._id,name: userDoc.name},jwtSecret,(err, token) => {
        if (err) {
          console.error('Error generating token:', err);
          return res.status(500).json({ error: 'Internal server error during token generation.' });
        }
        res.cookie('token', token).json(userDoc);
      }
    );
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});


app.get('/profile', (req, res) => {
  const { token } = req.cookies;
  if (token) {
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
      if (err) {
        return res.status(403).json('Token verification failed');
      }
      const { name, email, _id } = await User.findById(userData.id);
      res.json({ name, email, _id });
    });
  } else {
    res.status(401).json('No token provided');
  }
});


app.post('/logout',(req,res)=>{
  res.cookie('token','').json(true);
})

app.post('/upload-by-link',async(req,res)=>{
  const {link} = req.body;
  const newName = 'photo' +Date.now() + '.jpg';
  await imageDownloader.image({
    url:link,
    dest:__dirname+'/uploads/'+newName,
  });
  res.json(newName);
});

const photosMiddleware = multer({dest:__dirname+'/uploads'});

app.post('/upload',photosMiddleware.array('photos',100) ,(req,res)=>{
    const uploadedFiles = [];
    for(let i=0;i<req.files.length;i++){
      const {path,originalname} = req.files[i];
      const parts = originalname.split('.');
      const ext = parts[parts.length-1];
      const newPath = path+"."+ext;
      fs.renameSync(path,newPath);
      uploadedFiles.push(newPath.replace(__dirname+'/uploads/',''));
    }
    res.json({ files: uploadedFiles });
});

app.post('/places',(req,res)=>{
  const {token} = req.cookies;
  const {title,address,photos:addedPhotos,description,checkIn,checkOut
  ,perks,price,maxNoOfGuests,extraInfo} = req.body;
  jwt.verify(token,jwtSecret,{},async(err,userData)=>{
    if(err) throw err;
    const placeDoc = await Place.create({
      owner:userData.id,title,address,addedPhotos,
      description,checkIn,checkOut
      ,perks,extraInfo,maxNoOfGuests,price,
    });
    res.json(placeDoc);
  });
});

app.put('/places', async (req, res) => {
  const { token } = req.cookies;
  const { id, title, address, addedPhotos, description, checkIn, checkOut, 
    perks, extraInfo, maxNoOfGuests, price } = req.body;
  jwt.verify(token, jwtSecret, {}, async (err, userData) => {
    if (err) throw err;
    const placeDoc = await Place.findById(id);
    if (userData.id === placeDoc.owner.toString()) {
      placeDoc.set({
        title, address, photos: addedPhotos, description, checkIn, checkOut,
        perks, extraInfo, maxNoOfGuests, price
      });
      await placeDoc.save();
      res.json('ok');
    }
  })
})


app.get('/user-places',(req,res)=>{
  const {token} = req.cookies;
  jwt.verify( token , jwtSecret , {} , async (err,userData)=>{
    if(err) throw err;
    const {id} = userData;
    res.json(await Place.find({owner:id}));
    console.log(id);
  });
});

app.get('/places/:id',async (req,res)=>{
  const {id} = req.params;
  res.json(await Place.findById(id));
})

app.get('/places',async(req,res)=>{
  res.json(await Place.find());
})

app.post('/bookings', async (req, res) => {
  const userData = await getUserDataFromReq(req);
  const { place, checkIn, checkOut, numberOfGuests, name, phone, price } = req.body;
  Booking.create({
    place, checkIn, checkOut, numberOfGuests, name, phone, price,
    user: userData.id
  }).then((doc) => {
    res.json(doc);
  })
    .catch(err => {
      console.error('Error while creating booking:', err);
      res.status(500).json({ error: 'Internal server error' });
    });
});

async function getUserDataFromReq(req) {
  return new Promise((resolve, reject) => {
    const { token } = req.cookies;
    jwt.verify(token, jwtSecret, {}, (err, userData) => {
      if (err) throw err;
      resolve(userData);
    });
  });
}

app.get('/bookings', async (req, res) => {
  const userData = await getUserDataFromReq(req);
  res.json(await Booking.find({ user: userData.id }).populate('place'));
})


app.listen(process.env.port,()=>{
  console.log('connected');
});
