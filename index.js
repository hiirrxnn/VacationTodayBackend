const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const mime = require('mime-types');
require('dotenv').config({ path: path.resolve(__dirname, './.env') });

const User = require('./Models/User');
const Place = require('./Models/Place');
const Booking = require('./Models/Booking');

const app = express();
const salt = bcrypt.genSaltSync(10);
const jwtSecret = process.env.JWT_SECRET;

mongoose.connect(process.env.MONGO_URL);

app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(__dirname + '/uploads'));

app.use(cors({
  origin: true,
  credentials: true,
}));

async function getUserDataFromReq(req) {
  return new Promise((resolve, reject) => {
    const { token } = req.cookies;
    jwt.verify(token, jwtSecret, {}, (err, userData) => {
      if (err) reject(err);
      resolve(userData);
    });
  });
}

app.get('/test', (req, res) => {
  res.json('test ok');
});

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const userDoc = await User.create({
      name,
      email,
      password: bcrypt.hashSync(password, salt),
    });
    res.json(userDoc);
  } catch (e) {
    res.status(422).json(e);
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const userDoc = await User.findOne({ email });
    if (!userDoc) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const passOk = bcrypt.compareSync(password, userDoc.password);
    if (!passOk) {
      return res.status(401).json({ error: 'Incorrect password.' });
    }

    jwt.sign({ email: userDoc.email, id: userDoc._id, name: userDoc.name }, jwtSecret, {}, (err, token) => {
      if (err) {
        return res.status(500).json({ error: 'Internal server error during token generation.' });
      }
      res.cookie('token', token).json(userDoc);
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

app.get('/profile', async (req, res) => {
  try {
    const { token } = req.cookies;
    if (!token) {
      return res.status(401).json('No token provided');
    }

    const userData = await getUserDataFromReq(req);
    const user = await User.findById(userData.id);
    if (!user) {
      return res.status(404).json('User not found');
    }
    res.json({ name: user.name, email: user.email, _id: user._id });
  } catch (err) {
    res.status(403).json('Token verification failed');
  }
});

app.post('/logout', (req, res) => {
  res.cookie('token', '',).json(true);
});

app.post('/upload-by-link', async (req, res) => {
  const { link } = req.body;
  const newName = 'photo' + Date.now() + '.jpg';
  await imageDownloader.image({
    url: link,
    dest: path.join(__dirname, '/uploads', newName),
  });
  res.json(newName);
});

const photosMiddleware = multer({ dest: path.join(__dirname, '/uploads') });

app.post('/upload', photosMiddleware.array('photos', 100), (req, res) => {
  const uploadedFiles = req.files.map(file => {
    const parts = file.originalname.split('.');
    const ext = parts[parts.length - 1];
    const newPath = file.path + '.' + ext;
    fs.renameSync(file.path, newPath);
    return newPath.replace(__dirname + '/uploads/', '');
  });
  res.json({ files: uploadedFiles });
});

app.post('/places', async (req, res) => {
  const { token } = req.cookies;
  const { title, address, photos, description, checkIn, checkOut, perks, price, maxNoOfGuests, extraInfo } = req.body;
  try {
    const userData = await getUserDataFromReq(req);
    const placeDoc = await Place.create({
      owner: userData.id,
      title,
      address,
      photos,
      description,
      checkIn,
      checkOut,
      perks,
      extraInfo,
      maxNoOfGuests,
      price,
    });
    res.json(placeDoc);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create place' });
  }
});

app.put('/places', async (req, res) => {
  const { token } = req.cookies;
  const { id, title, address, photos, description, checkIn, checkOut, perks, extraInfo, maxNoOfGuests, price } = req.body;
  try {
    const userData = await getUserDataFromReq(req);
    const placeDoc = await Place.findById(id);
    if (userData.id === placeDoc.owner.toString()) {
      placeDoc.set({
        title,
        address,
        photos,
        description,
        checkIn,
        checkOut,
        perks,
        extraInfo,
        maxNoOfGuests,
        price,
      });
      await placeDoc.save();
      res.json('ok');
    } else {
      res.status(403).json('Unauthorized');
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to update place' });
  }
});

app.get('/user-places', async (req, res) => {
  try {
    const userData = await getUserDataFromReq(req);
    const places = await Place.find({ owner: userData.id });
    res.json(places);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user places' });
  }
});

app.get('/places/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const place = await Place.findById(id);
    res.json(place);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch place' });
  }
});

app.get('/places', async (req, res) => {
  try {
    const places = await Place.find();
    res.json(places);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch places' });
  }
});

app.post('/bookings', async (req, res) => {
  const { place, checkIn, checkOut, numberOfGuests, name, phone, price } = req.body;
  try {
    const userData = await getUserDataFromReq(req);
    const bookingDoc = await Booking.create({
      place,
      checkIn,
      checkOut,
      numberOfGuests,
      name,
      phone,
      price,
      user: userData.id,
    });
    res.json(bookingDoc);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create booking' });
  }
});

app.get('/bookings', async (req, res) => {
  try {
    const userData = await getUserDataFromReq(req);
    const bookings = await Booking.find({ user: userData.id }).populate('place');
    res.json(bookings);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

app.listen(process.env.PORT, () => {
  console.log(`Server is running on port ${process.env.PORT}`);
});
