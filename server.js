const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(express.json());
app.use(cookieParser());

const JWT_SECRET = 'your_jwt_secret';

mongoose.connect('mongodb://localhost:27017/yourDatabase')
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch((error) => console.error('❌ MongoDB connection error:', error));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  id_number: { type: String, required: true, unique: true },
  gender: { type: String, required: true },
  county: { type: String, required: true },
  constituency: { type: String, required: true },
  ward: { type: String, required: true },
  password: { type: String, required: true },
});

userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

const User = mongoose.model('User', userSchema);

// 📝 Register
app.post('/register', async (req, res) => {
  try {
    const { username, id_number, gender, county, constituency, ward, password } = req.body;

    if (!username || !id_number || !gender || !county || !constituency || !ward || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    const existingUser = await User.findOne({ id_number });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'ID Number already registered' });
    }

    const user = new User({ username, id_number, gender, county, constituency, ward, password });
    await user.save();

    res.status(200).json({ success: true, message: 'Registration successful' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ success: false, message: `Server error: ${error.message}` });
  }
});

// 🔐 Login by id_number + password only
app.post('/login', async (req, res) => {
  try {
    const { id_number, password } = req.body;

    if (!id_number || !password) {
      return res.status(400).json({ success: false, message: 'ID Number and Password are required' });
    }

    const user = await User.findOne({ id_number });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid ID Number' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid Password' });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'Lax',
      maxAge: 60 * 60 * 1000
    });

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        fullName: user.username,
        idNumber: user.id_number,
        county: user.county,
        constituency: user.constituency,
        ward: user.ward,
        hasVoted: user.hasVoted || false
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: `Server error: ${error.message}` });
  }
});

// 🔓 Logout
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true, message: 'Logged out' });
});

// ✅ Get logged-in user info (check authentication status)
app.get('/me', (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return res.status(200).json({ success: true, userId: decoded.id });
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
});


app.listen(5000, () => {
  console.log('🚀 Server running on http://localhost:5000');
});
