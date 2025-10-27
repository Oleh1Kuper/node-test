const express = require('express');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({ 
  credentials: true, 
  origin: process.env.CLIENT_BASE_URL, // e.g., https://yourapp.vercel.app
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
}));

console.log(process.env.CLIENT_BASE_URL);

// Configuration
const ACCESS_TOKEN_SECRET = 'your-access-token-secret-key';
const REFRESH_TOKEN_SECRET = 'your-refresh-token-secret-key';
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';

const users = [];

const sendTokenCookies = (res, accessToken, refreshToken) => {
  const cookieOptions = {
    httpOnly: true,
    sameSite: 'none', // or 'none' with secure:true in production
    secure: true, // set true if using HTTPS
    domain: '.123domain.shop',
  };

  // Access token expires quickly
  res.cookie('accessToken', accessToken, {
    ...cookieOptions,
    maxAge: 15 * 60 * 1000, // 15 minutes
  });

  // Refresh token lasts longer
  res.cookie('refreshToken', refreshToken, {
    ...cookieOptions,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
};

// Helper function to generate tokens
const generateTokens = (user) => {
  const accessToken = jwt.sign({ user }, ACCESS_TOKEN_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY
  });
  
  const refreshToken = jwt.sign({ user }, REFRESH_TOKEN_SECRET, {
    expiresIn: REFRESH_TOKEN_EXPIRY
  });
  
  return { accessToken, refreshToken };
};

// Auth Middleware
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    const token1 = req.cookies?.accessToken;
  console.log(token1, 'token from cookies');
  console.log(token, 'token from header');
  
  if (!token1) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  jwt.verify(token1, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// PUBLIC ROUTES

// Sign up
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    // Check if user already exists
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = {
      id: users.length + 1,
      username,
      password: hashedPassword
    };
    users.push(user);
    
    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);
    
    res.status(201).json({
      message: 'User created successfully',
      accessToken,
      refreshToken
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    // Find user
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);
    sendTokenCookies(res, accessToken, refreshToken);
    
    res.json({
      message: 'Login successful',
      // accessToken,
      // refreshToken
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Refresh token
app.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token required' });
  }
  
  jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }
    
    const { accessToken } = generateTokens(user);
    res.json({ accessToken });
  });
});

app.get('/api/data', authMiddleware, (req, res) => {
  const dummyData = {
    userId: req.user.userId,
    data: [
      { id: 1, title: 'Item 1', description: 'First dummy item' },
      { id: 2, title: 'Item 2', description: 'Second dummy item' },
      { id: 3, title: 'Item 3', description: 'Third dummy item' }
    ],
    timestamp: new Date().toISOString()
  };
  
  res.json(dummyData);
});

// Get user profile (protected)
app.get('/api/profile', authMiddleware, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  res.json({
    id: user.id,
    username: user.username
  });
});

// Start server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
