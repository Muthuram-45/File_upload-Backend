import mysql from 'mysql2';
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');

const app = express();
const port = process.env.PORT || 5000;


dotenv.config();


const admin = require('firebase-admin');


let serviceAccount;

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  } catch (err) {
    console.error("🔥 Invalid FIREBASE_SERVICE_ACCOUNT JSON:", err);
  }
} else {
  serviceAccount = require('./firebase-service-account.json');
}


// ✅ Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// =============================
// Middleware
// =============================
app.use(express.json());
app.use(cors());

// =============================
// MySQL Connection
// =============================
const db = mysql.createPool({
    host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl:{
    rejectUnauthorized:false
  }
});

db.connect((err) => {
  if (err) {
    console.error('❌ MySQL connection failed:', err);
    process.exit(1);
  }
  console.log('✅ Connected to MySQL Database');
});

app.get("/", (req, res) => {
  res.send("✅ Backend is live!");
});


// =============================
// Multer (for File Upload)
// =============================
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) =>
    cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_')),
});
const upload = multer({ storage });
app.use('/uploads', express.static(uploadDir));

// =============================
// EMAIL (OTP) SETUP
// =============================

const otpStore = {}; // ✅ Make sure this is globally accessible (above all routes)

// 🔹 Use your Gmail App Password (not your real Gmail password)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
     user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, // ⚠️ Replace with your Gmail App Password
  },
});

// 🔹 OTP Generator Function
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
}

// =============================
// SEND OTP
// =============================
app.post('/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res.status(400).json({ success: false, error: 'Email is required' });

    const otp = generateOtp();
    otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 }; // 5 min expiry

    const mailOptions = {
      from: 'muthuram921@gmail.com',
      to: email,
      subject: 'Your OTP Verification Code',
      html: `
        <div style="font-family:sans-serif;">
          <h3>Your OTP is:</h3>
          <h1 style="color:#2E86C1;">${otp}</h1>
          <p>This OTP is valid for 5 minutes.</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    console.log(`✅ OTP ${otp} sent to ${email}`);
    res.json({ success: true, message: 'OTP sent successfully to Gmail' });
  } catch (err) {
    console.error('❌ Error sending OTP:', err.message);
    res.status(500).json({ success: false, error: 'Failed to send OTP. Please try again.' });
  }
});

// =============================
// VERIFY OTP
// =============================
app.post('/verify-otp', (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp)
      return res.status(400).json({ success: false, error: 'Email and OTP required' });

    const record = otpStore[email];
    if (!record)
      return res.status(400).json({ success: false, error: 'OTP not sent or expired' });

    if (Date.now() > record.expires)
      return res.status(400).json({ success: false, error: 'OTP expired' });

    if (String(record.otp) !== String(otp))
      return res.status(400).json({ success: false, error: 'Invalid OTP' });

    delete otpStore[email];
    console.log(`✅ OTP verified for ${email}`);
    res.json({ success: true, message: 'OTP verified successfully' });
  } catch (err) {
    console.error('❌ OTP Verification Error:', err.message);
    res.status(500).json({ success: false, error: 'Server error during OTP verification' });
  }
});

// =============================
// REGISTER USER
// =============================
app.post('/register', async (req, res) => {
  try {
    const { firstName, lastName, email, mobile, password, company_name } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, error: 'Email and password required' });

    const [existing] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
    if (existing.length > 0)
      return res.status(400).json({ success: false, error: 'User already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await db
      .promise()
      .query(
        'INSERT INTO users (first_name, last_name, email, mobile, password, company_name) VALUES (?, ?, ?, ?, ?, ?)',
        [firstName, lastName, email, mobile || '', hashedPassword, company_name || null]
      );

    res.json({ success: true, message: '✅ User registered successfully' });
  } catch (err) {
    console.error('❌ Register Error:', err);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

// =============================
// NORMAL LOGIN (NO COMPANY)
// =============================
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, error: 'Email and password required' });

    const [rows] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0)
      return res.status(400).json({ success: false, error: 'Invalid credentials' });

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ success: false, error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email }, 'secret_key', { expiresIn: '1h' });

    res.json({
      success: true,
      message: '✅ Login successful',
      token,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        mobile: user.mobile,
      },
    });
  } catch (err) {
    console.error('❌ Login Error:', err);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

app.post('/company-login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, error: 'Email and password required' });

    // ✅ Fetch mobile also
    const [rows] = await db
      .promise()
      .query(
        'SELECT id, first_name, last_name, email, password, company_name, mobile FROM users WHERE email = ?',
        [email]
      );

    if (rows.length === 0)
      return res.status(400).json({ success: false, error: 'Invalid credentials' });

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ success: false, error: 'Invalid password' });

    // ✅ Include mobile in token too
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        company_name: user.company_name,
        mobile: user.mobile,
      },
      'secret_key',
      { expiresIn: '1h' }
    );

    // ✅ Return all necessary fields, including mobile
    res.json({
      success: true,
      message: '✅ Company login successful',
      token,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        company_name: user.company_name,
        mobile: user.mobile,
      },
    });
  } catch (err) {
    console.error('❌ Company Login Error:', err);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});
const { google } = require('googleapis');

// ✅ GOOGLE LOGIN (Updated with Authority Logging)
// =============================
app.post('/google-login', async (req, res) => {
  try {
    const { token } = req.body; // ✅ renamed to token (simpler)
    if (!token)
      return res.status(400).json({ success: false, error: 'Token required' });

    // ✅ Step 1: Verify Firebase token
    const decoded = await admin.auth().verifyIdToken(token);
    const email = decoded.email;
    const fullName = decoded.name || '';
    const [firstName, lastName = ''] = fullName.split(' ');
    const picture = decoded.picture || '';

    console.log(`🧾 Google Sign-In Request Received for: ${email}`);

    // ✅ Step 2: Check if the user exists in MySQL
    const [existing] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);

    let user;
    if (existing.length === 0) {
      console.log(`🆕 New Google user detected: ${email}. Creating account...`);
      await db
        .promise()
        .query(
          'INSERT INTO users (first_name, last_name, email, mobile, password) VALUES (?, ?, ?, ?, ?)',
          [firstName, lastName, email, '', '']
        );
      const [newUser] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
      user = newUser[0];
    } else {
      user = existing[0];
      console.log(`✅ Existing Google user found: ${email}`);
    }

    // ✅ Step 3: Generate JWT Token
    const appToken = jwt.sign({ id: user.id, email: user.email }, 'secret_key', { expiresIn: '1h' });

    // ✅ Step 4: Send response
    return res.json({
      success: true,
      message: '✅ Google Sign-In successful',
      token: appToken,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        picture,
      },
    });
  } catch (err) {
    console.error('❌ Google Login Error:', err);
    return res.status(400).json({ success: false, error: 'Invalid or expired Firebase token' });
  }
});


// =============================
// FETCH USER PROFILE (Latest from DB)
// =============================
app.get('/user/:email', async (req, res) => {
  try {
    const { email } = req.params;
    if (!email) return res.status(400).json({ success: false, error: 'Email required' });

    const [rows] = await db.promise().query(
      'SELECT first_name AS firstName, last_name AS lastName, email, mobile FROM users WHERE email = ?',
      [email]
    );

    if (rows.length === 0)
      return res.status(404).json({ success: false, error: 'User not found' });

    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error('❌ Fetch User Error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});


// =============================
// AUTH MIDDLEWARE
// =============================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// =============================
// FILE UPLOAD (Company + Normal Users)
// =============================
app.post('/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    const { name } = req.body;
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file uploaded' });
    }

    // ✅ Extract company name from logged-in user (token)
    const company = req.user.company_name || null;

    // File path
    const filePath = `/uploads/${req.file.filename}`;

    // Save in DB
    await db
      .promise()
      .query(
        'INSERT INTO files (file_name, file_path, company_name) VALUES (?, ?, ?)',
        [name || req.file.originalname, filePath, company]
      );

    res.json({
      success: true,
      message: '✅ File uploaded successfully',
      file: { name, path: filePath, company },
    });
  } catch (err) {
    console.error('❌ Upload Error:', err);
    res.status(500).json({ success: false, error: 'File upload failed' });
  }
});

// =============================
// GET FILES (Company + Public Files)
// =============================
app.get('/files', authenticateToken, async (req, res) => {
  try {
    const company = req.user.company_name || null;
    let query, values;

    if (company) {
      // ✅ Company user sees both their files and public files
      query = `
        SELECT file_name AS name, file_path AS path 
        FROM files 
        WHERE company_name = ? OR company_name IS NULL 
        ORDER BY id DESC
      `;
      values = [company];
    } else {
      // ✅ Normal user → only public files
      query = `
        SELECT file_name AS name, file_path AS path 
        FROM files 
        WHERE company_name IS NULL 
        ORDER BY id DESC
      `;
      values = [];
    }

    const [files] = await db.promise().query(query, values);
    res.json(files);
  } catch (err) {
    console.error('❌ Fetch Files Error:', err);
    res.status(500).json({ success: false, error: 'Error fetching files' });
  }
});



/// =============================
// UPDATE USER PROFILE (Supports Password)
// =============================
app.put('/update-profile', async (req, res) => {
  try {
    const { email, firstName, lastName, mobile, password } = req.body;

    if (!email)
      return res.status(400).json({ success: false, error: 'Email is required' });

    const [existing] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);

    // ✅ If user doesn’t exist — create a new one
    if (existing.length === 0) {
      const hashedPassword = password ? await bcrypt.hash(password, 10) : '';
      await db
        .promise()
        .query(
          'INSERT INTO users (first_name, last_name, email, mobile, password) VALUES (?, ?, ?, ?, ?)',
          [firstName || '', lastName || '', email, mobile || '', hashedPassword]
        );
      return res.json({ success: true, message: '✅ New Google user added successfully' });
    }

    // ✅ If password is provided — update it securely
    if (password && password.trim() !== '') {
      const hashedPassword = await bcrypt.hash(password, 10);
      await db
        .promise()
        .query(
          'UPDATE users SET first_name = ?, last_name = ?, mobile = ?, password = ? WHERE email = ?',
          [firstName || '', lastName || '', mobile || '', hashedPassword, email]
        );
    } else {
      await db
        .promise()
        .query(
          'UPDATE users SET first_name = ?, last_name = ?, mobile = ? WHERE email = ?',
          [firstName || '', lastName || '', mobile || '', email]
        );
    }

    res.json({ success: true, message: '✅ Profile updated successfully' });
  } catch (err) {
    console.error('❌ Update Profile Error:', err);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

// =============================
// FORGOT PASSWORD (Reset Password via Email)
// =============================
app.post('/forgot-password', async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({ success: false, error: 'Email and new password required' });
    }

    // ✅ Check if user exists
    const [users] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(400).json({ success: false, error: 'User not found' });
    }

    // ✅ Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // ✅ Update the user’s password in the database
    await db
      .promise()
      .query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);

    console.log(`🔐 Password updated for ${email}`);
    return res.json({ success: true, message: '✅ Password updated successfully' });
  } catch (err) {
    console.error('❌ Forgot Password Error:', err);
    return res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

// =============================
// CHANGE PASSWORD (For Logged-In Users)
// =============================
app.post('/change-password', async (req, res) => {
  try {
    const { email, oldPassword, newPassword } = req.body;

    if (!email || !oldPassword || !newPassword) {
      return res
        .status(400)
        .json({ success: false, error: 'Email, old password, and new password are required' });
    }

    // ✅ Find user
    const [users] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(400).json({ success: false, error: 'User not found' });
    }

    const user = users[0];

    // ✅ Verify old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, error: 'Old password is incorrect' });
    }

    // ✅ Hash new password and update
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db
      .promise()
      .query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);

    console.log(`🔐 Password changed successfully for ${email}`);
    return res.json({ success: true, message: '✅ Password changed successfully' });
  } catch (err) {
    console.error('❌ Change Password Error:', err);
    return res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

app.put('/change-name', async (req, res) => {
  try {
    const { email, firstName, lastName } = req.body;
    await db.promise().query(
      'UPDATE users SET first_name = ?, last_Name = ? WHERE email = ?',
      [firstName, lastName, email]
    );
    res.json({ success: true, message: '✅ Name updated successfully' });
  } catch (err) {
    console.error('❌ Change Name Error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});



// =============================
// CHANGE MOBILE
// =============================
app.put('/change-mobile', async (req, res) => {
  try {
    const { email, mobile } = req.body;
    if (!email || !mobile) {
      return res.status(400).json({ success: false, error: 'Email and mobile required' });
    }

    await db.promise().query('UPDATE users SET mobile = ? WHERE email = ?', [mobile, email]);
    return res.json({ success: true, message: '✅ Mobile updated successfully' });
  } catch (err) {
    console.error('❌ Change Mobile Error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});


// =============================
// START SERVER
// =============================
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
