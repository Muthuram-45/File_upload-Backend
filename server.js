const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const port = 5000;

require('dotenv').config();

// ✅ JWT Secret Key
const secretKey = 'f8a0c1b6d2e9-42ad-9a3f-57b4a0c9e2f'; // 🔥 Add this line

const admin = require('firebase-admin');
const serviceAccount = require('./firebase-service-account.json');

// ✅ Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// =============================
// Middleware
// =============================
app.use(express.json());
app.use(cors());

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/uploads/processed', express.static(path.join(__dirname, 'uploads/processed')));

// =============================
// DATABASE CONNECTION
// =============================
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '8080',
  database: 'file_upload_db',
});

db.connect((err) => {
  if (err) {
    console.error('❌ MySQL connection failed:', err);
    process.exit(1);
  }
  console.log('✅ Connected to MySQL Database');
});

// =============================
// MULTER SETUP
// =============================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true, // use SSL
  auth: {
    user: 'muthuram921@gmail.com',
    pass: 'clkz ubzz dyjq jwdt', // your app password
  },
});


transporter.verify((error, success) => {
  if (error) console.error('❌ Gmail SMTP Error:', error);
  else console.log('✅ Gmail SMTP is ready to send emails');
});
// =============================
// OTP Store (Temporary Memory)
// =============================
let otpStore = {}; // { email: { otp, expires } }

// Clean expired OTPs every 1 minute
setInterval(() => {
  const now = Date.now();
  for (const email in otpStore) {
    if (otpStore[email].expires < now) {
      delete otpStore[email];
    }
  }
}, 60 * 1000);

// =============================
// Helper Function: Generate OTP
// =============================
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
}
// =============================
// SEND OTP Endpoint
// =============================
app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, error: "Email is required" });
    }

    // Generate a new OTP
    const otp = generateOtp();
    otpStore[email] = {
      otp,
      expires: Date.now() + 10 * 60 * 1000, // 10 min expiry
    };

    console.log(`📩 Generated OTP ${otp} for ${email}`);

    // Mail content
    const mailOptions = {
      from: '"Muthu Ram - Verification" <muthuram921@gmail.com>',
      to: email,
      subject: "Your OTP Verification Code",
      html: `
        <div style="font-family: Arial, sans-serif; padding: 15px; background: #f9f9f9;">
          <h2 style="color: #2c3e50;">🔐 Your OTP Code</h2>
          <p style="font-size: 16px;">Use the OTP below to verify your account:</p>
          <h1 style="color: #3498db; letter-spacing: 2px;">${otp}</h1>
          <p>This OTP is valid for <strong>10 minutes</strong>.</p>
          <p>If you did not request this, please ignore this email.</p>
        </div>
      `,
    };

    // Send the mail
    await transporter.sendMail(mailOptions);

    console.log(`✅ OTP email sent successfully to ${email}`);
    return res.json({
      success: true,
      message: "✅ OTP sent successfully to your email",
    });
  } catch (error) {
    console.error("❌ OTP Send Error:", error);

    // Specific error handling
    if (error.response && error.response.includes("Daily user sending quota exceeded")) {
      return res.status(429).json({
        success: false,
        error: "Email sending limit reached. Try again later.",
      });
    }

    return res.status(500).json({
      success: false,
      error: "Failed to send OTP. Please try again later.",
    });
  }
});
// =============================
// VERIFY OTP
// =============================
app.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp)
    return res.status(400).json({ success: false, error: 'Email and OTP required' });

  const record = otpStore[email];
  if (!record) return res.status(400).json({ success: false, error: 'OTP not sent or expired' });
  if (Date.now() > record.expires) return res.status(400).json({ success: false, error: 'OTP expired' });

  if (String(record.otp) !== String(otp))
    return res.status(400).json({ success: false, error: 'Invalid OTP' });

  delete otpStore[email];
  res.json({ success: true, message: '✅ OTP verified successfully' });
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

app.post('/company-register', async (req, res) => {
  try {
    const { firstName, lastName, email, mobile, password, company_name } = req.body;
    if (!email || !password || !company_name)
      return res.status(400).json({ success: false, error: 'All fields required' });

    const [existing] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
    if (existing.length > 0)
      return res.status(400).json({ success: false, error: 'Company already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await db
      .promise()
      .query(
        'INSERT INTO users (first_name, last_name, email, mobile, password, company_name) VALUES (?, ?, ?, ?, ?, ?)',
        [firstName, lastName, email, mobile || '', hashedPassword, company_name]
      );

    res.json({ success: true, message: '✅ Company registered successfully' });
  } catch (err) {
    console.error('❌ Company Register Error:', err);
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
    if (!email)
      return res.status(400).json({ success: false, error: 'Email required' });

    const [rows] = await db
      .promise()
      .query(
        `SELECT 
          first_name AS firstName, 
          last_name AS lastName, 
          email, 
          mobile, 
          company_name AS company_name
        FROM users 
        WHERE email = ?`,
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
}// =============================
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
// GET FILES (Uploaded + Processed from DB)
// =============================
app.get('/files', authenticateToken, async (req, res) => {
  try {
    const company = req.user.company_name || null;

    // ---- Uploaded files from DB ----
    let uploadedQuery, values;
    if (company) {
      uploadedQuery = `
        SELECT id, file_name AS name, file_path AS path, 'uploaded' AS type
        FROM files
        WHERE company_name = ? OR company_name IS NULL
        ORDER BY id DESC
      `;
      values = [company];
    } else {
      uploadedQuery = `
        SELECT id, file_name AS name, file_path AS path, 'uploaded' AS type
        FROM files
        WHERE company_name IS NULL
        ORDER BY id DESC
      `;
      values = [];
    }
    const [uploadedFiles] = await db.promise().query(uploadedQuery, values);

    // ---- Processed folders from DB ----
    const [folders] = await db.promise().query(
      'SELECT id, folder_name, folder_path, tables_json FROM processed_files ORDER BY id DESC'
    );

    const processedFolders = folders.map(f => {
      let tables = {};
      try {
        tables = f.tables_json ? JSON.parse(f.tables_json) : {};
      } catch (e) {
        console.error('❌ Error parsing tables_json for folder', f.folder_name, e);
      }

      return {
        id: f.id,
        folderName: f.folder_name,       // folder name = raw uploaded file name
        folderPath: f.folder_path,
        tables,
        csvCount: Object.keys(tables).length,
        type: 'processed',
      };
    });

    res.json({ uploadedFiles, processedFolders });
  } catch (err) {
    console.error('❌ Fetch Files Error:', err);
    res.status(500).json({ success: false, error: 'Error fetching files' });
  }
});

// =============================
// GET CSV files inside a processed folder by folder ID
// =============================
app.get('/processed-folder/:id', authenticateToken, async (req, res) => {
  try {
    const folderId = req.params.id;

    const [folders] = await db.promise().query(
      'SELECT * FROM processed_files WHERE id = ?',
      [folderId]
    );

    if (!folders.length) return res.status(404).json({ error: 'Folder not found' });

    const folder = folders[0];
    const folderPath = folder.folder_path;

    if (!fs.existsSync(folderPath)) return res.status(404).json({ error: 'Folder path does not exist' });

    const files = fs.readdirSync(folderPath)
      .filter(f => f.endsWith('.csv'))
      .map(f => ({
        name: f,
        path: `/uploads/processed/${path.basename(folderPath)}/${f}` // Adjust URL path if needed
      }));

    res.json({ folder: { id: folder.id, folderName: folder.folder_name, files } });

  } catch (err) {
    console.error('❌ Fetch Processed Folder Error:', err);
    res.status(500).json({ success: false, error: 'Error fetching processed folder' });
  }
});


// =============================
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

app.listen(port, () => console.log(`🚀 Server running on http://localhost:${port}`));