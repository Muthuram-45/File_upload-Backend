const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const OpenAI = require("openai"); 

const app = express();
const port = 5000;

require('dotenv').config();

   // CommonJS require

// Initialize the OpenAI client
const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// ✅ JWT Secret Key
const secret_key = 'f8a0c1b6d2e9-42ad-9a3f-57b4a0c9e2f'; // 🔥 Add this line

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

    const now = new Date();

    // ✅ UPDATE LAST LOGIN
    await db.promise().query('UPDATE users SET last_login = ? WHERE id = ?', [now, user.id]);

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
        lastLogin: now,
      },
    });
  } catch (err) {
    console.error('❌ Login Error:', err);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

// =============================
// COMPANY LOGIN
// =============================
app.post('/company-login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, error: 'Email and password required' });

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

    const now = new Date();

    // ✅ UPDATE LAST LOGIN
    await db.promise().query('UPDATE users SET last_login = ? WHERE id = ?', [now, user.id]);

    const token = jwt.sign(
      { id: user.id, email: user.email, company_name: user.company_name, mobile: user.mobile },
      'secret_key',
      { expiresIn: '1h' }
    );

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
        lastLogin: now,
      },
    });
  } catch (err) {
    console.error('❌ Company Login Error:', err);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

// =============================
// GOOGLE LOGIN
// =============================
app.post('/google-login', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token)
      return res.status(400).json({ success: false, error: 'Token required' });

    const decoded = await admin.auth().verifyIdToken(token);
    const email = decoded.email;
    const fullName = decoded.name || '';
    const [firstName, lastName = ''] = fullName.split(' ');
    const picture = decoded.picture || '';

    console.log(`🧾 Google Sign-In Request Received for: ${email}`);

    const [existing] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);

    let user;
    if (existing.length === 0) {
      console.log(`🆕 New Google user detected: ${email}. Creating account...`);
      await db
        .promise()
        .query(
          'INSERT INTO users (first_name, last_name, email, mobile, password, last_login) VALUES (?, ?, ?, ?, ?, ?)',
          [firstName, lastName, email, '', '', new Date()]
        );
      const [newUser] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
      user = newUser[0];
    } else {
      user = existing[0];
      console.log(`✅ Existing Google user found: ${email}`);
      // ✅ UPDATE LAST LOGIN
      await db.promise().query('UPDATE users SET last_login = ? WHERE id = ?', [new Date(), user.id]);
    }

    const appToken = jwt.sign({ id: user.id, email: user.email }, 'secret_key', { expiresIn: '1h' });

    res.json({
      success: true,
      message: '✅ Google Sign-In successful',
      token: appToken,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        picture,
        lastLogin: new Date(),
      },
    });
  } catch (err) {
    console.error('❌ Google Login Error:', err);
    res.status(400).json({ success: false, error: 'Invalid or expired Firebase token' });
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
          company_name AS company_name,
          last_login AS lastLogin
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

// In-memory cache for repeated queries (optional)
const queryCache = {};

// POST /ask-ai
app.post('/ask-ai', authenticateToken, async (req, res) => {
  try {
    const { folderId, query } = req.body;

    if (!folderId || !query) {
      return res.status(400).json({ success: false, error: "folderId and query required" });
    }

    // Check cache first
    if (queryCache[folderId]?.[query]) {
      console.log("Returning cached response for this query");
      return res.json(queryCache[folderId][query]);
    }

    // 1️⃣ Get folder info from DB
    const [folderRows] = await db.promise().query(
      "SELECT folder_name, folder_path FROM processed_files WHERE id = ?",
      [folderId]
    );

    if (!folderRows.length) {
      return res.status(404).json({ success: false, error: "Folder not found" });
    }

    const { folder_path } = folderRows[0];
    if (!fs.existsSync(folder_path)) {
      return res.status(404).json({ success: false, error: "Folder path does not exist" });
    }

    // 2️⃣ Select the largest CSV file
    const fileNames = fs.readdirSync(folder_path);
    const csvFiles = fileNames.filter(f => f.endsWith(".csv"));
    if (!csvFiles.length) {
      return res.json({ summary: "No CSV files found in this folder.", rows: [] });
    }

    let largestFile = "";
    let largestSize = 0;
    for (const file of csvFiles) {
      const stats = fs.statSync(path.join(folder_path, file));
      if (stats.size > largestSize) {
        largestSize = stats.size;
        largestFile = file;
      }
    }

    const largestPath = path.join(folder_path, largestFile);
    let csvContent = fs.readFileSync(largestPath, "utf8");

    // 3️⃣ Sample CSV rows to avoid sending huge data
    function sampleCsvRows(csvText, maxRows = 100) {
      const lines = csvText.split(/\r?\n/);
      if (lines.length <= maxRows + 1) return csvText; // include header
      const headers = lines[0];
      const rows = lines.slice(1, maxRows + 1);
      return [headers, ...rows].join("\n");
    }
    const combinedData = sampleCsvRows(csvContent);

    // 4️⃣ Send data + query to OpenAI
    let aiResponse;
    const models = ["gpt-4o-mini", "gpt-3.5-turbo"];
    for (const model of models) {
      try {
        aiResponse = await client.chat.completions.create({
          model,
          temperature: 0.1,
          messages: [
            {
              role: "system",
              content: `
You are a data analysis engine.
Return JSON in this exact format:
{
  "summary": "AI text summary",
  "rows": [
    { "Column1": value, "Column2": value },
    ...
  ]
}
Rules:
- Only return rows relevant to the question.
- Use numeric values when possible.
- summary is plain text.
`
            },
            {
              role: "user",
              content: `DATA:\n${combinedData}\nQUESTION: ${query}`
            }
          ]
        });
        break;
      } catch (err) {
        console.error(`OpenAI error with model ${model}:`, err.response?.data || err.message);
        if (model === models[models.length - 1]) {
          return res.status(500).json({
            success: false,
            error: "OpenAI request failed",
            details: err.response?.data || err.message
          });
        }
      }
    }

    const text = aiResponse.choices[0]?.message?.content;

    // 5️⃣ Safe JSON parsing
    function safeJsonParse(text) {
      try {
        return JSON.parse(text);
      } catch {
        const fixed = text.replace(/(\r\n|\n|\r)/gm, '').replace(/'/g, '"');
        try {
          return JSON.parse(fixed);
        } catch {
          return null;
        }
      }
    }

    const parsed = safeJsonParse(text) || { summary: "No result returned", rows: [] };

    // 6️⃣ Save in cache
    queryCache[folderId] = queryCache[folderId] || {};
    queryCache[folderId][query] = parsed;

    res.json(parsed);

  } catch (err) {
    console.error("Unexpected server error:", err.message, err.stack);
    res.status(500).json({ success: false, error: "Server error" });
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