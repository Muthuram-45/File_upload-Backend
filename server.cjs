const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const multer = require('multer');
const path = require('path');
// const fs = require('fs');
const csv = require('csv-parser');
const { Parser } = require('json2csv');
const fs = require('fs-extra');
// const path = require('path');
const OpenAI = require("openai");
const axios = require('axios');
const readCSV = require("./utils/readCSV.cjs")

const app = express();
const port = 5000;

require('dotenv').config();

// CommonJS require
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Initialize the OpenAI client
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });


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
app.use(cors());

app.use(cors({
  origin: "http://localhost:5173", // or 3000
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: '50mb' })); // ✅ allow large JSON payloads
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/uploads/processed', express.static(path.join(__dirname, 'uploads/processed')));

// --------------------------------------------------------
// 📁 Ensure folder exists: uploads/API_Files
// --------------------------------------------------------
const uploadDir = path.join(__dirname, "uploads", "API_Files");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}


// =============================
// DATABASE CONNECTION
// =============================
const db = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '8080',
  database: 'file_upload_db',
});


const promiseDb = db.promise();


// db.connect((err) => {
//   if (err) {
//     console.error('❌ MySQL connection failed:', err);
//     process.exit(1);
//   }
//   console.log('✅ Connected to MySQL Database');
// });



// =============================
// MULTER SETUP  (NO CHANGES REMOVED)
// =============================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {

    // 🔥 If front-end sends custom file name => use it
    const customName = req.body.customFileName;

    if (customName) {
      return cb(null, customName + path.extname(file.originalname));
    }

    // Otherwise use your default unique file naming
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

    const token = jwt.sign({ id: user.id, email: user.email }, secret_key, { expiresIn: '24h' });

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
      secret_key,
      { expiresIn: '24h' }
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

    const appToken = jwt.sign({ id: user.id, email: user.email }, secret_key, { expiresIn: '24h' });


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
  try {
    const authHeader = req.headers.authorization;

    console.log("Auth Header received:", authHeader);

    if (!authHeader) {
      return res.status(403).json({ error: "Authorization header missing" });
    }

    if (!authHeader.startsWith("Bearer ")) {
      return res.status(403).json({ error: "Invalid token format" });
    }

    const token = authHeader.split(" ")[1];

    jwt.verify(token, secret_key, (err, user) => {
      if (err) {
        console.log("JWT verify error:", err.message);

        if (err.name === "TokenExpiredError") {
          return res.status(403).json({ error: "Token expired. Please login again." });
        }

        return res.status(403).json({ error: "Invalid token" });
      }

      console.log("✅ User verified:", user);

      req.user = user;   // VERY IMPORTANT
      next();            // continue to /files route
    });

  } catch (error) {
    console.log("Middleware crash:", error.message);
    return res.status(500).json({ error: "Server middleware error" });
  }
}

app.get('/fetch-api', async (req, res) => {
  try {
    const { url } = req.query;
    const token = req.headers.authorization || req.headers["x-api-key"];

    if (!url) {
      return res.status(400).json({ error: "API URL required" });
    }

    const headers = {};
    if (token) {
      // Works for Bearer / API Key / Custom
      headers["Authorization"] = token.startsWith("Bearer")
        ? token
        : `Bearer ${token}`;
      headers["x-api-key"] = token;
    }

    const response = await axios.get(url, { headers });

    return res.json({
      private: false,
      data: response.data
    });

  } catch (err) {
    if (err.response && [401, 403].includes(err.response.status)) {
      return res.status(401).json({
        private: true,
        message: "Private API. Token required"
      });
    }

    return res.status(500).json({ error: "Fetch failed" });
  }
});



// --------------------------------------------------------
// 🔍 API to check duplicate file name
// --------------------------------------------------------
app.get("/check-filename", (req, res) => {
  const fileName = req.query.name;

  db.query(
    "SELECT id FROM api_data WHERE file_name = ?",
    [fileName],
    (err, result) => {
      if (err) return res.json({ exists: false });

      if (result.length > 0) {
        res.json({ exists: true });
      } else {
        res.json({ exists: false });
      }
    }
  );
});

// --------------------------------------------------------
// 💾 Utility: Flatten nested objects for CSV
// --------------------------------------------------------
const flattenObject = (obj, prefix = '') =>
  Object.keys(obj).reduce((acc, k) => {
    const pre = prefix.length ? prefix + '_' : '';
    if (Array.isArray(obj[k])) {
      // Arrays are converted to JSON string
      acc[pre + k] = JSON.stringify(obj[k]);
    } else if (typeof obj[k] === 'object' && obj[k] !== null) {
      Object.assign(acc, flattenObject(obj[k], pre + k));
    } else {
      acc[pre + k] = obj[k];
    }
    return acc;
  }, {});

// --------------------------------------------------------
// 💾 Save API data: Dynamic CSV + Save DB
// --------------------------------------------------------
app.post("/save-api-data", (req, res) => {
  const { api_url, file_name, response, company_name } = req.body;

  if (!response) {
    return res.status(400).json({ success: false, message: "Response is empty" });
  }

  let jsonData;

  try {
    jsonData = typeof response === "string" ? JSON.parse(response) : response;
  } catch (err) {
    return res.status(400).json({ success: false, message: "Invalid JSON" });
  }

  // Wrap single objects into array for consistent processing
  if (!Array.isArray(jsonData)) {
    jsonData = [jsonData];
  }

  // Handle nested arrays inside each object (e.g., "products" in carts)
  const flatData = [];
  jsonData.forEach(item => {
    const arrayKeys = Object.keys(item).filter(key => Array.isArray(item[key]));

    if (arrayKeys.length) {
      // Expand each nested array into multiple rows
      arrayKeys.forEach(arrKey => {
        item[arrKey].forEach(subItem => {
          const row = flattenObject({ ...item, [arrKey]: undefined, ...subItem });
          flatData.push(row);
        });
      });
    } else {
      flatData.push(flattenObject(item));
    }
  });

  if (flatData.length === 0) {
    return res.status(400).json({ success: false, message: "No data to save" });
  }

  // Convert JSON → CSV
  let csv;
  try {
    const fields = Object.keys(flatData[0]);
    const parser = new Parser({ fields });
    csv = parser.parse(flatData);
  } catch (err) {
    console.error("CSV Parse Error:", err);
    return res.status(500).json({ success: false, message: "Failed to convert JSON to CSV" });
  }

  // Save CSV File
  const filePath = path.join(uploadDir, file_name + ".csv");
  try {
    fs.writeFileSync(filePath, csv);
  } catch (err) {
    console.error("File Save Error:", err);
    return res.status(500).json({ success: false, message: "Failed to save CSV file" });
  }

  // Save in database
  const sql = `
    INSERT INTO api_data (api_url, file_name, file_path, response, company_name)
    VALUES (?, ?, ?, ?, ?)
  `;

  db.query(
    sql,
    [api_url, file_name, `uploads/API_Files/${file_name}.csv`, JSON.stringify(response), company_name],
    (err, result) => {
      if (err) {
        console.error("DB Error:", err);
        return res.json({ success: false, message: "DB Error" });
      }

      res.json({
        success: true,
        message: "API Data saved successfully!",
        file_path: `uploads/API_Files/${file_name}.csv`
      });
    }
  );
});

// ======================
// HELPERS
// ======================
const sanitizeName = (name) =>
  name
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "_")
    .replace(/_+/g, "_");

async function createTable(tableName, columns) {
  const columnDefs = columns.map((col) => `\`${col}\` TEXT`).join(", ");
  const sql = `CREATE TABLE IF NOT EXISTS \`${tableName}\` (${columnDefs})`;
  await db.promise().query(sql);
}


async function insertData(tableName, columns, data, batchSize = 1000) {
  const colNames = columns.map((c) => `\`${c}\``).join(",");

  for (let i = 0; i < data.length; i += batchSize) {
    const batch = data.slice(i, i + batchSize);

    const values = batch.map((row) =>
      columns.map((col) =>
        row[col] !== undefined && row[col] !== "" ? row[col] : null
      )
    );

    const placeholders = values
      .map(() => `(${columns.map(() => "?").join(",")})`)
      .join(",");

    const flatValues = values.flat();

    const sql = `
      INSERT INTO \`${tableName}\` (${colNames})
      VALUES ${placeholders}
    `;

    await db.promise().query(sql, flatValues);
  }
}


// ======================
// /upload ROUTE (DUPLICATE → CANCEL)
// ======================
app.post("/upload", upload.array("files"), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ success: false, error: "No files uploaded" });
    }

    const companyName = req.user?.company || null;
    const inputFileName = req.body.name?.trim() || "Uploaded_File";

    // ==================================================
    // SAVE FILES (DUPLICATE = CANCEL)
    // ==================================================
    for (let i = 0; i < req.files.length; i++) {
      const file = req.files[i];

      const finalFileName =
        req.files.length === 1
          ? inputFileName
          : `${inputFileName}_${i + 1}`;

      // 🔍 Check already uploaded (any status)
      const [existing] = await db.promise().query(
        `SELECT id FROM files
         WHERE file_name = ?
         AND company_name <=> ?`,
        [finalFileName, companyName]
      );

      // ✅ Decide status
      const status = existing.length > 0 ? "CANCEL" : "NEW";

      // 💾 Always save in DB
      await db.promise().query(
        `INSERT INTO files (file_name, file_path, company_name, status)
         VALUES (?, ?, ?, ?)`,
        [finalFileName, file.path, companyName, status]
      );
    }

    // ==================================================
    // SINGLE FILE PROCESSING
    // ==================================================
    if (req.files.length === 1 && req.body.process === "true") {
      const file = req.files[0];
      const filePath = path.join(__dirname, "uploads", file.filename);

      const { headers, data } = await readCSV(filePath);
      if (!headers.length) {
        return res.status(400).json({ success: false, error: "Empty CSV" });
      }

      const columns = headers.map(h => sanitizeName(h));
      const normalizedData = data.map(row => {
        const obj = {};
        Object.keys(row).forEach(k => {
          obj[sanitizeName(k)] = row[k];
        });
        return obj;
      });

      const baseTableName = sanitizeName(inputFileName);

      const [existing] = await db.promise().query(
        "SHOW TABLES LIKE ?",
        [baseTableName]
      );

      const isDuplicate = existing.length > 0;

      if (!isDuplicate) {
        await createTable(baseTableName, columns);
        await insertData(baseTableName, columns, normalizedData, 1000);
      }

      await db.promise().query(
        `UPDATE files SET table_name = ?, status = ?
         WHERE file_path = ?`,
        [baseTableName, isDuplicate ? "CANCEL" : "DONE", file.path]
      );

      return res.json({
        success: true,
        message: isDuplicate
          ? "Duplicate file. Marked as CANCEL"
          : "File processed successfully"
      });
    }

    // ==================================================
    // MULTI FILE PROCESSING (UNCHANGED)
    // ==================================================
    // (same as your existing code)

    return res.json({
      success: true,
      message: "Files uploaded",
      uploaded: req.files.length
    });

  } catch (err) {
    console.error("UPLOAD ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});


/// =============================
// GET FILES (Uploaded + API + Processed)
// =============================
app.get("/files", authenticateToken, async (req, res) => {
  try {
    const company = req.user.company_name || null;

    // =============================
    // 1️⃣ UPLOADED FILES
    // =============================
    const uploadedQuery = company
      ? `SELECT 
           id,
           file_name AS name,
           file_path AS path,
           table_name,
           status,
           is_primary
         FROM files
         WHERE company_name = ? OR company_name IS NULL
         ORDER BY id ASC`
      : `SELECT 
           id,
           file_name AS name,
           file_path AS path,
           table_name,
           status,
           is_primary
         FROM files
         WHERE company_name IS NULL
         ORDER BY id ASC`;

    const [uploadedFiles] = await db
      .promise()
      .query(uploadedQuery, company ? [company] : []);

    const uploadedFilesWithSource = uploadedFiles.map(f => ({
      id: `uploaded-${f.id}`,
      name: f.name,
      path: f.path,
      table_name: f.table_name,
      status: f.status,
      is_primary: f.is_primary,
      source: "Uploaded File",
      type: "uploaded"
    }));

    // =============================
    // 2️⃣ API FILES
    // =============================
    const [apiFiles] = await db.promise().query(
      `SELECT id, file_name AS name, file_path AS path FROM api_data`
    );

    const apiFilesWithSource = apiFiles.map(f => ({
      id: `api-${f.id}`,
      name: f.name,
      path: f.path,
      source: "API Data",
      type: "api",
      status: "DONE",
      is_primary: 1
    }));

    // =============================
    // 3️⃣ PROCESSED TABLES
    // =============================
    const [tables] = await db.promise().query(`SHOW TABLES`);

    const processedMap = {};

    tables.forEach(row => {
      const tableName = Object.values(row)[0].toLowerCase();

      if (
        tableName.endsWith("_fulltable") ||
        tableName.endsWith("_entity") ||
        tableName.endsWith("_metrics") ||
        tableName.endsWith("_dimension")
      ) {
        const baseName = tableName.replace(
          /_(fulltable|entity|metrics|dimension)$/,
          ""
        );

        if (!processedMap[baseName]) processedMap[baseName] = [];
        processedMap[baseName].push(tableName);
      }
    });

    const processedFolders = Object.keys(processedMap).map((baseName, idx) => ({
      id: `processed-${idx}`,
      folderName: baseName,
      tables: processedMap[baseName],
      type: "processed",
      status: "DONE"
    }));

    // =============================
    // 4️⃣ STATUS FIX (UPDATED)
    // =============================
    const processedSet = new Set(
      processedFolders.map(p => p.folderName.toLowerCase())
    );

    const getBaseName = (name = "") =>
      name
        .toLowerCase()
        .replace(/\.[^/.]+$/, "")
        .replace(/_v\d+$/, "");

    const allFiles = [
      ...uploadedFilesWithSource,
      ...apiFilesWithSource
    ].map(f => {
      let baseName;

      if (f.path === "MULTI_UPLOAD" && f.table_name) {
        baseName = f.table_name.toLowerCase();
      } else {
        baseName = getBaseName(f.name);
      }

      let finalStatus;

      if (f.status === "CANCEL") {
        finalStatus = "CANCEL";
      }
      else if (processedSet.has(baseName)) {
        finalStatus = "DONE";
      }
      else if (!f.status || f.status === "NEW") {
        finalStatus = "NEW";   // 👈 batch start aagala
      }
      else {
        finalStatus = "PROCESSING";
      }

      return {
        ...f,
        status: finalStatus
      };
    });

    // =============================
    // 5️⃣ RESPONSE
    // =============================
    res.json({
      uploadedFiles: allFiles,
      processedFolders
    });

  } catch (err) {
    console.error("❌ Fetch Files Error:", err);
    res.status(500).json({ error: "Error fetching files" });
  }
});


// =============================
// GET PROCESSED TABLE DATA
// =============================
app.get('/processed-table/:tableName', authenticateToken, async (req, res) => {
  try {
    const tableName = req.params.tableName;

    const [rows] = await db
      .promise()
      .query(`SELECT * FROM \`${tableName}\``);

    res.json({
      tableName,
      rows
    });

  } catch (err) {
    console.error("❌ Fetch Processed Table Error:", err);
    res.status(500).json({
      success: false,
      error: "Error fetching processed table"
    });
  }
});


// =============================
// ✅ OPENAI CHAT API
// =============================
app.post("/api/chat", async (req, res) => {
  try {
    const { question } = req.body;

    if (!question) {
      return res.status(400).json({
        success: false,
        error: "Question is required",
      });
    }

    const response = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: question },
      ],
    });

    res.json({
      success: true,
      answer: response.choices[0].message.content,
    });

  } catch (error) {
    console.error("❌ OpenAI Error:", error.message);
    res.status(500).json({
      success: false,
      error: "AI Server Error ❌",
    });
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

// ------------------------
// NLQ SEARCH ROUTE
// ------------------------
app.post("/nlq-search", async (req, res) => {
  try {
    const { question, tableName } = req.body;

    if (!question || !tableName) {
      return res.status(400).json({ error: "Missing question or tableName" });
    }

    // 1️⃣ Fetch table rows
    const [rows] = await promiseDb.query(`SELECT * FROM \`${tableName}\``);
    if (!rows.length) {
      return res.status(404).json({ error: "Table is empty" });
    }

    // 2️⃣ Convert table to JSON string (simplified for OpenAI)
    const tableText = JSON.stringify(rows.slice(0, 50)); // limit rows to avoid huge prompt

    // 3️⃣ Call OpenAI
    const response = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",  // change from "gpt-4"
      messages: [
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: `Question: ${question}\nTable Data: ${tableText}` },
      ],
      max_tokens: 500,
    });


    // 4️⃣ Extract answer
    const answer = response.choices?.[0]?.message?.content || "No answer";

    // 5️⃣ Return structured JSON
    res.json([{ result: answer }]);
  } catch (err) {
    console.error("❌ NLQ Error FULL:", err);
    res.status(500).json({ error: "NLQ failed" });
  }
});



// =============================
// START SERVER
// =============================

app.listen(port, () => console.log(`🚀 Server running on http://localhost:${port}`));