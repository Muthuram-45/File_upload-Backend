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
const { CohereClient } = require("cohere-ai");
const cron = require("node-cron");
const crypto = require("crypto");
const PDFDocument = require("pdfkit");

function formatMySQLDate(dateString) {
  if (!dateString) return null;
  const date = new Date(dateString);
  if (isNaN(date.getTime())) return null;
  return date.toISOString().slice(0, 19).replace('T', ' ');
}


const app = express();
const port = process.env.PORT || 4000;

require('dotenv').config();

function stableHash(data) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(sortObject(data)))
    .digest("hex");
}

function sortObject(obj) {
  if (Array.isArray(obj)) return obj.map(sortObject);
  if (obj !== null && typeof obj === "object") {
    return Object.keys(obj)
      .sort()
      .reduce((acc, k) => {
        acc[k] = sortObject(obj[k]);
        return acc;
      }, {});
  }
  return obj;
}


// FOR Files_run_Stats

async function insertFileRunStat({
  file_name,
  company_name,
  uploaded_by,
  rows_count = 0,
  status = "DONE"
}) {
  await db.promise().query(`
    INSERT INTO file_run_stats
    (file_name, company_name, uploaded_by,
     processed_at, rows_count, status)
    VALUES (?, ?, ?, NOW(), ?, ?)
  `, [
    file_name,
    company_name,
    uploaded_by,
    rows_count,
    status
  ]);
}

// chat bot  Groq ai
const Groq = require("groq-sdk");
const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

// CommonJS require
// const client = new OpenAI({
//   apiKey: process.env.OPENAI_API_KEY,
// });

// CommonJS require for GROQAI

const GROQ_KEY = process.env.GROQ_API_KEY;

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
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = ["http://localhost:5173", "http://localhost:5174"];
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization", "Authorization-External", "x-api-key"],
  credentials: true
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

// =============================
// DATABASE MIGRATION (SUBSCRIPTION)
// =============================
(async () => {
  try {
    const [columns] = await db.promise().query("SHOW COLUMNS FROM users");
    const columnNames = columns.map(c => c.Field);

    if (!columnNames.includes('subscription_plan')) {
      await db.promise().query("ALTER TABLE users ADD COLUMN subscription_plan VARCHAR(50) DEFAULT 'Trial'");
      console.log("✅ Added subscription_plan column");
    }
    if (!columnNames.includes('subscription_expiry')) {
      // Default trial: 3 days from registration. For existing users, we'll give them 3 days from now.
      await db.promise().query("ALTER TABLE users ADD COLUMN subscription_expiry DATETIME");
      await db.promise().query("UPDATE users SET subscription_expiry = DATE_ADD(NOW(), INTERVAL 3 DAY) WHERE subscription_expiry IS NULL");
      console.log("✅ Added subscription_expiry column");
    }
    if (!columnNames.includes('activation_key')) {
      await db.promise().query("ALTER TABLE users ADD COLUMN activation_key VARCHAR(100)");
      console.log("✅ Added activation_key column");
    }

    // Ensure status column can hold new values
    await db.promise().query("ALTER TABLE users MODIFY COLUMN status VARCHAR(50) DEFAULT 'ACTIVE'");
    console.log("✅ Updated status column to VARCHAR(50)");
  } catch (err) {
    console.error("❌ Migration Error:", err);
  }
})();


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
    let { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: "Email is required"
      });
    }

    // ✅ normalize email
    email = email.trim().toLowerCase();

    // 🔍 CHECK IF USER ALREADY REGISTERED
    const [existing] = await db.promise().query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (existing.length > 0) {
      return res.status(409).json({
        success: false,
        error: "User already registered"
      });
    }

    // 🔐 Generate OTP
    const otp = generateOtp();

    otpStore[email] = {
      otp,
      expires: Date.now() + 10 * 60 * 1000 // 10 mins
    };

    console.log(`📩 OTP ${otp} generated for ${email}`);

    await transporter.sendMail({
      from: '"Cloud360 Verification" <muthuram921@gmail.com>',
      to: email,
      subject: "Your OTP Verification Code",
      html: `<h2>${otp}</h2><p>OTP valid for 10 minutes</p>`
    });

    res.json({
      success: true,
      message: "OTP sent successfully"
    });

  } catch (err) {
    console.error("❌ OTP Error:", err);
    res.status(500).json({
      success: false,
      error: "Failed to send OTP"
    });
  }
});

// =============================
// VERIFY OTP
// =============================
app.post("/verify-otp", (req, res) => {
  let { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({
      success: false,
      error: "Email and OTP required"
    });
  }

  // ✅ NORMALIZE EMAIL
  email = email.trim().toLowerCase();
  otp = otp.trim();

  const record = otpStore[email];

  if (!record) {
    return res.status(400).json({
      success: false,
      error: "OTP not sent or expired"
    });
  }

  if (Date.now() > record.expires) {
    delete otpStore[email];
    return res.status(400).json({
      success: false,
      error: "OTP expired"
    });
  }

  if (String(record.otp) !== String(otp)) {
    return res.status(400).json({
      success: false,
      error: "Invalid OTP"
    });
  }

  delete otpStore[email];

  res.json({
    success: true,
    message: "OTP verified"
  });
});


// gmail detect

function detectRoleAndCompany(email) {
  const [prefix, domain] = email.toLowerCase().split("@");

  if (["gmail.com", "yahoo.com", "outlook.com"].includes(domain)) {
    return {
      role: "personal",
      company_name: null
    };
  }

  const companyName = domain.split(".")[0];

  if (prefix === "manager" || prefix === "admin") {
    return {
      role: "manager",
      company_name: companyName
    };
  }

  return {
    role: "employee",
    company_name: companyName
  };
}



// =============================
// REGISTER USER
// =============================
app.post('/register', async (req, res) => {
  try {
    const { firstName, lastName, email, mobile, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password required'
      });
    }

    // ✅ Normalize email
    const normalizedEmail = email.trim().toLowerCase();

    // 🚫 BLOCK COMPANY EMAILS FOR NORMAL REGISTER
    const allowedDomains = ['gmail.com', 'yahoo.com', 'outlook.com'];
    const emailDomain = normalizedEmail.split('@')[1];

    if (!allowedDomains.includes(emailDomain)) {
      return res.status(400).json({
        success: false,
        error: 'Only Gmail, Yahoo, or Outlook emails are allowed for personal registration'
      });
    }

    // 🔍 Check existing user
    const [existing] = await db.promise().query(
      'SELECT id FROM users WHERE email = ?',
      [normalizedEmail]
    );

    if (existing.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'User already registered'
      });
    }

    // 🔐 Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 🔥 FORCE PERSONAL USER
    const role = 'personal';
    const company_name = null;
    const status = 'ACTIVE';

    // 💾 INSERT USER
    const [result] = await db.promise().query(
      `INSERT INTO users
       (first_name, last_name, email, mobile, password, company_name, role, status, report_hour, report_minute, timezone, subscription_plan, subscription_expiry)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Trial', DATE_ADD(NOW(), INTERVAL 3 DAY))`,
      [
        firstName,
        lastName,
        normalizedEmail,
        mobile || '',
        hashedPassword,
        company_name,
        role,
        status,
        9, // report_hour
        0, // report_minute
        'Asia/Kolkata' // default timezone
      ]
    );

    const userId = result.insertId;

    // 🔄 Sync with Admin Server
    try {
      await axios.post(`${process.env.ADMIN_SERVER_URL}/api/users`, {
        id: userId,
        firstname: firstName,
        lastname: lastName,
        email: normalizedEmail,
        contact: mobile || '',
        password: password, // Store password in admin if needed, or hash
        user_type: 'client',
        plan: 'Trial',
        valid_until: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        category: 'individual',
        company_name: null
      }, {
        headers: { 'x-api-key': process.env.API_BRIDGE_KEY }
      });
      console.log(`✅ Synced ${normalizedEmail} (ID: ${userId}) to Admin server`);
    } catch (syncErr) {
      console.error(`⚠️ Sync to Admin failed for ${normalizedEmail}:`, syncErr.message);
      // We don't fail the registration if sync fails, but we log it
    }

    res.json({
      success: true,
      message: '✅ User registered successfully',
      role,
      company_name
    });

  } catch (err) {
    console.error('❌ Register Error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal Server Error'
    });
  }
});

app.post('/company-register', async (req, res) => {
  try {
    const { firstName, lastName, email, mobile, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password required'
      });
    }

    // ✅ Normalize email
    const normalizedEmail = email.trim().toLowerCase();

    // 🔍 Check if email already exists
    const [existing] = await db
      .promise()
      .query('SELECT id FROM users WHERE email = ?', [normalizedEmail]);

    if (existing.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'User already registered. Please login.'
      });
    }

    // 🔐 Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // ✅ USE YOUR EXISTING ROLE DETECTOR
    const { role, company_name } = detectRoleAndCompany(email);

    // 🔥 STATUS RULE (THIS IS NEW)
    const status = role === 'employee' ? 'PENDING' : 'ACTIVE';

    // 💾 INSERT USER
    const [result] = await db.promise().query(
      `INSERT INTO users
       (first_name, last_name, email, mobile, password, company_name, role, status, report_hour, report_minute, timezone, subscription_plan, subscription_expiry)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Trial', DATE_ADD(NOW(), INTERVAL 3 DAY))`,
      [
        firstName,
        lastName,
        normalizedEmail, // Changed from email to normalizedEmail for consistency
        mobile || '',
        hashedPassword,
        company_name,
        role,
        status,
        9, // report_hour
        0, // report_minute
        'Asia/Kolkata' // default timezone
      ]
    );

    const userId = result.insertId;

    // 🔄 Sync with Admin Server
    try {
      await axios.post(`${process.env.ADMIN_SERVER_URL}/api/users`, {
        id: userId,
        firstname: firstName,
        lastname: lastName,
        email: normalizedEmail,
        contact: mobile || '',
        password: password,
        user_type: role === 'manager' ? 'admin' : 'client',
        plan: 'Trial',
        valid_until: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        category: 'company',
        company_name: company_name
      }, {
        headers: { 'x-api-key': process.env.API_BRIDGE_KEY }
      });
      console.log(`✅ Synced corporate user ${normalizedEmail} (ID: ${userId}) to Admin server`);
    } catch (syncErr) {
      console.error(`⚠️ Sync to Admin failed for ${normalizedEmail}:`, syncErr.message);
    }

    // 📧 SEND APPROVAL EMAIL ONLY FOR EMPLOYEE
    if (role === 'employee') {
      const [managers] = await db.promise().query(
        `SELECT email FROM users WHERE role = 'manager' AND company_name = ?`,
        [company_name]
      );

      if (managers.length > 0) {
        const approveToken = jwt.sign(
          { email: normalizedEmail, company_name },
          secret_key,
          { expiresIn: '48h' }
        );

        const approveLink = `http://localhost:5000/approve-employee?token=${approveToken}`;

        await transporter.sendMail({
          to: managers[0].email,
          subject: 'Employee Approval Required',
          html: `
            <h3>New Employee Registration</h3>
            <p>Email: <b>${email}</b></p>
            <p>Company: <b>${company_name}</b></p>
            <a href="${approveLink}">✅ Approve Employee</a>
          `
        });
      }
    }

    res.json({
      success: true,
      message:
        role === 'employee'
          ? 'Registered successfully. Waiting for manager approval'
          : 'Company registered successfully',
      role,
      status
    });

  } catch (err) {
    console.error('❌ Company Register Error:', err);

    return res.status(500).json({
      success: false,
      error: 'Internal Server Error'
    });
  }
});
app.get('/approve-employee', async (req, res) => {
  try {
    const { token } = req.query;
    const decoded = jwt.verify(token, secret_key);

    await db.promise().query(
      `UPDATE users SET status = 'ACTIVE'
       WHERE email = ? AND company_name = ?`,
      [decoded.email, decoded.company_name]
    );

    res.send(`
      <h2>✅ Employee Approved</h2>
      <p>${decoded.email} can now login.</p>
    `);
  } catch (err) {
    res.status(400).send('Invalid or expired approval link');
  }
});


app.post('/login', async (req, res) => {
  try {
    let { email, password } = req.body;
    if (email) email = email.trim().toLowerCase();

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password required'
      });
    }

    const [rows] = await db
      .promise()
      .query('SELECT * FROM users WHERE email = ?', [email]);

    let user;
    if (rows.length === 0) {
      // 🔍 FALLBACK: Check Admin Server (New User Sync)
      try {
        console.log(`🔍 User ${email} not found locally, checking Admin server...`);
        const adminRes = await axios.get(`${process.env.ADMIN_SERVER_URL}/api/users/check/${email}`, {
          headers: { 'x-api-key': process.env.API_BRIDGE_KEY }
        });

        if (adminRes.data) {
          const adminUser = adminRes.data;
          console.log(`✅ User found in Admin server. Syncing to local DB...`);

          const syncPassword = adminUser.password || await bcrypt.hash('SyncedUser123!', 10);

          await db.promise().query(
            `INSERT INTO users (first_name, last_name, email, mobile, password, company_name, role, status, subscription_plan, subscription_expiry)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)`,
            [
              adminUser.firstname,
              adminUser.lastname,
              adminUser.email,
              adminUser.contact || '',
              syncPassword,
              adminUser.company_name,
              adminUser.category === 'company' ? 'manager' : 'personal',
              adminUser.plan || 'Trial',
              adminUser.valid_until || new Date(Date.now() + 3 * 24 * 60 * 60 * 1000)
            ]
          );

          const [newRows] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
          user = newRows[0];
        }
      } catch (adminErr) {
        if (adminErr.response && adminErr.response.status === 404) {
          console.log(`❌ User ${email} not found in Admin server. Refusing login.`);
        } else {
          console.error(`❌ Admin check failed:`, adminErr.message);
        }
        return res.status(400).json({
          success: false,
          error: 'Invalid credentials'
        });
      }
    } else {
      user = rows[0];
      // 🔄 FULL SYNC: Update user detail and status from Admin
      try {
        const syncLog = (msg) => {
          const logMsg = `[${new Date().toISOString()}] ${msg}\n`;
          console.log(msg);
          fs.appendFileSync(path.join(__dirname, 'sync_debug.log'), logMsg);
        };

        syncLog(`🔄 [Login Sync] Attempting full sync for: ${email}`);
        const adminRes = await axios.get(`${process.env.ADMIN_SERVER_URL}/api/users/check/${email}`, {
          headers: { 'x-api-key': process.env.API_BRIDGE_KEY }
        });

        if (adminRes.data) {
          const adminUser = adminRes.data;

          // Map Admin status to Portal status
          let portalStatus = user.status; // Default to local status to preserve PENDING
          const adminStatus = (adminUser.status || '').toLowerCase();
          if (adminStatus === 'inactive') {
            portalStatus = 'INACTIVE';
          } else if (adminStatus === 'expired') {
            portalStatus = 'EXPIRED';
          } else if (adminStatus === 'active' && user.status !== 'PENDING') {
            portalStatus = 'ACTIVE';
          }

          syncLog(`📦 [Login Sync] Data: ${JSON.stringify({ plan: adminUser.plan, status: adminUser.status, portalStatus })}`);

          await db.promise().query(
            `UPDATE users SET 
              subscription_plan = ?, 
              subscription_expiry = ?, 
              first_name = ?, 
              last_name = ?, 
              mobile = ?, 
              status = ? 
             WHERE email = ?`,
            [
              adminUser.plan,
              formatMySQLDate(adminUser.valid_until),
              adminUser.firstname,
              adminUser.lastname,
              adminUser.contact || '',
              portalStatus,
              email
            ]
          );

          // Update local user object for current session
          user.subscription_plan = adminUser.plan;
          user.subscription_expiry = adminUser.valid_until;
          user.first_name = adminUser.firstname;
          user.last_name = adminUser.lastname;
          user.mobile = adminUser.contact || '';
          user.status = portalStatus;

          syncLog(`✅ [Login Sync] Full sync completed for ${email}`);
        }
      } catch (syncErr) {
        if (syncErr.response && syncErr.response.status === 404) {
          const syncLog = (msg) => {
            const logMsg = `[${new Date().toISOString()}] ${msg}\n`;
            console.log(msg);
            fs.appendFileSync(path.join(__dirname, 'sync_debug.log'), logMsg);
          };
          syncLog(`🚨 [Login Sync] User ${email} DELETED remotely. Removing local record.`);
          await db.promise().query('DELETE FROM users WHERE email = ?', [email]);
          return res.status(400).json({
            success: false,
            error: 'Account no longer exists'
          });
        }
        const errMsg = `❌ [Login Sync] Sync failed for ${email}: ${syncErr.message}`;
        console.error(errMsg);
        fs.appendFileSync(path.join(__dirname, 'sync_debug.log'), `[${new Date().toISOString()}] ${errMsg}\n`);
      }
    }

    if (!user) {
      return res.status(400).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    // 🔐 ✅ BLOCK LOGIN IF STATUS IS NOT ACTIVE OR EXPIRED
    if (user.status !== 'ACTIVE' && user.status !== 'EXPIRED') {
      let errorMessage = 'Account is deactivated';
      if (user.status === 'PENDING') {
        errorMessage = 'Account pending approval';
      } else if (user.status === 'REJECTED') {
        errorMessage = 'Account rejected';
      }

      return res.status(403).json({
        success: false,
        error: errorMessage
      });
    }


    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    const now = new Date();
    await db
      .promise()
      .query('UPDATE users SET last_login = ? WHERE id = ?', [now, user.id]);

    // 🔥 JWT WITH ROLE
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        company_name: user.company_name || null
      },
      secret_key,
      { expiresIn: '24h' }
    );

    // Compute subscription status for login response
    let isSubscriptionActive = true;
    if (user.role === 'personal' || user.status === 'EXPIRED') {
      if (!user.subscription_expiry || new Date(user.subscription_expiry) < new Date() || user.status === 'EXPIRED') {
        isSubscriptionActive = false;
      }
    }

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
        role: user.role,
        company_name: user.company_name || null,
        lastLogin: now,
        subscription_plan: user.subscription_plan || null,
        subscription_expiry: user.subscription_expiry || null,
        status: user.status || 'ACTIVE',
        isSubscriptionActive
      }
    });

  } catch (err) {
    console.error('❌ Login Error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal Server Error'
    });
  }
});
app.post('/company-login', async (req, res) => {
  try {
    let { email, password } = req.body;
    if (email) email = email.trim().toLowerCase();

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password required'
      });
    }

    const [rows] = await db.promise().query(
      `SELECT id, first_name, last_name, email, password,
              company_name, mobile, role, status, subscription_plan, subscription_expiry
       FROM users
       WHERE email = ?`,
      [email]
    );

    let user;
    if (rows.length === 0) {
      // 🔍 FALLBACK: Check Admin Server (Corporate)
      try {
        console.log(`🔍 Company User ${email} not found locally, checking Admin server...`);
        const adminRes = await axios.get(`${process.env.ADMIN_SERVER_URL}/api/users/check/${email}`, {
          headers: { 'x-api-key': process.env.API_BRIDGE_KEY }
        });

        if (adminRes.data) {
          const adminUser = adminRes.data;
          console.log(`✅ Company User found in Admin server. Syncing to local DB...`);

          const syncPassword = adminUser.password || await bcrypt.hash('SyncedUser123!', 10);

          await db.promise().query(
            `INSERT INTO users (first_name, last_name, email, mobile, password, company_name, role, status, subscription_plan, subscription_expiry)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)`,
            [
              adminUser.firstname,
              adminUser.lastname,
              adminUser.email,
              adminUser.contact || '',
              syncPassword,
              adminUser.company_name,
              adminUser.category === 'company' ? 'manager' : 'personal',
              adminUser.plan || 'Trial',
              adminUser.valid_until || new Date(Date.now() + 3 * 24 * 60 * 60 * 1000)
            ]
          );

          const [newRows] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
          user = newRows[0];
        }
      } catch (adminErr) {
        if (adminErr.response && adminErr.response.status === 404) {
          console.log(`❌ Company User ${email} not found in Admin server. Refusing login.`);
        } else {
          console.error(`❌ Admin check failed for company login:`, adminErr.message);
        }
        return res.status(400).json({
          success: false,
          error: 'Invalid credentials'
        });
      }
    } else {
      user = rows[0];
      // 🔄 FULL SYNC: For existing company users
      try {
        const syncLog = (msg) => {
          const logMsg = `[${new Date().toISOString()}] ${msg}\n`;
          console.log(msg);
          fs.appendFileSync(path.join(__dirname, 'sync_debug.log'), logMsg);
        };

        syncLog(`🔄 [Company Login Sync] Attempting sync for: ${email}`);
        const adminRes = await axios.get(`${process.env.ADMIN_SERVER_URL}/api/users/check/${email}`, {
          headers: { 'x-api-key': process.env.API_BRIDGE_KEY }
        });

        if (adminRes.data) {
          const adminUser = adminRes.data;

          // Map Admin status to Portal status
          let portalStatus = user.status; // Default to local status to preserve PENDING
          const adminStatus = (adminUser.status || '').toLowerCase();
          if (adminStatus === 'inactive') {
            portalStatus = 'INACTIVE';
          } else if (adminStatus === 'expired') {
            portalStatus = 'EXPIRED';
          } else if (adminStatus === 'active' && user.status !== 'PENDING') {
            portalStatus = 'ACTIVE';
          }

          syncLog(`📦 [Company Login Sync] Data: ${JSON.stringify({ plan: adminUser.plan, status: adminUser.status, portalStatus })}`);

          await db.promise().query(
            `UPDATE users SET 
              subscription_plan = ?, 
              subscription_expiry = ?, 
              first_name = ?, 
              last_name = ?, 
              mobile = ?, 
              status = ? 
             WHERE email = ?`,
            [
              adminUser.plan,
              adminUser.valid_until,
              adminUser.firstname,
              adminUser.lastname,
              adminUser.contact || '',
              portalStatus,
              email
            ]
          );

          user.subscription_plan = adminUser.plan;
          user.subscription_expiry = adminUser.valid_until;
          user.first_name = adminUser.firstname;
          user.last_name = adminUser.lastname;
          user.mobile = adminUser.contact || '';
          user.status = portalStatus;

          syncLog(`✅ [Company Login Sync] Full sync completed for ${email}`);
        } else {
          syncLog(`⚠️ [Company Login Sync] No data returned from Admin for ${email}`);
        }
      } catch (syncErr) {
        if (syncErr.response && syncErr.response.status === 404) {
          const syncLog = (msg) => {
            const logMsg = `[${new Date().toISOString()}] ${msg}\n`;
            console.log(msg);
            fs.appendFileSync(path.join(__dirname, 'sync_debug.log'), logMsg);
          };
          syncLog(`🚨 [Company Login Sync] User ${email} DELETED remotely. Removing local record.`);
          await db.promise().query('DELETE FROM users WHERE email = ?', [email]);
          return res.status(400).json({
            success: false,
            error: 'Account no longer exists'
          });
        }
        const errMsg = `❌ [Company Login Sync] Failed for ${email}: ${syncErr.message}`;
        console.error(errMsg);
        fs.appendFileSync(path.join(__dirname, 'sync_debug.log'), `[${new Date().toISOString()}] ${errMsg}\n`);
      }
    }

    if (!user) {
      return res.status(400).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    // 🚫 BLOCK PERSONAL USERS
    if (user.role === 'personal') {
      return res.status(403).json({
        success: false,
        error: 'Personal users cannot use company login'
      });
    }

    // 🔐 ✅ BLOCK LOGIN IF STATUS IS NOT ACTIVE OR EXPIRED
    if (user.status !== 'ACTIVE' && user.status !== 'EXPIRED') {
      let errorMessage = 'Account is deactivated';
      if (user.status === 'PENDING') {
        errorMessage = 'Account pending manager approval';
      } else if (user.status === 'REJECTED') {
        errorMessage = 'Account rejected';
      }

      return res.status(403).json({
        success: false,
        error: errorMessage
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        error: 'Invalid password'
      });
    }

    const now = new Date();
    await db
      .promise()
      .query('UPDATE users SET last_login = ? WHERE id = ?', [now, user.id]);

    // 🔥 JWT WITH ROLE
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        company_name: user.company_name,
        mobile: user.mobile
      },
      secret_key,
      { expiresIn: '24h' }
    );

    // Compute subscription status for login response
    let isSubscriptionActive = true;
    if (user.role === 'personal' || user.status === 'EXPIRED') {
      if (!user.subscription_expiry || new Date(user.subscription_expiry) < new Date() || user.status === 'EXPIRED') {
        isSubscriptionActive = false;
      }
    }

    res.json({
      success: true,
      message: '✅ Company login successful',
      token,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        role: user.role,
        company_name: user.company_name,
        mobile: user.mobile,
        lastLogin: now,
        subscription_plan: user.subscription_plan || null,
        subscription_expiry: user.subscription_expiry || null,
        status: user.status || 'ACTIVE',
        isSubscriptionActive
      }
    });

  } catch (err) {
    console.error('❌ Company Login Error:', err);
    res.status(500).json({
      success: false,
      error: 'Internal Server Error'
    });
  }
});



app.post("/invite-employee", authenticateToken, async (req, res) => {
  try {
    const { email, accessType } = req.body;
    const inviter = req.user;

    // 🔒 1️⃣ ONLY MANAGER CAN INVITE
    if (inviter.role !== "manager") {
      return res.status(403).json({
        success: false,
        error: "Only manager can invite employees",
      });
    }

    // 🔒 2️⃣ COMPANY MUST EXIST
    if (!inviter.company_name) {
      return res.status(400).json({
        success: false,
        error: "Manager must belong to a company",
      });
    }

    // 🔒 3️⃣ SAME DOMAIN CHECK
    const inviterDomain = inviter.email.split("@")[1];
    const inviteeDomain = email.split("@")[1];

    if (inviterDomain !== inviteeDomain) {
      return res.status(400).json({
        success: false,
        error: `You can invite only @${inviterDomain} email users`,
      });
    }

    // 🔐 4️⃣ CREATE INVITE TOKEN
    const inviteToken = jwt.sign(
      {
        email,
        company_name: inviter.company_name,
        accessType,        // "login" | "view"
      },
      secret_key,
      { expiresIn: "48h" }
    );

    // 🔗 5️⃣ INVITE LINK
    const inviteLink = `http://localhost:5173/invite-redirect?token=${inviteToken}`;

    // 📧 6️⃣ SEND EMAIL
    await transporter.sendMail({
      from: "Cloud360 <muthuram921@gmail.com>",
      to: email,
      subject: "Cloud360 Employee Invitation",
      html: `
        <p>You are invited to <b>${inviter.company_name}</b>.</p>
        <p>Access type: <b>${accessType.toUpperCase()}</b></p>
        <a href="${inviteLink}">Click here to continue</a>
      `,
    });

    res.json({
      success: true,
      message: "✅ Invite sent successfully",
    });
  } catch (err) {
    console.error("❌ Invite Error:", err);
    res.status(500).json({
      success: false,
      error: "Invite failed",
    });
  }
});



// =============================
// VERIFY INVITE
// =============================
app.get("/verify-invite", (req, res) => {
  try {
    const { token } = req.query;
    const decoded = jwt.verify(token, secret_key);

    // 🔵 VIEW ACCESS
    if (decoded.accessType === "view") {
      const viewToken = jwt.sign(
        {
          email: decoded.email,
          company_name: decoded.company_name,
          role: "employee",
          viewOnly: true
        },
        secret_key,
        { expiresIn: "6h" }
      );

      return res.json({
        success: true,
        access: "view",
        token: viewToken
      });
    }

    // 🔵 LOGIN ACCESS → FORCE COMPANY REGISTER
    return res.json({
      success: true,
      access: "login",
      email: decoded.email,
      company_name: decoded.company_name,
      forceCompanyRegister: true   // 🔥 IMPORTANT
    });

  } catch (err) {
    return res.status(400).json({ success: false });
  }
});


app.post('/google-login', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        success: false,
        error: 'Token required'
      });
    }

    const decoded = await admin.auth().verifyIdToken(token);

    const email = decoded.email;
    const fullName = decoded.name || '';
    const [firstName, lastName = ''] = fullName.split(' ');
    const picture = decoded.picture || '';

    console.log(`🧾 Google Sign-In Request: ${email}`);

    const [existing] = await db
      .promise()
      .query('SELECT * FROM users WHERE email = ?', [email]);

    let user;

    if (existing.length === 0) {
      // 🔥 AUTO DETECT ROLE + COMPANY
      const role = "personal";      // ✅ Google login = personal
      const company_name = null;


      await db.promise().query(
        `INSERT INTO users
   (first_name, last_name, email, mobile, password,
    company_name, role, status, last_login)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          firstName,
          lastName,
          email,
          '',
          '',
          company_name,
          role,
          "ACTIVE",          // 🔥 AUTO ACTIVATE
          new Date()
        ]
      );



      const [newUser] = await db
        .promise()
        .query('SELECT * FROM users WHERE email = ?', [email]);

      user = newUser[0];
    } else {
      user = existing[0];
      await db
        .promise()
        .query('UPDATE users SET last_login = ? WHERE id = ?', [
          new Date(),
          user.id
        ]);
    }

    // 🔥 JWT WITH ROLE
    const appToken = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,                      // ✅ ADD
        company_name: user.company_name || null
      },
      secret_key,
      { expiresIn: '24h' }
    );

    // Compute subscription status for login response
    let isSubscriptionActive = true;
    if (user.role === 'personal' || user.status === 'EXPIRED') {
      if (!user.subscription_expiry || new Date(user.subscription_expiry) < new Date() || user.status === 'EXPIRED') {
        isSubscriptionActive = false;
      }
    }

    res.json({
      success: true,
      message: '✅ Google Sign-In successful',
      token: appToken,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        role: user.role,
        company_name: user.company_name || null,
        picture,
        lastLogin: new Date(),
        subscription_plan: user.subscription_plan || null,
        subscription_expiry: user.subscription_expiry || null,
        status: user.status || 'ACTIVE',
        isSubscriptionActive
      }
    });
  } catch (err) {
    console.error('❌ Google Login Error:', err);
    res.status(400).json({
      success: false,
      error: 'Invalid or expired Firebase token'
    });
  }
});

// =============================
// FETCH USER PROFILE (Latest from DB)
app.get('/user/:email', async (req, res) => {
  try {
    const { email } = req.params;

    const [rows] = await db.promise().query(
      `SELECT 
        first_name AS firstName, 
        last_name AS lastName, 
        email, 
        mobile, 
        role,
        company_name AS company_name,
        last_login AS lastLogin,
        report_hour,
        report_minute,
        timezone
      FROM users 
      WHERE email = ?`,
      [email]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error('❌ Fetch User Error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get("/manager/pending-employees", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "manager") {
      return res.status(403).json({ error: "Access denied" });
    }

    const [rows] = await db.promise().query(
      `SELECT 
         id,
         first_name,
         last_name,
         email,
         mobile
       FROM users
       WHERE company_name = ?
         AND role = 'employee'
         AND status = 'PENDING'`,
      [req.user.company_name]
    );

    res.json({
      success: true,
      employees: rows
    });

  } catch (err) {
    console.error("Pending employees error:", err);
    res.status(500).json({ success: false });
  }
});

app.post("/manager/approve-employee", authenticateToken, async (req, res) => {
  if (req.user.role !== "manager") {
    return res.status(403).json({ error: "Access denied" });
  }

  const { userId } = req.body;

  await db.promise().query(
    `UPDATE users
     SET status = 'ACTIVE'
     WHERE id = ? AND company_name = ?`,
    [userId, req.user.company_name]
  );

  res.json({ success: true, message: "Employee approved" });
});
app.post("/manager/reject-employee", authenticateToken, async (req, res) => {
  if (req.user.role !== "manager") {
    return res.status(403).json({ error: "Access denied" });
  }

  const { userId } = req.body;

  await db.promise().query(
    `UPDATE users
     SET status = 'REJECTED'
     WHERE id = ? AND company_name = ?`,
    [userId, req.user.company_name]
  );

  res.json({ success: true, message: "Employee rejected" });
});



// =============================
// AUTH MIDDLEWARE (UPDATED FOR SUBSCRIPTION)
// =============================
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Token missing" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, secret_key, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }

    try {
      // 🔥 Fetch latest status and subscription
      const [rows] = await db.promise().query(
        "SELECT id, first_name, last_name, role, status, subscription_expiry, subscription_plan FROM users WHERE id = ?",
        [decoded.id]
      );

      if (rows.length === 0) {
        return res.status(401).json({ error: "User no longer exists" });
      }

      const u = rows[0];

      // 🚫 BLOCK IF INACTIVE
      if (u.status === 'INACTIVE') {
        return res.status(403).json({
          error: "Account is deactivated. Please contact support.",
          accountInactive: true
        });
      }

      let isSubscriptionActive = true;
      let plan = u.subscription_plan;
      let expiry = u.subscription_expiry;

      // Subscription check for personal users or Expired status
      if (u.role === 'personal' || u.status === 'EXPIRED') {
        if (!u.subscription_expiry || new Date(u.subscription_expiry) < new Date() || u.status === 'EXPIRED') {
          isSubscriptionActive = false;
        }
      }

      req.user = {
        id: decoded.id,
        first_name: u.first_name,
        last_name: u.last_name,
        email: decoded.email,
        role: u.role || "personal",
        company_name: decoded.company_name || null,
        viewOnly: decoded.viewOnly || false,
        isSubscriptionActive,
        subscription_plan: plan,
        subscription_expiry: expiry,
        status: u.status
      };

      next();
    } catch (dbErr) {
      console.error("Auth Middleware DB Error:", dbErr);
      return res.status(500).json({ error: "Internal server error during authentication" });
    }
  });
}

// 🛡️ SUBSCRIPTION GUARD
function checkSubscription(req, res, next) {
  if (!req.user.isSubscriptionActive) {
    return res.status(403).json({
      error: "Subscription expired. Please activate a new plan.",
      subscriptionExpired: true
    });
  }
  next();
}
app.get("/fetch-api", authenticateToken, checkSubscription, async (req, res) => {
  try {
    if (req.user.viewOnly) {
      return res.status(403).json({ error: "View-only access" });
    }

    const { url } = req.query;
    if (!url) return res.status(400).json({ error: "API URL required" });

    const externalToken =
      req.headers["authorization-external"] || req.headers["x-api-key"];

    const headers = {};
    if (externalToken) {
      headers.Authorization = externalToken.startsWith("Bearer")
        ? externalToken
        : `Bearer ${externalToken}`;
    }

    const apiResponse = await axios.get(url, { headers });

    res.json({ success: true, data: apiResponse.data });
  } catch (err) {
    if (err.response?.status === 401) {
      return res.status(401).json({ private: true });
    }
    res.status(500).json({ error: "Fetch failed" });
  }
});
app.post("/fetch-api", authenticateToken, checkSubscription, async (req, res) => {
  try {
    if (req.user.viewOnly) {
      return res.status(403).json({ error: "View-only access" });
    }

    const { url, file_name } = req.body;
    if (!url || !file_name) {
      return res.status(400).json({ error: "API URL and File Name required" });
    }

    const apiResponse = await axios.get(url);
    const raw = Array.isArray(apiResponse.data)
      ? apiResponse.data
      : [apiResponse.data];

    const hash = stableHash(raw);

    const companyName = req.user.company_name || null;
    const uploadedBy = req.user.id;
    const now = new Date();
    const nextRun = new Date(now.getTime() + 5 * 60 * 1000);

    const safeName = file_name
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "_")
      .replace(/[^a-z0-9_]/g, "");

    const [existing] = await db.promise().query(
      `SELECT id, response_hash FROM api_data
       WHERE file_name = ? AND company_name <=> ?`,
      [safeName, companyName]
    );

    let status = "DONE";

    if (existing.length === 0 || existing[0].response_hash !== hash) {
      status = "NEW";
    }

    if (existing.length === 0) {
      await db.promise().query(
        `INSERT INTO api_data
         (api_url, file_name, response, response_hash,
          company_name, uploaded_by,
          status, last_processed_at, next_process_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          url,
          safeName,
          JSON.stringify(raw),
          hash,
          companyName,
          uploadedBy,
          "NEW",
          now,
          nextRun
        ]
      );
    } else {
      await db.promise().query(
        `UPDATE api_data
         SET response = ?, response_hash = ?, status = ?,
             last_processed_at = ?, next_process_at = ?
         WHERE id = ?`,
        [
          JSON.stringify(raw),
          hash,
          status,
          now,
          nextRun,
          existing[0].id
        ]
      );
    }

    res.json({ success: true, status });

  } catch (err) {
    res.status(500).json({ error: "Fetch failed" });
  }
});

app.post("/save-api-data", authenticateToken, checkSubscription, async (req, res) => {
  try {
    if (req.user.viewOnly) {
      return res.status(403).json({ error: "View-only access" });
    }

    const { api_url, file_name, response } = req.body;
    if (!api_url || !file_name || !response) {
      return res.status(400).json({ error: "Missing data" });
    }

    // 🔹 Safe file name
    const safeName = file_name
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "_")
      .replace(/[^a-z0-9_]/g, "");

    // 🔹 Always keep RAW API JSON
    const raw = Array.isArray(response) ? response : [response];

    // 🔥 Hash must be SAME as cron (no cleaning, no filtering)
    const hash = stableHash(raw);

    const now = new Date();
    const nextRun = new Date(now.getTime() + 5 * 60 * 1000);

    const externalToken =
      req.headers["authorization-external"] ||
      req.headers["x-api-key"] ||
      null;

    // 🔍 Prevent duplicate API names per company
    const [existing] = await db.promise().query(
      `SELECT id FROM api_data WHERE file_name = ? AND company_name <=> ?`,
      [safeName, req.user.company_name || null]
    );

    if (existing.length > 0) {
      return res.status(409).json({ error: "File name already exists" });
    }

    // 💾 Store RAW JSON + HASH
    await db.promise().query(
      `INSERT INTO api_data
       (api_url, file_name, response, response_hash, company_name, uploaded_by,
        status, last_processed_at, next_process_at, api_token)
       VALUES (?, ?, ?, ?, ?, ?, 'NEW', ?, ?, ?)`,
      [
        api_url,
        safeName,
        JSON.stringify(raw),
        hash,
        req.user.company_name || null,
        req.user.id,
        now,
        nextRun,
        externalToken
      ]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("❌ Save API Error:", err);
    res.status(500).json({ error: "Save failed" });
  }
});
// =======================================================
// ⏰ API CRON – FINAL & CORRECT
// =======================================================

cron.schedule("*/5 * * * *", async () => {
  console.log("⏰ API cron started (every 2 minutes)");

  try {
    const [apis] = await db.promise().query(`
      SELECT
        id,
        api_url,
        response,
        response_hash,
        api_token,
        file_name,
        company_name,
        uploaded_by
      FROM api_data
    `);

    for (const api of apis) {
      const now = new Date();
      const nextRun = new Date(now.getTime() + 60 * 60 * 1000);

      try {
        // 1️⃣ FETCH API
        const headers = { "User-Agent": "Cloud360-Cron/1.0" };
        if (api.api_token) {
          headers.Authorization = api.api_token.startsWith("Bearer ")
            ? api.api_token
            : `Bearer ${api.api_token}`;
        }

        const res = await axios.get(api.api_url, {
          timeout: 20000,
          headers
        });

        const rawNewData = Array.isArray(res.data)
          ? res.data
          : [res.data];

        // 2️⃣ HASH = ONLY SOURCE OF TRUTH
        const newHash = stableHash(rawNewData);
        const oldHash = api.response_hash;

        const isUpdated = newHash !== oldHash;

        // 3️⃣ ROW COUNTS (REPORTING ONLY)
        let prevRows = 0;
        try {
          const oldData = api.response ? JSON.parse(api.response) : [];
          prevRows = Array.isArray(oldData) ? oldData.length : 0;
        } catch { }

        const currRows = rawNewData.length;
        const newRows = isUpdated
          ? Math.max(currRows - prevRows, 0)
          : 0;

        // 4️⃣ STATUS DECISION
        const apiDataStatus = isUpdated ? "NEW" : "DONE";
        const runStatus = isUpdated ? "UPDATED" : "NO_CHANGE";

        // 5️⃣ UPDATE api_data (LATEST SNAPSHOT)
        await db.promise().query(`
          UPDATE api_data
          SET
            response = ?,
            response_hash = ?,
            status = ?,
            last_processed_at = ?,
            next_process_at = ?
          WHERE id = ?
        `, [
          JSON.stringify(rawNewData),
          newHash,
          apiDataStatus,
          now,
          nextRun,
          api.id
        ]);

        // 6️⃣ INSERT api_run_stats (ALWAYS)
        await db.promise().query(`
          INSERT INTO api_run_stats
          (
            api_id,
            api_name,
            company_name,
            uploaded_by,
            run_time,
            prev_rows,
            curr_rows,
            new_rows,
            duplicates_removed,
            status
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
          api.id,
          api.file_name,
          api.company_name,
          api.uploaded_by,
          now,
          prevRows,
          currRows,
          newRows,
          0,
          runStatus
        ]);

        console.log(`✔ API ${api.file_name} → ${runStatus}`);

      } catch (err) {
        console.error("❌ API fetch failed:", api.api_url, err.message);
      }
    }

  } catch (err) {
    console.error("❌ Cron fatal error:", err.message);
  }
});

// =======================================================
// 📊 UPDATE DAILY REPORT TIME
// =======================================================
app.post("/api/report-time", authenticateToken, checkSubscription, async (req, res) => {
  const { email, hour, minute, timezone } = req.body;

  try {
    const [result] = await db.promise().query(
      `
      UPDATE users
      SET report_hour = ?, report_minute = ?, timezone = ?, last_report_sent = NULL
      WHERE email = ?
      `,
      [hour, minute, timezone || 'Asia/Kolkata', email]
    );

    if (result.affectedRows > 0) {
      res.json({ success: true });
    } else {
      res.json({ success: false });
    }

  } catch (err) {
    console.error("Report time update error:", err);
    res.status(500).json({ success: false });
  }
});

// =======================================================
// 📊 GET DAILY REPORT TIME
// =======================================================
app.get("/api/report-time/:email", async (req, res) => {
  const { email } = req.params;

  try {
    const [rows] = await db.promise().query(
      `SELECT report_hour, report_minute, timezone FROM users WHERE email = ?`,
      [email]
    );

    if (rows.length > 0) {
      res.json({
        success: true,
        hour: rows[0].report_hour,
        minute: rows[0].report_minute,
        timezone: rows[0].timezone
      });
    } else {
      res.json({ success: false });
    }
  } catch (err) {
    console.error("Report time fetch error:", err);
    res.status(500).json({ success: false });
  }
});

// =======================================================
// 📧 DAILY SUMMARY MAIL CRON (Dynamic Per User)
// Runs Every Minute
// =======================================================
cron.schedule("* * * * *", async () => {
  console.log("⏰ Checking Daily Report Schedule...");

  try {
    const [users] = await db.promise().query(`
      SELECT id, email, role, company_name,
             report_hour, report_minute, timezone, last_report_sent
      FROM users
      WHERE status = 'ACTIVE'
    `);

    for (const user of users) {
      const userTimezone = user.timezone || "Asia/Kolkata";
      const now = new Date(
        new Date().toLocaleString("en-US", { timeZone: userTimezone })
      );

      const currentHour = now.getHours();
      const currentMinute = now.getMinutes();
      const todayDate = now.toISOString().split("T")[0];

      // ⛔ Skip if already sent today
      if (
        user.last_report_sent &&
        new Date(user.last_report_sent).toISOString().split("T")[0] === todayDate
      ) {
        continue;
      }

      // ✅ Check time match
      if (
        user.report_hour === currentHour &&
        user.report_minute === currentMinute
      ) {
        // 🔒 ATOMIC LOCK: Update first, send only if we claimed the row
        const [updateResult] = await db.promise().query(
          `UPDATE users
           SET last_report_sent = CURDATE()
           WHERE id = ?
             AND (last_report_sent IS NULL OR last_report_sent < CURDATE())`,
          [user.id]
        );

        if (updateResult.affectedRows > 0) {
          console.log(`📤 Sending report to ${user.email} (${userTimezone})`);
          await sendDailyReport(user);
          console.log(`✅ Report sent: ${user.email}`);
        }
      }
    }

  } catch (err) {
    console.error("Cron error:", err);
  }
});
// =======================================================
// 📩 SEND DAILY REPORT FUNCTION
// =======================================================
async function sendDailyReport(user) {

  // ===================================================
  // 📁 FILE SUMMARY (TODAY)
  // ===================================================
  const [files] = await db.promise().query(`
    SELECT
    	file_name,
        status,
        rows_count,
        processed_at
      FROM file_run_stats
      WHERE
        (${user.company_name ? "company_name = ?" : "uploaded_by = ?"})
        AND DATE(processed_at) = CURDATE()
      ORDER BY processed_at DESC
    `, [user.company_name || user.id]);

  // ===================================================
  // 🌐 API SUMMARY (AGGREGATED – TODAY)
  // ===================================================
  const [apis] = await db.promise().query(`
    SELECT
      api_name,
      COUNT(*) AS total_runs,
      SUM(new_rows) AS total_new_rows,
      MAX(run_time) AS last_run,
      CASE
        WHEN SUM(new_rows) > 0 THEN 'UPDATED'
        ELSE 'NO_CHANGE'
      END AS status
    FROM api_run_stats
    WHERE
      (${user.company_name ? "company_name = ?" : "uploaded_by = ?"})
      AND DATE(run_time) = CURDATE()
    GROUP BY api_name
    ORDER BY api_name
  `, [user.company_name || user.id]);

  // ===================================================
  // 🌐 API UPDATE DETAILS (ONLY WHEN DATA CHANGED)
  // ===================================================
  const [apiChanges] = await db.promise().query(`
    SELECT
      api_name,
      run_time,
      new_rows,
      status
    FROM api_run_stats
    WHERE
      (${user.company_name ? "company_name = ?" : "uploaded_by = ?"})
      AND DATE(run_time) = CURDATE()
      AND new_rows > 0
    ORDER BY api_name, run_time
  `, [user.company_name || user.id]);

  if (!files.length && !apis.length && !apiChanges.length) {
    console.log("No activity today for:", user.email);
    return;
  }

  const html = buildDailySummaryEmail(
    user,
    files,
    apis,
    apiChanges
  );

  await transporter.sendMail({
    to: user.email,
    subject: "📊 Cloud360 Daily Data Summary",
    html
  });

  console.log("✅ Report sent:", user.email);
}

// =======================================================
// ✉️ EMAIL TEMPLATE
// =======================================================
function buildDailySummaryEmail(user, files, apis, apiChanges) {

  const today = new Date().toLocaleDateString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric"
  });

  // -------------------------------
  // GROUP API CHANGES BY API NAME
  // -------------------------------
  const groupedApiChanges = {};
  (apiChanges || []).forEach(r => {
    if (!groupedApiChanges[r.api_name]) {
      groupedApiChanges[r.api_name] = [];
    }
    groupedApiChanges[r.api_name].push(r);
  });

  return `
  <h2>📊 Cloud360 Daily Summary</h2>

  <p>
    <b>Date:</b> ${today}<br/>
    <b>User:</b> ${user.email}<br/>
    <b>Role:</b> ${user.role}
  </p>

  <hr/>

  <!-- ================= FILES ================= -->
 <h3 style="margin-top:10px;">📁 Uploaded Files</h3>

<table width="100%" cellpadding="0" cellspacing="0"
  style="
    border-collapse:collapse;
    table-layout:fixed;
    font-size:13px;
  ">
  <thead>
    <tr style="background:#f4f6f8;">
      <th style="width:40%;border:1px solid #ddd;padding:6px;text-align:center;">File Name</th>
      <th style="width:15%;border:1px solid #ddd;padding:6px;text-align:center;">Status</th>
      <th style="width:15%;border:1px solid #ddd;padding:6px;text-align:center;">Rows</th>
      <th style="width:30%;border:1px solid #ddd;padding:6px;text-align:center;">Processed At</th>
    </tr>
  </thead>
  <tbody>
    ${files.length
      ? files.map(f => `
          <tr>
            <td style="border:1px solid #ddd;padding:6px;word-break:break-word;text-align:center;">
              ${f.file_name}
            </td>
            <td style="border:1px solid #ddd;padding:6px;text-align:center;">
              ${f.status}
            </td>
            <td style="border:1px solid #ddd;padding:6px;text-align:center;">
              ${f.rows_count ?? "—"}
            </td>
            <td style="border:1px solid #ddd;padding:6px;text-align:center;">
  ${f.processed_at
          ? new Date(f.processed_at).toLocaleString("en-IN", {
            day: "2-digit",
            month: "short",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            hour12: true
          })
          : "—"
        }
</td>

          </tr>
        `).join("")
      : `<tr>
            <td colspan="4" style="border:1px solid #ddd;padding:8px;text-align:center;">
              No file activity today
            </td>
          </tr>`
    }
  </tbody>
</table>


  <br/>

  <!-- ================= API TABLE ================= -->
 <h3 style="margin-top:16px;">🌐 API Summary (Today)</h3>

<table width="100%" cellpadding="0" cellspacing="0"
  style="
    border-collapse:collapse;
    table-layout:fixed;
    font-size:13px;
  ">
  <thead>
    <tr style="background:#f4f6f8;">
      <th style="width:35%;border:1px solid #ddd;padding:6px;text-align:center;">API Name</th>
      <th style="width:20%;border:1px solid #ddd;padding:6px;text-align:center;">Status</th>
      <th style="width:20%;border:1px solid #ddd;padding:6px;text-align:center;">Total Batch Process (24 hrs)</th>
      <th style="width:25%;border:1px solid #ddd;padding:6px;text-align:center;">Last Processed Time</th>
    </tr>
  </thead>
  <tbody>
    ${apis.length
      ? apis.map(a => `
          <tr>
            <td style="border:1px solid #ddd;padding:6px;word-break:break-word;text-align:center;">
              ${a.api_name}
            </td>
            <td style="border:1px solid #ddd;padding:6px;text-align:center;">
              ${a.status === "UPDATED" ? "🟢 UPDATED" : "⚪ NO CHANGE"}
            </td>
            <td style="border:1px solid #ddd;padding:6px;text-align:center;">
              ${a.total_runs}
            </td>
            <td style="border:1px solid #ddd;padding:6px;text-align:center;">
              ${new Date(a.last_run).toLocaleTimeString("en-IN", {
        hour: "2-digit",
        minute: "2-digit",
        hour12: true
      })}
            </td>
          </tr>
        `).join("")
      : `<tr>
            <td colspan="4" style="border:1px solid #ddd;padding:8px;text-align:center;">
              No API activity today
            </td>
          </tr>`
    }
  </tbody>
</table>


  <br/>

  <!-- ================= API UPDATES ================= -->
  <h3>🌐 API Updates (Only Changed)</h3>

  ${Object.keys(groupedApiChanges).length
      ? Object.entries(groupedApiChanges).map(([api, runs]) => `
        <p><b>🟢 ${api}</b></p>
        <ul>
          ${runs.map(r => `
            <li>
  ${new Date(r.run_time).toLocaleTimeString("en-IN", {
        hour: "2-digit",
        minute: "2-digit",
        hour12: true
      })}
  → ${r.status === "UPDATED" ? "🟢 UPDATED" : "⚪ NO CHANGE"}
</li>

          `).join("")}
        </ul>
      `).join("")
      : `<p>No API updates today</p>`
    }

  <br/>

  <p>
    👉 <a href="http://localhost:5173/dashboard">Open Dashboard</a>
  </p>

  <small>
    This is an automated report generated by Cloud360.
  </small>
  `;
}

// --------------------------------------------------------
// 💾 Utility: Flatten nested objects for CSV
// --------------------------------------------------------
const flattenObject = (obj, prefix = '') =>
  Object.keys(obj).reduce((acc, k) => {
    const pre = prefix.length ? prefix + '_' : '';
    if (Array.isArray(obj[k])) {
      acc[pre + k] = JSON.stringify(obj[k]);
    } else if (typeof obj[k] === 'object' && obj[k] !== null) {
      Object.assign(acc, flattenObject(obj[k], pre + k));
    } else {
      acc[pre + k] = obj[k];
    }
    return acc;
  }, {});



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
// HELPER FUNCTIONS (ADD HERE)
// ======================
function safeFileName(name) {
  return name
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_")      // spaces → _
    .replace(/[^a-z0-9_]/g, ""); // remove special chars
}


// ======================
// /upload ROUTE (CLEAN FINAL VERSION)
// ======================

app.post("/upload", authenticateToken, checkSubscription, (req, res, next) => {
  if (req.user.viewOnly) {
    return res.status(403).json({ error: "View-only users cannot upload files" });
  }
  next();
}, upload.array("files"), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        success: false,
        error: "No files uploaded"
      });
    }

    const companyName = req.user?.company_name || null;
    const rawName = req.body.name || "uploaded_file";
    const baseFileName = safeFileName(rawName);

    // ==================================================
    // SINGLE FILE FLOW
    // ==================================================
    if (req.files.length === 1) {
      const file = req.files[0];
      const finalFilename = `${baseFileName}.csv`;
      const finalPath = path.join(__dirname, "uploads", finalFilename);

      fs.renameSync(file.path, finalPath);

      const [existing] = await db.promise().query(
        `SELECT id FROM files
           WHERE file_name = ?
           AND company_name <=> ?`,
        [baseFileName, companyName]
      );

      const status = existing.length > 0 ? "CANCEL" : "NEW";

      await db.promise().query(
        `INSERT INTO files (file_name, file_path, company_name, uploaded_by, status)
   VALUES (?, ?, ?, ?, ?)`,
        [
          baseFileName,
          `/uploads/${finalFilename}`,
          companyName,
          req.user.id,     // 👈 user_id
          status
        ]
      );

      // 📊 LOG ACTIVITY FOR DAILY REPORT
      try {
        const { data } = await readCSV(finalPath);
        await insertFileRunStat({
          file_name: baseFileName,
          company_name: companyName,
          uploaded_by: req.user.id,
          rows_count: data.length,
          status: "DONE"
        });
      } catch (err) {
        console.error("❌ Error logging file stat:", err);
      }


      return res.json({
        success: true,
        message: "File uploaded successfully",
        file: finalFilename
      });
    }

    // ==================================================
    // MULTI FILE FLOW (MERGE → ONE FILE)
    // ==================================================
    if (req.files.length > 1) {
      let allHeaders = [];
      let allDataRaw = [];

      for (const file of req.files) {
        const { headers, data } = await readCSV(file.path);

        const normalizedHeaders = headers.map(h => sanitizeName(h));
        allHeaders.push(normalizedHeaders);

        const normalizedData = data.map(row => {
          const obj = {};
          Object.keys(row).forEach(k => {
            obj[sanitizeName(k)] = row[k];
          });
          return obj;
        });

        allDataRaw.push(normalizedData);
      }

      const commonColumns = allHeaders.reduce((a, b) =>
        a.filter(c => b.includes(c))
      );

      if (commonColumns.length === 0) {
        return res.status(400).json({
          success: false,
          error: "No common primary key found"
        });
      }

      const primaryKey =
        commonColumns.includes("id") ? "id" :
          commonColumns.includes("user_id") ? "user_id" :
            commonColumns.includes("emp_id") ? "emp_id" :
              commonColumns[0];

      const allColumnsSet = new Set();
      allHeaders.forEach(h => h.forEach(c => allColumnsSet.add(c)));
      let allColumns = Array.from(allColumnsSet);

      const map = new Map();
      for (const fileData of allDataRaw) {
        for (const row of fileData) {
          if (!row[primaryKey]) continue;

          const key = row[primaryKey].toString().trim();
          if (!map.has(key)) {
            const obj = {};
            allColumns.forEach(c => (obj[c] = ""));
            map.set(key, obj);
          }

          const target = map.get(key);
          Object.keys(row).forEach(col => {
            if (row[col] !== "") target[col] = row[col];
          });
        }
      }

      allColumns = [
        primaryKey,
        ...allColumns.filter(c => c !== primaryKey)
      ];

      const parser = new Parser({ fields: allColumns });
      const mergedCSV = parser.parse(Array.from(map.values()));

      // 🔥 USE USER FILE NAME
      let finalFilename = `${baseFileName}.csv`;
      let finalPath = path.join(__dirname, "uploads", finalFilename);

      // avoid overwrite
      let counter = 1;
      while (fs.existsSync(finalPath)) {
        finalFilename = `${baseFileName}_${counter}.csv`;
        finalPath = path.join(__dirname, "uploads", finalFilename);
        counter++;
      }

      fs.writeFileSync(finalPath, mergedCSV);

      // delete temp uploads
      req.files.forEach(f => {
        if (fs.existsSync(f.path)) fs.unlinkSync(f.path);
      });

      // save ONLY merged file
      await db.promise().query(
        `INSERT INTO files (file_name, file_path, company_name, uploaded_by, status)
   VALUES (?, ?, ?, ?, 'NEW')`,
        [
          baseFileName,
          `/uploads/${finalFilename}`,
          companyName,
          req.user.id
        ]
      );

      // 📊 LOG ACTIVITY FOR DAILY REPORT
      try {
        const { data } = await readCSV(finalPath);
        await insertFileRunStat({
          file_name: baseFileName,
          company_name: companyName,
          uploaded_by: req.user.id,
          rows_count: data.length,
          status: "DONE"
        });
      } catch (err) {
        console.error("❌ Error logging merged file stat:", err);
      }


      return res.json({
        success: true,
        message: "Files merged successfully",
        file: finalFilename
      });
    }

  } catch (err) {
    console.error("❌ UPLOAD ERROR:", err);
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
}
);

// =============================
// GET FILES (COMPANY BASED - FINAL)
// =============================
app.get("/files", authenticateToken, async (req, res) => {
  try {
    const { company_name, id: userId } = req.user;
    const isCompanyUser = !!company_name;

    // =============================
    // 1️⃣ UPLOADED FILES
    // =============================
    let uploadedQuery = "";
    let uploadedParams = [];

    if (isCompanyUser) {
      uploadedQuery = `
        SELECT 
          id,
          file_name AS name,
          file_path AS path,
          status,
          processed_at,
          completed_at
        FROM files
        WHERE company_name = ?
        ORDER BY id ASC`;
      uploadedParams = [company_name];
    } else {
      uploadedQuery = `
        SELECT 
          id,
          file_name AS name,
          file_path AS path,
          status,
          processed_at,
          completed_at
        FROM files
        WHERE uploaded_by = ?
        ORDER BY id ASC`;
      uploadedParams = [userId];
    }

    const [uploadedFiles] = await db.promise().query(uploadedQuery, uploadedParams);

    const uploadedFilesWithSource = uploadedFiles.map(f => ({
      id: `uploaded-${f.id}`,
      name: f.name,
      path: f.path,
      status: f.status,
      source: "Uploaded File",
      type: "uploaded",
      processed_at: f.processed_at,
      completed_at: f.completed_at
    }));

    // =============================
    // 2️⃣ API FILES
    // =============================
    let apiQuery = "";
    let apiParams = [];

    if (isCompanyUser) {
      apiQuery = `
        SELECT 
          id,
          COALESCE(file_name, CONCAT('api_', id)) AS name,
          file_path AS path,
          status,
          last_processed_at,
          next_process_at
        FROM api_data
        WHERE company_name = ?`;
      apiParams = [company_name];
    } else {
      apiQuery = `
        SELECT 
          id,
          COALESCE(file_name, CONCAT('api_', id)) AS name,
          file_path AS path,
          status,
          last_processed_at,
          next_process_at
        FROM api_data
        WHERE uploaded_by = ?`;
      apiParams = [userId];
    }

    const [apiFiles] = await db.promise().query(apiQuery, apiParams);

    const apiFilesWithSource = apiFiles.map(f => ({
      id: `api-${f.id}`,
      name: f.name,
      path: f.path,
      source: "API Data",
      type: "api",
      status: f.status || "DONE",
      last_processed_at: f.last_processed_at,
      next_process_at: f.next_process_at
    }));

    // =============================
    // 3️⃣ PROCESSED TABLES (COMPANY SAFE)
    // =============================
    let allowedFilesQuery = "";
    let allowedParams = [];

    if (isCompanyUser) {
      allowedFilesQuery = `
        SELECT file_name FROM files WHERE company_name = ?
        UNION
        SELECT file_name FROM api_data WHERE company_name = ?`;
      allowedParams = [company_name, company_name];
    } else {
      allowedFilesQuery = `
        SELECT file_name FROM files WHERE uploaded_by = ?
        UNION
        SELECT file_name FROM api_data WHERE uploaded_by = ?`;
      allowedParams = [userId, userId];
    }

    const [allowedFiles] = await db.promise().query(allowedFilesQuery, allowedParams);

    const allowedBaseNames = new Set(
      allowedFiles
        .filter(f => f.file_name)
        .map(f => f.file_name.toLowerCase().replace(/\.[^/.]+$/, ""))
    );

    const [tables] = await db.promise().query("SHOW TABLES");

    const processedMap = {};

    tables.forEach(row => {
      const tableName = Object.values(row)[0].toLowerCase();
      const match = tableName.match(/(.+)_(fulltable|entity|metrics|dimension)$/);
      if (!match) return;

      const baseName = match[1];
      if (!allowedBaseNames.has(baseName)) return;

      if (!processedMap[baseName]) processedMap[baseName] = [];
      processedMap[baseName].push(tableName);
    });

    const processedFolders = Object.keys(processedMap).map((baseName, idx) => ({
      id: `processed-${idx}`,
      folderName: baseName,
      tables: processedMap[baseName],
      type: "processed",
      status: "DONE"
    }));

    // =============================
    // 4️⃣ FINAL STATUS FIX
    // =============================
    const processedSet = new Set(
      processedFolders.map(p => p.folderName.toLowerCase())
    );

    const getBaseName = (name = "") =>
      name.toLowerCase().replace(/\.[^/.]+$/, "");

    const allFiles = [...uploadedFilesWithSource, ...apiFilesWithSource].map(f => {
      const baseName = getBaseName(f.name);
      let finalStatus = f.status;

      if (f.status === "CANCEL") finalStatus = "CANCEL";
      else if (f.status === "PROCESSING") finalStatus = "PROCESSING";
      else if (processedSet.has(baseName)) finalStatus = "DONE";
      else finalStatus = "NEW";

      return { ...f, status: finalStatus };
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

app.get("/processed-table/:tableName", authenticateToken, async (req, res) => {
  try {
    const { tableName } = req.params;
    const { id: userId, company_name, viewOnly } = req.user;

    let filesQuery = "";
    let queryParams = [];

    // =============================
    // 1️⃣ PERSONAL USER
    // =============================
    if (!company_name) {
      filesQuery = `
        SELECT file_name FROM files WHERE uploaded_by = ?
        UNION
        SELECT file_name FROM api_data WHERE uploaded_by = ?
      `;
      queryParams = [userId, userId];
    }
    // =============================
    // 2️⃣ COMPANY USER
    // =============================
    else {
      filesQuery = `
        SELECT file_name FROM files WHERE company_name = ?
        UNION
        SELECT file_name FROM api_data WHERE company_name = ?
      `;
      queryParams = [company_name, company_name];
    }

    const [files] = await db.promise().query(filesQuery, queryParams);

    // =============================
    // 3️⃣ Normalize filenames
    // =============================
    const allowedBaseNames = files
      .filter(f => f.file_name)
      .map(f =>
        f.file_name
          .toLowerCase()
          .replace(/\.[^/.]+$/, "")
          .replace(/\s+/g, "_")
      );

    const baseName = tableName
      .toLowerCase()
      .replace(/_(fulltable|entity|metrics|dimension)$/, "")
      .replace(/\s+/g, "_");

    // =============================
    // 4️⃣ Access check
    // =============================
    if (!allowedBaseNames.includes(baseName)) {
      return res.status(403).json({
        success: false,
        error: "You don't have access to this file"
      });
    }

    // =============================
    // 5️⃣ Spark table exists?
    // =============================
    const [[exists]] = await db.promise().query(
      `
      SELECT COUNT(*) AS count
      FROM information_schema.tables
      WHERE table_schema = DATABASE()
      AND table_name = ?
      `,
      [tableName]
    );

    if (exists.count === 0) {
      return res.json({
        success: true,
        tableName,
        rows: [],
        status: "WAITING",
        viewOnly: !!viewOnly
      });
    }

    // =============================
    // 6️⃣ Fetch processed data
    // =============================
    const [rows] = await db.promise().query(
      `SELECT * FROM \`${tableName}\``
    );

    res.json({
      success: true,
      tableName,
      rows,
      status: "READY",
      viewOnly: !!viewOnly
    });

  } catch (err) {
    console.error("❌ Fetch Processed Table Error:", err);
    res.status(500).json({
      success: false,
      error: "Error fetching processed table"
    });
  }
});


app.get("/dashboard-counts", authenticateToken, async (req, res) => {
  try {
    const { id: userId, role, company_name, viewOnly } = req.user;

    // =============================
    // 👀 VIEW-ONLY USER FIX (IMPORTANT)
    // =============================
    if (viewOnly) {
      return res.json({
        success: true,
        me: {
          uploadedFiles: 0,
          uploadedApi: 0,
          processedFiles: 0
        },
        company: null
      });
    }

    const isManager = role === "manager";
    const isCompanyUser = !!company_name;

    // =============================
    // 1️⃣ MY UPLOADED FILES
    // =============================
    const [[myFiles]] = await promiseDb.query(
      `SELECT COUNT(*) AS count FROM files WHERE uploaded_by = ?`,
      [userId]
    );

    // =============================
    // 2️⃣ MY API FILES
    // =============================
    const [[myApi]] = await promiseDb.query(
      `SELECT COUNT(*) AS count FROM api_data WHERE uploaded_by = ?`,
      [userId]
    );

    // =============================
    // 3️⃣ GET ALL PROCESSED TABLE BASE NAMES
    // =============================
    const [tables] = await promiseDb.query("SHOW TABLES");

    const processedSet = new Set(
      tables
        .map(t => Object.values(t)[0])
        .filter(name =>
          name.endsWith("_fulltable") ||
          name.endsWith("_entity") ||
          name.endsWith("_metrics") ||
          name.endsWith("_dimension")
        )
        .map(name =>
          name.replace(/_(fulltable|entity|metrics|dimension)$/i, "")
            .toLowerCase()
        )
    );

    // =============================
    // 4️⃣ MY PROCESSED FILES
    // =============================
    const [myNames] = await promiseDb.query(
      `SELECT file_name FROM files WHERE uploaded_by = ?`,
      [userId]
    );

    const myProcessed = myNames.filter(f =>
      processedSet.has(f.file_name.toLowerCase())
    ).length;

    // =============================
    // 5️⃣ COMPANY STATS (MANAGER ONLY)
    // =============================
    let companyStats = null;

    if (isManager && isCompanyUser) {
      const [[companyFiles]] = await promiseDb.query(
        `SELECT COUNT(*) AS count FROM files WHERE company_name = ?`,
        [company_name]
      );

      const [[companyApi]] = await promiseDb.query(
        `SELECT COUNT(*) AS count FROM api_data WHERE company_name = ?`,
        [company_name]
      );

      const [companyNames] = await promiseDb.query(
        `SELECT file_name FROM files WHERE company_name = ?`,
        [company_name]
      );

      const companyProcessed = companyNames.filter(f =>
        processedSet.has(f.file_name.toLowerCase())
      ).length;

      companyStats = {
        uploadedFiles: companyFiles.count,
        uploadedApi: companyApi.count,
        processedFiles: companyProcessed
      };
    }

    // =============================
    // 6️⃣ RESPONSE
    // =============================
    res.json({
      success: true,
      me: {
        uploadedFiles: myFiles.count,
        uploadedApi: myApi.count,
        processedFiles: myProcessed
      },
      company: companyStats
    });

  } catch (err) {
    console.error("❌ Dashboard Counts Error:", err);
    res.status(500).json({ error: "Dashboard failed" });
  }
});


// =============================
// ✅ GROQ CHAT API (DATA AWARE)
// =============================
app.post("/api/chat", authenticateToken, checkSubscription, async (req, res) => {
  try {
    const { question } = req.body;
    const { id: userId, company_name } = req.user;

    if (!question) {
      return res.status(400).json({
        success: false,
        error: "Question is required",
      });
    }

    // 1️⃣ FETCH USER DATA CONTEXT
    let metadata = {
      files: [],
      apis: [],
      processedTables: []
    };

    try {
      // Fetch Uploaded Files
      const [files] = await promiseDb.query(
        `SELECT file_name FROM files WHERE ${company_name ? "company_name = ?" : "uploaded_by = ?"}`,
        [company_name || userId]
      );
      metadata.files = files.map(f => f.file_name);

      // Fetch API Data
      const [apis] = await promiseDb.query(
        `SELECT file_name FROM api_data WHERE ${company_name ? "company_name = ?" : "uploaded_by = ?"}`,
        [company_name || userId]
      );
      metadata.apis = apis.map(a => a.file_name);

      // Fetch Processed Tables (Authorized)
      const [tables] = await promiseDb.query("SHOW TABLES");
      const allowedBaseNames = new Set([...metadata.files, ...metadata.apis].map(name => name.toLowerCase().replace(/\.[^/.]+$/, "")));

      metadata.processedTables = tables
        .map(t => Object.values(t)[0])
        .filter(name => {
          const match = name.match(/(.+)_(fulltable|entity|metrics|dimension)$/i);
          if (!match) return false;
          return allowedBaseNames.has(match[1].toLowerCase());
        });

    } catch (dbErr) {
      console.error("❌ Database metadata fetch error:", dbErr);
    }

    // 2️⃣ CONSTRUCT SYSTEM PROMPT
    const systemPrompt = `
You are "Cloud360 - AI Assistant", a professional and helpful guide for the Cloud360 data platform.

**Product Knowledge:**
Cloud360 is an advanced data engineering platform that allows users to:
1. **Upload Files**: Upload CSV/Excel files for processing.
2. **API Integration**: Fetch data from external APIs and schedule periodic updates.
3. **Spark Processing**: Transform raw data into structured tables (Full-table, Entities, Metrics, Dimensions) using Spark.
4. **Natural Language Queries (NLP)**: Query data using plain English (handled by the NLP Results section).
5. **Daily Reports**: Receive automated email summaries of data activities.
6. **Dashboard**: Visualize data stats and processed results.

**User Data Context:**
The user currently logged in has access to the following:
- Uploaded Files: ${metadata.files.join(", ") || "None"}
- Configured APIs: ${metadata.apis.join(", ") || "None"}
- Processed Data Tables: ${metadata.processedTables.join(", ") || "None"}

**Instructions:**
- Answer questions about the user's files, APIs, and processed tables accurately using the context provided.
- Explain Cloud360 features helpfully if asked.
- If a user asks a question about specific data that requires complex analysis (e.g., "Show me the total sales"), suggest they use the "NLP Results" or "Dashboard" section for precise SQL-based insights.
- Be concise, professional, and friendly.
- If you don't know the answer or the data is not in the context, say so politely.
`;

    // 3️⃣ CALL GROQ AI
    const response = await groq.chat.completions.create({
      model: "llama-3.1-8b-instant",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: question },
      ],
    });

    res.json({
      success: true,
      answer: response.choices[0].message.content,
    });

  } catch (error) {
    console.error("❌ Groq/Chat Error:", error.message);
    res.status(500).json({
      success: false,
      error: "AI Assistant is currently unavailable ❌",
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

// =============================
// 🧠 NLP HELPER FUNCTIONS
// =============================

async function getTableColumns(tableName) {
  const [rows] = await promiseDb.query(
    `SHOW COLUMNS FROM \`${tableName}\``
  );
  return rows.map(r => r.Field);
}


function detectResultMode(question) {
  const q = question.toLowerCase();

  if (
    q.includes("separate") ||
    q.includes("separately") ||
    q.includes("individually") ||
    q.includes("table wise")
  ) {
    return "separate";
  }

  if (
    q.includes("total") ||
    q.includes("overall") ||
    q.includes("combined") ||
    q.includes("group")
  ) {
    return "combined";
  }

  return "auto";
}

// =============================
// 🧠 SAFE JSON PARSER
// =============================
function safeParseJSON(text) {
  if (!text) return null;

  const cleaned = text
    .replace(/```json/gi, "")
    .replace(/```/g, "")
    .trim();

  return JSON.parse(cleaned);
}



// =============================
// 🧠 NLP QUERY ROUTE (SECURE)
// =============================
app.post("/nlp/query", authenticateToken, checkSubscription, async (req, res) => {
  try {
    const { question, forceMode } = req.body;

    if (!question || typeof question !== "string") {
      return res.status(400).json({ error: "Question required" });
    }

    const { id: userId, company_name } = req.user;

    console.log("🧠 QUESTION:", question);

    // =====================================================
    // 🔐 1️⃣ FETCH ALLOWED DATASETS (FILES + API)
    // =====================================================
    let allowedQuery = "";
    let params = [];
    // PERSONAL USER
    if (!company_name) {
      allowedQuery = `
        SELECT file_name FROM files WHERE uploaded_by = ?
        UNION
        SELECT file_name FROM api_data WHERE uploaded_by = ?
      `;
      params = [userId, userId];
    }
    // COMPANY USER (EMPLOYEE / MANAGER)
    else {
      allowedQuery = `
        SELECT file_name FROM files WHERE company_name = ?
        UNION
        SELECT file_name FROM api_data WHERE company_name = ?
      `;
      params = [company_name, company_name];
    }

    const [allowedFiles] = await promiseDb.query(allowedQuery, params);

    const allowedBaseNames = new Set(
      allowedFiles
        .filter(r => r.file_name)
        .map(r =>
          r.file_name
            .toLowerCase()
            .replace(/\.[^/.]+$/, "")
            .replace(/\s+/g, "_")
        )
    );
    if (allowedBaseNames.size === 0) {
      return res.json({
        success: true,
        mode: "auto",
        results: {},
        message: "No data available for NLP query"
      });
    }
    // =====================================================
    // 🔐 2️⃣ LOAD ONLY AUTHORIZED FULLTABLES
    // =====================================================
    const [tables] = await promiseDb.query("SHOW TABLES");

    const fullTables = tables
      .map(t => Object.values(t)[0])
      .filter(name => {
        if (!name.endsWith("_fulltable")) return false;
        const base = name.replace(/_fulltable$/, "").toLowerCase();
        return allowedBaseNames.has(base);
      });
    if (fullTables.length === 0) {
      return res.json({
        success: true,
        mode: "auto",
        results: {},
        message: "No processed tables available"
      });
    }
    // =====================================================
    // 3️⃣ MAP LOGICAL DATASETS
    // =====================================================
    const datasetMap = {};
    for (const table of fullTables) {
      const base = table.replace(/_fulltable$/, "");
      datasetMap[base] = table;
    }

    const logicalDatasets = Object.keys(datasetMap);
    // =====================================================
    // 4️⃣ FILTER DATASETS BY QUESTION
    // =====================================================
    const qLower = question.toLowerCase();

    const matchedDatasets = logicalDatasets.filter(ds => {
      const base = ds.replace(/_\d+$/, "");
      return qLower.includes(base) || qLower.includes(ds);
    });

    const datasetsUsed =
      matchedDatasets.length > 0 ? matchedDatasets : logicalDatasets;

    const mode = forceMode || detectResultMode(question);

    console.log("🧭 MODE:", mode);
    console.log("📦 DATASETS USED:", datasetsUsed);
    // =====================================================
    // 5️⃣ LOAD SCHEMA (SAFE)
    // =====================================================
    const schemaInfo = {};
    for (const ds of datasetsUsed) {
      const tableName = datasetMap[ds];
      schemaInfo[tableName] = await getTableColumns(tableName);
    }
    // =====================================================
    // 6️⃣ BUILD AI PROMPT
    // =====================================================
    const prompt = `
You are a senior MySQL data analyst.
 
STRICT RULES:
- Use ONLY the tables AND columns listed below
- Tables are FULLTABLES (raw data)
- NEVER invent table names or column names
- Choose the MOST RELEVANT column based on the question meaning
- Return ONLY valid JSON (no explanation)
 
SCHEMA:
${datasetsUsed
        .map(ds => {
          const table = datasetMap[ds];
          const cols = schemaInfo[table].join(", ");
          return `Table: ${table}\nColumns: ${cols}`;
        })
        .join("\n\n")}
 
MODE RULES:
- combined → aggregate across all tables
- separate → one query per table
- auto → choose best mode based on the question
 
RETURN FORMAT:
{
  "mode": "combined | separate | auto",
  "queries": [
    {
      "dataset": "dataset_name",
      "sql": "SELECT ..."
    }
  ]
}
 
User Question:
"${question}"
`;
    // =====================================================
    // 7️⃣ OPENAI CALL
    // =====================================================
    const aiRes = await axios.post(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        model: "llama-3.3-70b-versatile", // choose your Groq model
        messages: [{ role: "user", content: prompt }],
        temperature: 0,
        max_tokens: 2048
      },
      {
        headers: {
          Authorization: `Bearer ${GROQ_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );
    const text = aiRes.data.choices[0].message.content;
    const aiJson = safeParseJSON(text);
    if (!aiJson || !Array.isArray(aiJson.queries)) {
      return res.status(400).json({
        error: "Invalid AI response",
        raw: text
      });
    }
    // =====================================================
    // 🔒 8️⃣ FINAL SQL SAFETY CHECK
    // =====================================================
    const allowedTableSet = new Set(fullTables.map(t => t.toLowerCase()));

    for (const q of aiJson.queries) {
      const sql = q.sql.toLowerCase();

      const hasAccess = [...allowedTableSet].some(t =>
        sql.includes(` ${t} `) || sql.includes(`\`${t}\``)
      );

      if (!hasAccess) {
        return res.status(403).json({
          error: "Unauthorized dataset access",
          sql
        });
      }
    }
    // =====================================================
    // 9️⃣ EXECUTE SQL
    // =====================================================
    const perTableResults = {};

    for (const q of aiJson.queries) {
      const sql = q.sql.trim();

      if (!sql.toLowerCase().startsWith("select")) {
        return res.status(400).json({ error: "Unsafe SQL", sql });
      }

      console.log("🧠 EXECUTING:", sql);
      const [rows] = await promiseDb.query(sql);
      perTableResults[q.dataset] = rows;
    }
    // =====================================================
    // 🚫 NO DATA FOUND CHECK
    // =====================================================
    const hasAnyData = Object.values(perTableResults).some(
      rows => Array.isArray(rows) && rows.length > 0
    );
    if (!hasAnyData) {
      return res.json({
        success: true,
        mode: forceMode || aiJson.mode || "auto",
        results: {},
        message: "No data found for your question"
      });
    }


    // =====================================================
    // 🔔 POPUP DECISION (AUTHORIZED & SAFE)
    // =====================================================
    const tablesWithData = Object.entries(perTableResults)
      .filter(([_, rows]) => Array.isArray(rows) && rows.length > 0)
      .map(([dataset]) => dataset.replace(/_fulltable$/, ""));
    if (tablesWithData.length > 1 && !forceMode) {
      return res.json({
        needsUserChoice: true,
        datasets: tablesWithData
      });
    }


    // =====================================================
    // 🔟 FINAL RESPONSE
    // =====================================================
    const finalMode = forceMode || aiJson.mode;
    let results = {};

    if (finalMode === "combined") {
      results.combined_result = Object.values(perTableResults).flat();
    } else {
      results = perTableResults;
    }

    res.json({
      success: true,
      mode: finalMode,
      results
    });

  } catch (err) {
    console.error("❌ NLP ERROR:", err);
    res.status(500).json({ error: "NLP query failed" });
  }
});

app.post("/nlp/send-pdf", authenticateToken, checkSubscription, async (req, res) => {
  try {
    const { question, tables } = req.body;
    const userEmail = req.user.email;

    if (!question || !tables || !Array.isArray(tables)) {
      return res.status(400).json({ error: "Invalid payload" });
    }

    const filePath = path.join(
      __dirname,
      "uploads",
      `NLP_Report_${Date.now()}.pdf`
    );

    const doc = new PDFDocument({ size: "A4", margin: 40 });
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    // =============================
    // HEADER
    // =============================
    doc.fontSize(18).text("NLP Analysis Report", { align: "center" });
    doc.moveDown();
    doc.fontSize(12).text(`Question: ${question}`);
    doc.text(`Generated for: ${userEmail}`);
    doc.moveDown(2);

    // =============================
    // LOOP EACH DATASET
    // =============================
    for (const block of tables) {
      const { table, insights, rows, chartImage } = block;

      // ---------- DATASET TITLE ----------
      doc.fontSize(14).text(table.toUpperCase(), { underline: true });
      doc.moveDown();

      // ---------- INSIGHTS ----------
      // =============================
      // 🧠 INSIGHTS BOX (DESIGNED)
      // =============================
      doc.fontSize(13).fillColor("#000").text("Insights");
      doc.moveDown(0.5);

      // Box dimensions
      const boxX = doc.x;
      const boxY = doc.y;
      const boxWidth = doc.page.width - 80;
      const boxPadding = 10;

      // Calculate box height dynamically
      const boxHeight = insights.length * 16 + boxPadding * 2;

      // Draw background box
      doc
        .rect(boxX, boxY, boxWidth, boxHeight)
        .fill("#f3f4f6");

      // Write insights text
      doc.fillColor("#000").fontSize(10);

      let textY = boxY + boxPadding;
      insights.forEach((i, idx) => {
        doc.text(`${idx + 1}. ${i}`, boxX + boxPadding, textY, {
          width: boxWidth - boxPadding * 2
        });
        textY += 16;
      });

      // Move cursor below box
      doc.y = boxY + boxHeight + 15;


      // ---------- CHART ----------
      // Move cursor below insights box
      doc.y = boxY + boxHeight + 20;

      // =============================
      // 📊 CHART (SAME PAGE, BELOW INSIGHTS)
      // =============================
      if (chartImage) {
        const base64 = chartImage.replace(/^data:image\/png;base64,/, "");
        const imgBuffer = Buffer.from(base64, "base64");

        const chartWidth = doc.page.width - 80;
        const chartHeight = 260;

        // Auto page break safety
        if (doc.y + chartHeight > doc.page.height - 40) {
          doc.addPage();
        }

        doc.fontSize(12).fillColor("#000").text("Chart Analysis");
        doc.moveDown(0.5);

        doc.image(imgBuffer, {
          fit: [chartWidth, chartHeight],
          align: "center"
        });

        doc.moveDown(1.5);
      }

      // =============================
      // 📋 TABLE DESIGN (LIKE UI)
      // =============================
      doc.addPage({ size: "A4", layout: "landscape", margin: 40 });

      const columns = Object.keys(rows[0]);

      const tableX = 40;
      let tableY = doc.y;
      const rowHeight = 22;
      const pageBottom = doc.page.height - 50;

      // -------------------------------------------------
      // 🔹 AUTO COLUMN WIDTH CALCULATION
      // -------------------------------------------------
      const minColWidth = 60;
      const maxColWidth = 160;

      // Estimate width based on header + first 10 rows
      const colWidths = columns.map(col => {
        let maxLen = col.length;

        rows.slice(0, 10).forEach(r => {
          const val = String(r[col] ?? "");
          if (val.length > maxLen) maxLen = val.length;
        });

        // Approx width per character
        const estimated = maxLen * 6.5;

        return Math.max(minColWidth, Math.min(maxColWidth, estimated));
      });

      // Scale down if exceeds page width
      const totalWidth = colWidths.reduce((a, b) => a + b, 0);
      const availableWidth = doc.page.width - 80;

      if (totalWidth > availableWidth) {
        const scale = availableWidth / totalWidth;
        for (let i = 0; i < colWidths.length; i++) {
          colWidths[i] *= scale;
        }
      }

      // -------------------------------------------------
      // 🔹 HEADER DRAW FUNCTION
      // -------------------------------------------------
      // ---------- HEADER DRAW FUNCTION (FIXED) ----------
      const headerHeight = 28;

      const drawHeader = () => {
        let x = tableX;

        columns.forEach((col, i) => {
          // 🔵 Header background (ONLY this row)
          doc
            .rect(x, tableY, colWidths[i], headerHeight)
            .fill("#007bff");

          // 🔲 Header border (same table style)
          doc
            .rect(x, tableY, colWidths[i], headerHeight)
            .stroke();

          // Header text
          doc
            .fillColor("#ffffff")
            .font("Helvetica-Bold")
            .fontSize(9)
            .text(
              col.replace(/_/g, " "),
              x + 6,
              tableY + 8,
              {
                width: colWidths[i] - 12,
                align: "center",
                lineBreak: true,
                wordBreak: false
              }
            );

          x += colWidths[i];
        });

        doc.font("Helvetica").fillColor("#000");
        tableY += headerHeight;
      };


      // -------------------------------------------------
      // 🔹 DRAW HEADER
      // -------------------------------------------------
      drawHeader();

      // -------------------------------------------------
      // 🔹 DRAW ROWS
      // -------------------------------------------------
      rows.forEach((row, rowIndex) => {
        if (tableY > pageBottom) {
          doc.addPage({ size: "A4", layout: "landscape", margin: 40 });
          tableY = 40;
          drawHeader();
        }

        let x = tableX;

        columns.forEach((col, i) => {

          // Zebra background
          if (rowIndex % 2 === 0) {
            doc
              .rect(x, tableY, colWidths[i], rowHeight)
              .fill("#f9fafb");
          }

          // Border
          doc
            .rect(x, tableY, colWidths[i], rowHeight)
            .stroke();

          // ✅ FIXED
          const value = row[col];
          const isNumber = typeof value === "number";

          doc
            .fillColor("#000")
            .fontSize(9)
            .text(
              value != null ? String(value) : "",
              x + 6,
              tableY + 7,
              {
                width: colWidths[i] - 12,
                ellipsis: true,
                align: isNumber ? "right" : "left"
              }
            );

          x += colWidths[i];
        });

        tableY += rowHeight;
      });

      doc.addPage();
    }

    doc.end();

    // =============================
    // EMAIL PDF
    // =============================
    stream.on("finish", async () => {
      await transporter.sendMail({
        to: userEmail,
        subject: "📄 NLP Report (Insights + Chart + Table)",
        text: "Your NLP analysis report is attached.",
        attachments: [
          {
            filename: "NLP_Report.pdf",
            path: filePath
          }
        ]
      });

      // cleanup
      setTimeout(() => fs.unlinkSync(filePath), 30000);

      res.json({ success: true });
    });

  } catch (err) {
    console.error("❌ PDF ERROR:", err);
    res.status(500).json({ error: "PDF generation failed" });
  }
});



// =============================
// SUBSCRIPTION ENDPOINTS
// =============================

// =============================
// 🎫 SUPPORT TICKETS (PROXY TO ADMIN)
// =============================
app.get("/api/client-tickets", authenticateToken, async (req, res) => {
  try {
    // 1️⃣ Need to get the admin user ID by email
    const adminRes = await axios.get(`${process.env.ADMIN_SERVER_URL}/api/users/check/${req.user.email}`, {
      headers: { 'x-api-key': process.env.API_BRIDGE_KEY }
    });

    if (!adminRes.data || !adminRes.data.id) {
      return res.status(404).json({ error: "Admin user not found for sync" });
    }

    const adminUserId = adminRes.data.id;

    // 2️⃣ Fetch tickets from admin server
    const ticketsRes = await axios.get(`${process.env.ADMIN_SERVER_URL}/api/tickets/client/${adminUserId}`);
    res.json(ticketsRes.data);
  } catch (err) {
    console.error("❌ Fetch Tickets Error:", err.message);
    res.status(500).json({ error: "Failed to fetch tickets from support server" });
  }
});

app.post("/api/client-tickets", authenticateToken, async (req, res) => {
  try {
    const { subject, issue, category, priority } = req.body;

    // 1️⃣ Get admin user ID
    const adminRes = await axios.get(`${process.env.ADMIN_SERVER_URL}/api/users/check/${req.user.email}`, {
      headers: { 'x-api-key': process.env.API_BRIDGE_KEY }
    });

    if (!adminRes.data || !adminRes.data.id) {
      return res.status(404).json({ error: "Admin user not found for sync" });
    }

    const adminUserId = adminRes.data.id;

    // 2️⃣ Create ticket on admin server
    const createRes = await axios.post(`${process.env.ADMIN_SERVER_URL}/api/tickets`, {
      client_id: adminUserId,
      subject,
      issue,
      category,
      priority
    });

    res.status(201).json(createRes.data);
  } catch (err) {
    console.error("❌ Create Ticket Error:", err.message);
    res.status(500).json({ error: "Failed to submit ticket" });
  }
});

app.post("/api/subscription-request", authenticateToken, async (req, res) => {
  try {
    const { plan } = req.body;
    const { id, first_name, last_name, email } = req.user;

    const userName = `${first_name || ''} ${last_name || ''}`.trim() || 'Valued User';

    // 1️⃣ Send Email to Admin
    const mailOptions = {
      from: `"Cloud360 Subscription" <${process.env.EMAIL_USER || 'muthuram921@gmail.com'}>`,
      to: 'muthuram921@gmail.com',
      subject: `🚀 New Subscription Request: ${plan}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 20px auto; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                .header { background: linear-gradient(135deg, #2563eb, #1e40af); color: #fff; padding: 30px; text-align: center; }
                .header h1 { margin: 0; font-size: 24px; letter-spacing: 1px; }
                .content { padding: 30px; background-color: #fff; }
                .details-box { background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 20px; margin: 20px 0; }
                .detail-item { margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #edf2f7; }
                .detail-item:last-child { border-bottom: none; }
                .label { font-weight: 600; color: #4a5568; width: 140px; display: inline-block; }
                .value { color: #2d3748; font-weight: 500; }
                .plan-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; background-color: #e0e7ff; color: #3730a3; font-weight: 600; font-size: 14px; }
                .footer { background-color: #f8fafc; padding: 20px; text-align: center; font-size: 13px; color: #64748b; border-top: 1px solid #e2e8f0; }
                .btn { display: inline-block; padding: 12px 24px; background-color: #2563eb; color: #ffffff !important; text-decoration: none; border-radius: 6px; font-weight: 600; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Subscription Request</h1>
                </div>
                <div class="content">
                    <p>Hello Admin,</p>
                    <p>A new subscription request has been received from the Cloud360 Portal. Here are the user details:</p>
                    
                    <div class="details-box">
                        <div class="detail-item">
                            <span class="label">User Name:</span>
                            <span class="value">${userName}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Email Address:</span>
                            <span class="value">${email}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">User ID:</span>
                            <span class="value">#${id}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Requested Plan:</span>
                            <span class="plan-badge">${plan}</span>
                        </div>
                    </div>
                    
                    <p>You can manage this request by clicking the button below to open the Admin Dashboard.</p>
                    
                    <div style="text-align: center;">
                        <a href="${process.env.ADMIN_DASHBOARD_URL || 'http://localhost:5173'}/requests" class="btn">View in Dashboard</a>
                    </div>
                </div>
                <div class="footer">
                    This is an automated notification from Cloud360 Platform.
                </div>
            </div>
        </body>
        </html>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`📧 Subscription request email sent for ${email} (${plan})`);

    // 2️⃣ Forward to Admin Dashboard (Cloud Licensing Server)
    try {
      await axios.post(`${process.env.ADMIN_SERVER_URL}/api/license/subscription-request`, {
        userId: id,
        firstName: first_name,
        lastName: last_name,
        email: email,
        plan: plan,
        category: req.user.role === 'manager' ? 'company' : 'individual'
      }, {
        headers: { 'x-api-key': process.env.API_BRIDGE_KEY }
      });
      console.log(`✅ Forwarded subscription request to Admin server for ${email}`);
    } catch (forwardErr) {
      console.error(`⚠️ Forwarding to Admin failed:`, forwardErr.message);
      // We still return success if email was sent, as admin can see email
    }

    res.json({ success: true, message: "Request sent to admin successfully!" });
  } catch (err) {
    console.error("Subscription Request Error:", err);
    res.status(500).json({ error: "Failed to process subscription request" });
  }
});

app.get("/api/subscription-status", authenticateToken, (req, res) => {
  res.json({
    success: true,
    plan: req.user.subscription_plan,
    expiry: req.user.subscription_expiry,
    isActive: req.user.isSubscriptionActive,
    status: req.user.status
  });
});

app.post("/api/activate-subscription", authenticateToken, async (req, res) => {
  try {
    const { key } = req.body;
    if (!key) return res.status(400).json({ error: "Activation key required" });

    let daysToAdd = 0;
    let planName = "";

    if (key === "CLOUD360-TRIAL") { daysToAdd = 7; planName = "Trial"; }
    else if (key === "CLOUD360-1M") { daysToAdd = 30; planName = "1 Month"; }
    else if (key === "CLOUD360-3M") { daysToAdd = 90; planName = "3 Months"; }
    else if (key === "CLOUD360-6M") { daysToAdd = 180; planName = "6 Months"; }
    else if (key === "CLOUD360-1Y") { daysToAdd = 365; planName = "1 Year"; }
    else {
      return res.status(400).json({ error: "Invalid activation key" });
    }

    const [existing] = await db.promise().query(
      "SELECT subscription_expiry FROM users WHERE id = ?", [req.user.id]
    );

    let currentExpiry = new Date();
    if (existing[0].subscription_expiry && new Date(existing[0].subscription_expiry) > new Date()) {
      currentExpiry = new Date(existing[0].subscription_expiry);
    }

    const newExpiry = new Date(currentExpiry.getTime() + daysToAdd * 24 * 60 * 60 * 1000);

    await db.promise().query(
      "UPDATE users SET subscription_plan = ?, subscription_expiry = ?, activation_key = ? WHERE id = ?",
      [planName, newExpiry, key, req.user.id]
    );

    res.json({
      success: true,
      message: `Successfully activated ${planName} plan!`,
      plan: planName,
      expiry: newExpiry
    });
  } catch (err) {
    console.error("Activation Error:", err);
    res.status(500).json({ error: "Failed to activate subscription" });
  }
});

app.post("/api/sync-user-from-admin", async (req, res) => {
  try {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || apiKey !== process.env.API_BRIDGE_KEY) {
      return res.status(403).json({ error: "Unauthorized bridge access" });
    }

    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Log the incoming sync request
    const syncLog = (msg) => {
      const logMsg = `[${new Date().toISOString()}] ${msg}\n`;
      console.log(msg);
      fs.appendFileSync(path.join(__dirname, 'sync_debug.log'), logMsg);
    };

    syncLog(`🔄 [Remote Sync] Incoming sync for: ${normalizedEmail}`);

    const adminRes = await axios.get(`${process.env.ADMIN_SERVER_URL}/api/users/check/${normalizedEmail}`, {
      headers: { 'x-api-key': process.env.API_BRIDGE_KEY }
    });

    if (adminRes.data) {
      const adminUser = adminRes.data;

      // Map Admin status to Portal status
      let portalStatus = 'ACTIVE';
      const adminStatus = (adminUser.status || '').toLowerCase();
      if (adminStatus === 'inactive') {
        portalStatus = 'INACTIVE';
      } else if (adminStatus === 'expired') {
        portalStatus = 'EXPIRED';
      }

      await db.promise().query(
        `UPDATE users SET 
          subscription_plan = ?, 
          subscription_expiry = ?, 
          first_name = ?, 
          last_name = ?, 
          mobile = ?, 
          status = ? 
         WHERE email = ?`,
        [
          adminUser.plan,
          formatMySQLDate(adminUser.valid_until),
          adminUser.firstname,
          adminUser.lastname,
          adminUser.contact || '',
          portalStatus,
          normalizedEmail
        ]
      );

      syncLog(`✅ [Remote Sync] Successfully updated ${normalizedEmail}`);
      res.json({ success: true, message: "User synced successfully" });
    } else {
      res.status(404).json({ error: "User not found in Admin server" });
    }
  } catch (err) {
    console.error("Sync Error:", err.message);
    res.status(500).json({ error: "Failed to sync user" });
  }
});


// =============================
// START SERVER
// =============================

app.listen(port, () => console.log(`🚀 Server running on http://localhost:${port}`));