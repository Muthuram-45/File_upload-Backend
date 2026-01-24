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


const app = express();
const port = 5000;

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


// CommonJS require
const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
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

    await db.promise().query(
      `INSERT INTO users
       (first_name, last_name, email, mobile, password, company_name, role, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        firstName,
        lastName,
        normalizedEmail,
        mobile || '',
        hashedPassword,
        company_name,
        role,
        status
      ]
    );

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

    // 🔍 Check if email already exists
    const [existing] = await db
      .promise()
      .query('SELECT id FROM users WHERE email = ?', [email]);

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
    await db.promise().query(
      `INSERT INTO users
       (first_name, last_name, email, mobile, password, company_name, role, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        firstName,
        lastName,
        email,
        mobile || '',
        hashedPassword,
        company_name,
        role,
        status
      ]
    );

    // 📧 SEND APPROVAL EMAIL ONLY FOR EMPLOYEE
    if (role === 'employee') {
      const [managers] = await db.promise().query(
        `SELECT email FROM users WHERE role = 'manager' AND company_name = ?`,
        [company_name]
      );

      if (managers.length > 0) {
        const approveToken = jwt.sign(
          { email, company_name },
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
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password required'
      });
    }

    const [rows] = await db
      .promise()
      .query('SELECT * FROM users WHERE email = ?', [email]);

    if (rows.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    const user = rows[0];

    // 🔐 ✅ BLOCK LOGIN ONLY FOR COMPANY EMPLOYEES
    if (user.role !== 'personal' && user.status !== 'ACTIVE') {
      return res.status(403).json({
        success: false,
        error:
          user.status === 'PENDING'
            ? 'Account pending manager approval'
            : 'Account rejected'
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
        lastLogin: now
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
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password required'
      });
    }

    const [rows] = await db.promise().query(
      `SELECT id, first_name, last_name, email, password,
              company_name, mobile, role, status
       FROM users
       WHERE email = ?`,
      [email]
    );

    if (rows.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid credentials'
      });
    }

    const user = rows[0];

    // 🚫 BLOCK PERSONAL USERS
    if (user.role === 'personal') {
      return res.status(403).json({
        success: false,
        error: 'Personal users cannot use company login'
      });
    }

    // 🔐 ✅ BLOCK LOGIN UNTIL MANAGER APPROVAL
    if (user.status !== 'ACTIVE') {
      return res.status(403).json({
        success: false,
        error:
          user.status === 'PENDING'
            ? 'Account pending manager approval'
            : 'Account rejected'
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
        lastLogin: now
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
        lastLogin: new Date()
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
        last_login AS lastLogin
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
// AUTH MIDDLEWARE (UPDATED)
// =============================
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Token missing" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, secret_key, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }

    // ✅ FINAL USER CONTEXT
    req.user = {
      id: decoded.id,                         // user id
      email: decoded.email,
      role: decoded.role || "personal",       // 🔥 ADD (VERY IMPORTANT)
      company_name: decoded.company_name || null,
      viewOnly: decoded.viewOnly || false
    };

    next();
  });
}
app.get("/fetch-api", authenticateToken, async (req, res) => {
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
app.post("/fetch-api", authenticateToken, async (req, res) => {
  try {
    if (req.user.viewOnly) {
      return res.status(403).json({
        success: false,
        error: "View-only access. Fetch API disabled."
      });
    }

    const { url, file_name } = req.body;
    if (!url || !file_name) {
      return res.status(400).json({
        success: false,
        error: "API URL and File Name are required"
      });
    }

    const externalToken =
      req.headers["x-api-key"] || req.headers["authorization-external"];

    const headers = {};
    if (externalToken) {
      headers.Authorization = externalToken.startsWith("Bearer")
        ? externalToken
        : `Bearer ${externalToken}`;
    }

    const apiResponse = await axios.get(url, { headers });

    const raw = Array.isArray(apiResponse.data)
      ? apiResponse.data
      : [apiResponse.data];

    // 🔥 Use same hashing as cron
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
      `SELECT id FROM api_data WHERE file_name = ? AND company_name <=> ?`,
      [safeName, companyName]
    );

    if (existing.length === 0) {
      // 🆕 insert
      await db.promise().query(
        `INSERT INTO api_data
         (api_url, file_name, response, response_hash, company_name, uploaded_by,
          status, last_processed_at, next_process_at)
         VALUES (?, ?, ?, ?, ?, ?, 'NEW', ?, ?)`,
        [url, safeName, JSON.stringify(raw), hash, companyName, uploadedBy, now, nextRun]
      );
    } else {
      // ♻️ update → always mark NEW (cron will decide DONE later)
      await db.promise().query(
        `UPDATE api_data
         SET api_url = ?,
             response = ?,
             response_hash = ?,
             status = 'NEW',
             last_processed_at = ?,
             next_process_at = ?
         WHERE id = ?`,
        [url, JSON.stringify(raw), hash, now, nextRun, existing[0].id]
      );
    }

    res.json({ success: true, data: raw });
  } catch (err) {
    console.error("❌ Fetch API Error:", err.message);
    res.status(500).json({ success: false, error: "Fetch failed" });
  }
});
app.post("/save-api-data", authenticateToken, async (req, res) => {
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


cron.schedule("*/5 * * * *", async () => {
  console.log("⏰ API cron started (every 5 minutes)");

  try {
    const [apis] = await db.promise().query(`
      SELECT 
        id,
        api_url,
        response_hash,
        api_token,
        last_processed_at,
        status
      FROM api_data
      WHERE status != 'PROCESSING'
    `);

    for (const api of apis) {

      // ⛔ Extra safety (double-check)
      if (api.status === "PROCESSING") {
        continue;
      }

      const now = new Date();
      const nextRun = new Date(now.getTime() + 5 * 60 * 1000);

      try {
        const headers = { "User-Agent": "Cloud360-Cron/1.0" };

        if (api.api_token) {
          headers.Authorization = api.api_token.startsWith("Bearer ")
            ? api.api_token
            : `Bearer ${api.api_token}`;
        }

        const res = await axios.get(api.api_url, {
          timeout: 15000,
          headers,
        });

        const rawNewData = Array.isArray(res.data)
          ? res.data
          : [res.data];

        // 🔥 Stable hash of raw response
        const newHash = stableHash(rawNewData);
        const oldHash = api.response_hash || null;

        const isNewData = newHash !== oldHash;
        const status = isNewData ? "NEW" : "DONE";
        const lastProcessedAt = isNewData ? now : api.last_processed_at;

        await db.promise().query(
          `
          UPDATE api_data
          SET
            response = ?,
            response_hash = ?,
            status = ?,
            last_processed_at = ?,
            next_process_at = ?
          WHERE id = ?
          `,
          [
            JSON.stringify(rawNewData),
            newHash,
            status,
            lastProcessedAt,
            nextRun,
            api.id,
          ]
        );

        console.log(`✔ ${api.api_url} → ${status}`);

      } catch (apiErr) {
        console.error("❌ API fetch failed:", api.api_url, apiErr.message);

        await db.promise().query(
          `UPDATE api_data SET next_process_at = ? WHERE id = ?`,
          [nextRun, api.id]
        );
      }
    }
  } catch (err) {
    console.error("❌ Cron fatal error:", err.message);
  }
});


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

// // --------------------------------------------------------
// // 💾 Save API data (CSV + DB)
// // --------------------------------------------------------
// app.post("/save-api-data", authenticateToken, (req, res) => {
//   if (req.user.viewOnly) {
//     return res.status(403).json({
//       success: false,
//       error: "View-only users cannot save API data"
//     });
//   }
//   const { api_url, file_name, response } = req.body;

//   // 🔥 From token
//   const uploadedBy = req.user.id;
//   const company_name = req.user.company_name || null;

//   if (!response) {
//     return res.status(400).json({
//       success: false,
//       message: "Response is empty",
//     });
//   }

//   let jsonData;
//   try {
//     jsonData = typeof response === "string"
//       ? JSON.parse(response)
//       : response;
//   } catch {
//     return res.status(400).json({
//       success: false,
//       message: "Invalid JSON",
//     });
//   }

//   if (!Array.isArray(jsonData)) {
//     jsonData = [jsonData];
//   }

//   // -----------------------------
//   // Flatten JSON
//   // -----------------------------
//   const flatData = [];

//   jsonData.forEach(item => {
//     const arrayKeys = Object.keys(item).filter(
//       key => Array.isArray(item[key])
//     );

//     if (arrayKeys.length) {
//       arrayKeys.forEach(arrKey => {
//         item[arrKey].forEach(subItem => {
//           flatData.push(
//             flattenObject({
//               ...item,
//               [arrKey]: undefined,
//               ...subItem
//             })
//           );
//         });
//       });
//     } else {
//       flatData.push(flattenObject(item));
//     }
//   });

//   if (!flatData.length) {
//     return res.status(400).json({
//       success: false,
//       message: "No data to save",
//     });
//   }

//   // -----------------------------
//   // JSON → CSV
//   // -----------------------------
//   let csv;
//   try {
//     const fields = Object.keys(flatData[0]);
//     const parser = new Parser({ fields });
//     csv = parser.parse(flatData);
//   } catch (err) {
//     console.error("CSV Parse Error:", err);
//     return res.status(500).json({
//       success: false,
//       message: "Failed to convert JSON to CSV",
//     });
//   }

//   // -----------------------------
//   // ✅ SAFE FILE NAME (NEW)
//   // -----------------------------
//   const safeName = file_name
//     .trim()
//     .toLowerCase()
//     .replace(/\s+/g, "_")
//     .replace(/[^a-z0-9_]/g, "");

//   const relativePath = `uploads/API_Files/${safeName}.csv`;
//   const fullPath = path.join(__dirname, relativePath);

//   // -----------------------------
//   // Save CSV file
//   // -----------------------------
//   try {
//     fs.writeFileSync(fullPath, csv);
//   } catch (err) {
//     console.error("File Save Error:", err);
//     return res.status(500).json({
//       success: false,
//       message: "Failed to save CSV file",
//     });
//   }

//   // -----------------------------
//   // Save DB record (FIXED)
//   // -----------------------------
//   const sql = `
//     INSERT INTO api_data
//       (api_url, file_name, file_path, response, company_name, uploaded_by)
//     VALUES (?, ?, ?, ?, ?, ?)
//   `;

//   db.query(
//     sql,
//     [
//       api_url,
//       safeName,
//       relativePath,
//       JSON.stringify(jsonData), // ✅ FIXED
//       company_name,
//       uploadedBy,
//     ],
//     (err) => {
//       if (err) {
//         console.error("DB Error:", err);
//         return res.status(500).json({
//           success: false,
//           message: "DB Error",
//         });
//       }

//       res.json({
//         success: true,
//         message: "API Data saved successfully!",
//         file_path: relativePath,
//       });
//     }
//   );
// });



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

app.post("/upload", authenticateToken, (req, res, next) => {
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
// =============================
// 🧠 NLP HELPER FUNCTIONS
// =============================

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
// 🧠 NLP QUERY ROUTE
// =============================
app.post("/nlp/query", authenticateToken, async (req, res) => {
  try {
    const { question, forceMode } = req.body;

    if (!question || typeof question !== "string") {
      return res.status(400).json({ error: "Question required" });
    }

    console.log("🧠 QUESTION:", question);

    // =============================
    // 1️⃣ LOAD ONLY FULLTABLES
    // =============================
    const [tables] = await promiseDb.query("SHOW TABLES");

    const fullTables = tables
      .map(t => Object.values(t)[0])
      .filter(name => name.endsWith("_fulltable"));

    // =============================
    // 2️⃣ MAP LOGICAL DATASETS
    // =============================
    const datasetMap = {};
    // sales_data_2024 -> sales_data_2024_fulltable

    for (const table of fullTables) {
      const base = table.replace(/_fulltable$/, "");
      datasetMap[base] = table;
    }

    const logicalDatasets = Object.keys(datasetMap);

    // =============================
    // 3️⃣ FILTER DATASETS BY QUESTION
    // =============================
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

    // =============================
    // 4️⃣ BUILD AI PROMPT
    // =============================
    const prompt = `
You are a senior MySQL data analyst.

RULES:
- Use ONLY the tables listed below
- Tables are FULLTABLES (raw data)
- NEVER invent tables or columns
- Return ONLY JSON

TABLES:
${datasetsUsed.map(ds => `Table: ${datasetMap[ds]}`).join("\n")}

If mode is:
- combined → aggregate across all tables
- separate → one query per table

RETURN FORMAT:
{
  "mode": "combined | separate",
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

    // =============================
    // 5️⃣ OPENAI CALL
    // =============================
    const aiRes = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0,
      response_format: { type: "json_object" }
    });

    const aiJson = safeParseJSON(aiRes.choices[0].message.content);

    if (!aiJson || !Array.isArray(aiJson.queries)) {
      return res.status(400).json({
        error: "Invalid AI response",
        raw: aiRes.choices[0].message.content
      });
    }

    // =============================
    // 6️⃣ EXECUTE SQL (ALWAYS PER TABLE FIRST)
    // =============================
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

    // =============================
    // 7️⃣ POPUP DECISION (CLEAN NAMES ONLY)
    // =============================
    const tablesWithData = Object.entries(perTableResults)
      .filter(([_, rows]) => Array.isArray(rows) && rows.length > 0)
      .map(([dataset]) => dataset.replace(/_fulltable$/, "")); // 🔥 ONLY CHANGE

    if (tablesWithData.length > 1 && !forceMode) {
      return res.json({
        needsUserChoice: true,
        datasets: tablesWithData
      });
    }

    // =============================
    // 8️⃣ FINAL RESULT (USER WINS)
    // =============================
    const finalMode = forceMode || aiJson.mode;

    let results = {};

    if (finalMode === "combined") {
      let combinedRows = [];

      for (const rows of Object.values(perTableResults)) {
        combinedRows = combinedRows.concat(rows);
      }

      results["combined_result"] = combinedRows;
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


// =============================
// START SERVER
// =============================

app.listen(port, () => console.log(`🚀 Server running on http://localhost:${port}`));