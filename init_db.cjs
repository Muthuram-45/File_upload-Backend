const mysql = require('mysql2/promise');
require('dotenv').config();
const fs = require('fs');
const path = require('path');

async function initDB() {
  const connectionConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT || 3306,
    ssl: {
      rejectUnauthorized: false,
      ca: fs.readFileSync(path.join(__dirname, process.env.DB_SSL_CA || 'global-bundle.pem'))
    }
  };

  let connection;
  try {
    connection = await mysql.createConnection(connectionConfig);

    const dbName = process.env.DB_NAME || 'file_upload_db';
    await connection.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``);
    await connection.query(`USE \`${dbName}\``);

    // 1. Users Table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        email VARCHAR(255) UNIQUE NOT NULL,
        mobile VARCHAR(20),
        password VARCHAR(255),
        company_name VARCHAR(255),
        role VARCHAR(50),
        status VARCHAR(50) DEFAULT 'ACTIVE',
        report_hour INT DEFAULT 9,
        report_minute INT DEFAULT 0,
        timezone VARCHAR(100) DEFAULT 'Asia/Kolkata',
        subscription_plan VARCHAR(50) DEFAULT 'Trial',
        subscription_expiry DATETIME,
        activation_key VARCHAR(100),
        last_login DATETIME,
        last_report_sent DATE
      )
    `);

    // 2. File Run Stats Table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS file_run_stats (
        id INT AUTO_INCREMENT PRIMARY KEY,
        file_name VARCHAR(255),
        company_name VARCHAR(255),
        uploaded_by INT,
        processed_at DATETIME,
        rows_count INT,
        status VARCHAR(50)
      )
    `);

    // 3. API Data Table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS api_data (
        id INT AUTO_INCREMENT PRIMARY KEY,
        api_url TEXT,
        file_name VARCHAR(255),
        response LONGTEXT,
        response_hash VARCHAR(255),
        company_name VARCHAR(255),
        uploaded_by INT,
        status VARCHAR(50),
        last_processed_at DATETIME,
        next_process_at DATETIME,
        api_token TEXT,
        file_path TEXT,
        file_content LONGBLOB
      )
    `);

    // 4. API Run Stats Table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS api_run_stats (
        id INT AUTO_INCREMENT PRIMARY KEY,
        api_id INT,
        api_name VARCHAR(255),
        company_name VARCHAR(255),
        uploaded_by INT,
        run_time DATETIME,
        prev_rows INT,
        curr_rows INT,
        new_rows INT,
        duplicates_removed INT,
        status VARCHAR(50)
      )
    `);

    // 5. Files Table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS files (
        id INT AUTO_INCREMENT PRIMARY KEY,
        file_name VARCHAR(255),
        display_name VARCHAR(255),
        file_path TEXT,
        company_name VARCHAR(255),
        uploaded_by INT,
        status VARCHAR(50),
        file_content LONGBLOB,
        processed_at DATETIME,
        completed_at DATETIME
      )
    `);

  } catch (error) {
    console.error('❌ Initialization failed:', error);
    throw error;
  } finally {
    if (connection) {
      await connection.end();
    }
  }
}


module.exports = { initDB };

if (require.main === module) {
  initDB().catch(err => {
    console.error(err);
    process.exit(1);
  });
}

