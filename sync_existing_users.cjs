const mysql = require('mysql2/promise');
const axios = require('axios');
require('dotenv').config();

const ADMIN_URL = process.env.ADMIN_SERVER_URL || 'http://localhost:5000';
const API_KEY = process.env.API_BRIDGE_KEY || 'cloud-secret-bridge-2024';

async function sync() {
    console.log("🚀 Starting migration of existing users to Admin Server...");
    
    try {
        const db = await mysql.createConnection({
            host: 'localhost',
            user: 'root',
            password: '8080',
            database: 'file_upload_db'
        });

        const [users] = await db.query("SELECT * FROM users");
        console.log(`📊 Found ${users.length} users in local database.`);

        for (const user of users) {
            try {
                process.stdout.write(`🔄 Syncing ${user.email}... `);
                
                // Determine user category
                const category = (user.role === 'personal') ? 'individual' : 'company';
                const user_type = (user.role === 'manager') ? 'admin' : 'client';

                await axios.post(`${ADMIN_URL}/api/users`, {
                    firstname: user.first_name,
                    lastname: user.last_name,
                    email: user.email,
                    contact: user.mobile || '',
                    password: user.password, // We send the hashed password directly
                    user_type: user_type,
                    plan: user.subscription_plan || 'Trial',
                    valid_until: user.subscription_expiry ? new Date(user.subscription_expiry).toISOString().split('T')[0] : new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
                    category: category,
                    company_name: user.company_name
                }, {
                    headers: { 'x-api-key': API_KEY }
                });

                console.log("✅ DONE");
            } catch (err) {
                if (err.response && err.response.status === 500 && err.response.data.error.includes('Duplicate entry')) {
                    console.log("⏭️ ALREADY EXISTS");
                } else {
                    console.log(`❌ FAILED: ${err.message}`);
                }
            }
        }

        console.log("\n🎉 Migration completed!");
        await db.end();
    } catch (err) {
        console.error("❌ FATAL ERROR:", err.message);
    }
}

sync();
